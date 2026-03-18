"""
Detection Service
Core phishing detection logic
"""
import os
import json
import pickle
import numpy as np
from typing import Dict, List, Tuple, Optional
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config, DetectionError


FEATURE_COLUMNS = [
    'is_suspicious_from_domain', 'received_hops_count',
    'first_external_ip_is_blacklisted',
    'spf_fail', 'dkim_fail', 'dmarc_fail',
    'from_display_name_mismatch', 'from_domain_in_subject',
    'avg_domain_age_days', 'max_vt_detection_ratio',
    'min_has_https', 'short_url_count', 'mixed_sld_count',
    'max_domain_length',
    'ip_address_count', 'port_count',
    'at_symbol_count', 'subdomain_count', 'suspicious_param_count',
    'avg_url_length', 'avg_path_depth', 'max_query_length',
    'urgent_keywords_count', 'financial_keywords_count',
    'text_length', 'urgency_score', 'exclamation_count',
    'caps_ratio', 'url_count',
    'attachment_count', 'has_suspicious_attachment',
    'has_executable_attachment', 'total_attachment_size',
    'has_double_extension',
    'has_html_body', 'html_link_count', 'has_hidden_links',
    'has_form', 'has_iframe',
]


class DetectionService:
    """
    Phishing detection service
    Implements multi-class detection (PHISHING/SUSPICIOUS/SAFE)
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.model = None
        self.demo_weights = self._get_demo_weights()
        
        self._load_model()
    
    def _get_demo_weights(self) -> Dict[str, float]:
        """Get demo weights for rule-based detection"""
        return {
            'is_suspicious_from_domain': 0.30,
            'spf_fail': 0.20,
            'dkim_fail': 0.15,
            'dmarc_fail': 0.15,
            'from_display_name_mismatch': 0.20,
            'received_hops_count': 0.01,
            'first_external_ip_is_blacklisted': 0.25,
            'from_domain_in_subject': 0.10,
            'avg_domain_age_days': -0.0002,
            'max_vt_detection_ratio': 0.50,
            'min_has_https': -0.15,
            'short_url_count': 0.20,
            'mixed_sld_count': 0.10,
            'max_domain_length': 0.003,
            'ip_address_count': 0.25,
            'port_count': 0.15,
            'at_symbol_count': 0.20,
            'subdomain_count': 0.10,
            'suspicious_param_count': 0.15,
            'avg_url_length': 0.001,
            'avg_path_depth': 0.02,
            'max_query_length': 0.001,
            'urgent_keywords_count': 0.15,
            'financial_keywords_count': 0.12,
            'text_length': -0.0001,
            'urgency_score': 0.25,
            'exclamation_count': 0.05,
            'caps_ratio': 0.10,
            'url_count': 0.03,
            'attachment_count': 0.05,
            'has_suspicious_attachment': 0.25,
            'has_executable_attachment': 0.35,
            'total_attachment_size': 0.00001,
            'has_double_extension': 0.30,
            'sandbox_detected': 0.40,
            'max_sandbox_detection_ratio': 0.35,
            'has_sandbox_analysis': 0.05,
            'has_html_body': 0.02,
            'html_link_count': 0.02,
            'has_hidden_links': 0.25,
            'has_form': 0.15,
            'has_iframe': 0.20,
            'has_external_script': 0.25,
        }
    
    def _load_model(self) -> bool:
        """Load pre-trained model"""
        model_path = self.config.detection.model_path
        
        if not os.path.exists(model_path):
            self.logger.warning(f"Model file not found: {model_path}, using demo mode")
            return False
        
        try:
            import lightgbm as lgb
            self.model = lgb.Booster(model_file=model_path)
            self.logger.info(f"Loaded LightGBM model: {model_path}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to load model: {e}")
            return False
    
    def analyze(
        self,
        email_data: Dict,
        features: Dict,
        url_risk_level: str = 'UNKNOWN',
        url_risk_score: int = 0
    ) -> Tuple[str, float, str]:
        """
        Analyze email for phishing detection
        
        Args:
            email_data: Parsed email data
            features: Feature vector
            url_risk_level: URL risk level from URL analyzer
            url_risk_score: URL risk score from URL analyzer
            
        Returns:
            Tuple of (label, confidence, reason)
        """
        url_reasons: List[str] = []
        
        kill_reason = self._check_kill_switch(features, url_risk_level, url_risk_score)
        if kill_reason:
            return "PHISHING", 0.99, f"Hard Rule Triggered: {kill_reason}"
        
        sandbox_risk = self._check_sandbox_risk(features)
        base_confidence = 0.65 if sandbox_risk == "HIGH_RISK_FILE_NO_RESULT" else 0.0
        
        if self.model:
            input_data = [[float(features.get(col, 0)) for col in FEATURE_COLUMNS]]
            prediction = self.model.predict(np.array(input_data))
            
            if isinstance(prediction, (list, np.ndarray)):
                model_prob = float(prediction[0]) if len(prediction) > 0 else 0.0
            else:
                model_prob = float(prediction)
        else:
            _, model_prob = self._demo_predict(features, email_data)
            model_prob = float(model_prob)
        
        url_weight = 0.4
        model_weight = 0.6
        
        if url_risk_level == 'HIGH':
            final_confidence = max(base_confidence, model_prob, url_risk_score / 100)
        elif url_risk_level == 'MEDIUM':
            final_confidence = max(base_confidence, model_prob * model_weight + (url_risk_score / 100) * url_weight)
        else:
            final_confidence = max(base_confidence, model_prob)
        
        if features.get('first_external_ip_is_blacklisted'):
            final_confidence = min(1.0, final_confidence + 0.2)
        
        return self._determine_label(final_confidence, features, url_reasons)
    
    def _check_kill_switch(
        self,
        features: Dict,
        url_risk_level: str,
        url_risk_score: int
    ) -> Optional[str]:
        """Check hard kill switch rules"""
        if features.get('sandbox_detected'):
            return "Sandbox Detected Malware"
        
        if (features.get('spf_fail') and features.get('dkim_fail') and 
            features.get('dmarc_fail') and features.get('from_display_name_mismatch')):
            return "Authentication Failed + Impersonation"
        
        if features.get('max_vt_detection_ratio', 0) > 0.5:
            return "Known Malicious URL"
        
        if url_risk_level == 'HIGH' and url_risk_score >= 80:
            return f"High Risk URL Detected (Score: {url_risk_score})"
        
        return None
    
    def _check_sandbox_risk(self, features: Dict) -> Optional[str]:
        """Check sandbox risk"""
        if features.get('has_executable_attachment') and not features.get('has_sandbox_analysis'):
            return "HIGH_RISK_FILE_NO_RESULT"
        return None
    
    def _determine_label(
        self,
        confidence: float,
        features: Dict,
        url_reasons: List[str]
    ) -> Tuple[str, float, str]:
        """Determine final label based on confidence"""
        phishing_threshold = self.config.detection.phishing_threshold
        suspicious_threshold = self.config.detection.suspicious_threshold
        
        if confidence >= phishing_threshold:
            return self._build_phishing_result(features, url_reasons, confidence)
        elif confidence >= suspicious_threshold:
            return self._build_suspicious_result(features, url_reasons, confidence)
        else:
            return self._build_safe_result(features, confidence)
    
    def _build_phishing_result(
        self,
        features: Dict,
        url_reasons: List[str],
        confidence: float
    ) -> Tuple[str, float, str]:
        """Build phishing detection result"""
        reasons = []
        
        if url_reasons:
            reasons.append(f"URL风险: {'; '.join(url_reasons[:3])}")
        
        if features.get('is_suspicious_from_domain'):
            reasons.append("可疑的发件人域名")
        if features.get('spf_fail') and features.get('dkim_fail') and features.get('dmarc_fail'):
            reasons.append("邮件认证失败（SPF/DKIM/DMARC全部失败）")
        elif features.get('spf_fail'):
            reasons.append("SPF认证失败")
        elif features.get('dkim_fail'):
            reasons.append("DKIM认证失败")
        elif features.get('dmarc_fail'):
            reasons.append("DMARC认证失败")
        if features.get('from_display_name_mismatch'):
            reasons.append("发件人显示名称与邮箱不匹配")
        
        if features.get('has_executable_attachment'):
            reasons.append("包含可执行文件附件")
        if features.get('has_suspicious_attachment'):
            reasons.append("包含可疑附件")
        if features.get('has_double_extension'):
            reasons.append("附件使用双重扩展名")
        if features.get('sandbox_detected'):
            reasons.append("沙箱检测到恶意代码")
        
        if features.get('has_html_body'):
            reasons.append("包含HTML正文")
        if features.get('html_link_count', 0) > 5:
            reasons.append("HTML链接数量异常")
        if features.get('has_hidden_links'):
            reasons.append("包含隐藏链接")
        if features.get('has_form'):
            reasons.append("包含表单（可能用于窃取信息）")
        if features.get('has_iframe'):
            reasons.append("包含iframe（可能用于恶意重定向）")
        
        if features.get('urgent_keywords_count', 0) > 3:
            reasons.append("包含过多紧急关键词")
        if features.get('financial_keywords_count', 0) > 2:
            reasons.append("包含金融相关关键词")
        
        reason = "；".join(reasons) if reasons else "检测到高置信度钓鱼邮件特征"
        
        return "PHISHING", confidence, reason
    
    def _build_suspicious_result(
        self,
        features: Dict,
        url_reasons: List[str],
        confidence: float
    ) -> Tuple[str, float, str]:
        """Build suspicious detection result"""
        reasons = []
        
        if url_reasons:
            reasons.append(f"URL风险: {'; '.join(url_reasons[:2])}")
        
        if features.get('is_suspicious_from_domain'):
            reasons.append("发件人域名可疑")
        if features.get('spf_fail') or features.get('dkim_fail') or features.get('dmarc_fail'):
            reasons.append("邮件认证存在问题")
        if features.get('from_display_name_mismatch'):
            reasons.append("发件人显示名称与邮箱可能不匹配")
        
        if features.get('attachment_count', 0) > 3:
            reasons.append("附件数量异常")
        if features.get('has_suspicious_attachment'):
            reasons.append("存在可疑附件")
        
        if features.get('urgent_keywords_count', 0) > 1:
            reasons.append("包含紧急关键词")
        
        reason = "；".join(reasons) + "，建议人工复核" if reasons else "检测到可疑特征，建议人工复核"
        
        return "SUSPICIOUS", confidence, reason
    
    def _build_safe_result(
        self,
        features: Dict,
        confidence: float
    ) -> Tuple[str, float, str]:
        """Build safe detection result"""
        safe_reasons = []
        
        if not features.get('is_suspicious_from_domain'):
            safe_reasons.append("发件人域名正常")
        if not features.get('spf_fail') and not features.get('dkim_fail') and not features.get('dmarc_fail'):
            safe_reasons.append("邮件认证通过")
        if features.get('url_count', 0) == 0:
            safe_reasons.append("未发现可疑链接")
        if features.get('attachment_count', 0) == 0:
            safe_reasons.append("无附件")
        
        reason = "；".join(safe_reasons) if safe_reasons else "未检测到显著威胁"
        
        return "SAFE", confidence, reason
    
    def _demo_predict(
        self,
        feature_vector: Dict,
        email_data: Dict
    ) -> Tuple[bool, float]:
        """Demo prediction using rule-based approach"""
        score = 0.0
        
        subject = email_data.get('subject', '') if email_data else ''
        body = ""
        if email_data:
            body = email_data.get('body', '') + email_data.get('html_body', '')
        
        has_trusted_domain = False
        urls = feature_vector.get('urls', [])
        for url in urls:
            from urllib.parse import urlparse
            try:
                parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
                domain = parsed.netloc.split(':')[0]
                domain_parts = domain.split('.')
                if len(domain_parts) >= 2:
                    registered_domain = '.'.join(domain_parts[-2:])
                    if registered_domain in self.config.whitelist.trusted_domains:
                        has_trusted_domain = True
                        break
            except:
                pass
        
        is_verification = self._is_verification_email(subject, body)
        
        weight_scale = 0.6
        
        for feature, weight in self.demo_weights.items():
            value = float(feature_vector.get(feature, 0))
            adjusted_weight = weight * weight_scale
            
            if feature == 'avg_domain_age_days':
                if not has_trusted_domain:
                    if value < 30:
                        score += adjusted_weight * 0.6
                    elif value < 90:
                        score += adjusted_weight * 0.3
                    elif value < 365:
                        score += adjusted_weight * 0.1
            elif feature == 'text_length':
                score += adjusted_weight * max(0, (1000 - value)) / 1000
            else:
                score += adjusted_weight * value
        
        if has_trusted_domain:
            score -= 0.5
        
        if is_verification:
            high_risk_features = [
                feature_vector.get('has_executable_attachment', 0),
                feature_vector.get('sandbox_detected', 0),
                feature_vector.get('has_hidden_links', 0),
                feature_vector.get('ip_address_count', 0),
                feature_vector.get('has_suspicious_attachment', 0),
            ]
            high_risk_count = sum(1 for f in high_risk_features if f > 0)
            
            if high_risk_count == 0:
                score -= 0.4
            elif high_risk_count <= 1:
                score -= 0.2
        
        import math
        confidence = 1 / (1 + math.exp(-score))
        
        is_phish = confidence > self.config.detection.phishing_threshold
        
        return is_phish, confidence
    
    def _is_verification_email(self, subject: str, body: str) -> bool:
        """Check if email is a verification email"""
        indicators = self.config.whitelist.verification_indicators
        text = (subject + " " + body).lower()
        
        for indicator in indicators:
            if indicator.lower() in text:
                return True
        
        return False
    
    def batch_analyze(
        self,
        email_data_list: List[Dict],
        feature_vectors: List[Dict]
    ) -> List[Tuple[str, float, str]]:
        """Batch analyze multiple emails"""
        results = []
        for email_data, features in zip(email_data_list, feature_vectors):
            result = self.analyze(email_data, features)
            results.append(result)
        return results
