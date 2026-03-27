"""
Detection Service
Core phishing detection logic with new trained model
"""
import os
import re
import json
import pickle
import numpy as np
from typing import Dict, List, Tuple, Optional
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config, DetectionError


NEW_FEATURE_COLUMNS = [
    'text_length', 'word_count', 'uppercase_ratio', 'exclamation_count',
    'question_count', 'digit_ratio', 'special_char_ratio', 'url_count',
    'ip_url_count', 'shortened_url_count', 'urgent_word_count',
    'financial_word_count', 'phishing_pattern_count', 'email_count',
    'html_tag_count', 'link_count', 'form_count'
]

LEGACY_FEATURE_COLUMNS = [
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

URGENT_WORDS = [
    'urgent', 'immediately', 'important', 'attention', 'alert',
    'warning', 'critical', 'verify', 'confirm', 'suspend',
    '紧急', '立即', '重要', '注意', '警告', '验证', '确认', '暂停'
]

FINANCIAL_WORDS = [
    'bank', 'account', 'password', 'credit', 'debit', 'pin',
    'ssn', 'security', 'login', 'verify', 'update',
    '银行', '账户', '密码', '信用卡', '安全', '登录', '验证', '更新'
]

PHISHING_PATTERNS = [
    r'click\s+here',
    r'verify\s+your\s+account',
    r'your\s+account\s+has\s+been',
    r'suspended',
    r'limited',
    r'unusual\s+activity',
    r'confirm\s+your\s+identity',
    r'update\s+your\s+information',
    r'click\s+below',
    r'act\s+now',
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
        self.model_type = None
        self.feature_names = None
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
        
        current_file = os.path.abspath(__file__)
        backend_dir = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
        base_dir = os.path.dirname(backend_dir)
        
        pkl_path = os.path.join(base_dir, 'models', 'phish_detector.pkl')
        txt_path = os.path.join(base_dir, 'models', 'phish_detector.txt')
        feature_info_path = os.path.join(base_dir, 'models', 'feature_info.json')
        
        self.logger.info(f"Looking for model files in: {os.path.join(base_dir, 'models')}")
        self.logger.info(f"PKL path exists: {os.path.exists(pkl_path)}")
        self.logger.info(f"TXT path exists: {os.path.exists(txt_path)}")
        
        if os.path.exists(pkl_path):
            try:
                with open(pkl_path, 'rb') as f:
                    self.model = pickle.load(f)
                self.model_type = 'new'
                self.logger.info(f"Loaded new LightGBM model from pickle: {pkl_path}")
                
                if os.path.exists(feature_info_path):
                    with open(feature_info_path, 'r', encoding='utf-8') as f:
                        feature_info = json.load(f)
                        self.feature_names = feature_info.get('feature_names', NEW_FEATURE_COLUMNS)
                        self.logger.info(f"Model metrics: {feature_info.get('metrics', {})}")
                else:
                    self.feature_names = NEW_FEATURE_COLUMNS
                
                return True
            except Exception as e:
                self.logger.error(f"Failed to load pickle model: {e}")
        
        if os.path.exists(txt_path):
            try:
                import lightgbm as lgb
                self.model = lgb.Booster(model_file=txt_path)
                self.model_type = 'legacy'
                self.feature_names = LEGACY_FEATURE_COLUMNS
                self.logger.info(f"Loaded legacy LightGBM model: {txt_path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to load legacy model: {e}")
        
        if os.path.exists(model_path):
            try:
                import lightgbm as lgb
                self.model = lgb.Booster(model_file=model_path)
                self.model_type = 'legacy'
                self.feature_names = LEGACY_FEATURE_COLUMNS
                self.logger.info(f"Loaded LightGBM model: {model_path}")
                return True
            except Exception as e:
                self.logger.error(f"Failed to load model: {e}")
        
        self.logger.warning(f"No model file found, using demo mode")
        return False
    
    def _extract_new_features(self, email_data: Dict, features: Dict) -> Dict[str, float]:
        """Extract features for new model"""
        text = ""
        if email_data:
            text = str(email_data.get('body', '')) + ' ' + str(email_data.get('html_body', ''))
            text += ' ' + str(email_data.get('subject', ''))
        
        text_lower = text.lower()
        
        if not text:
            return {name: 0.0 for name in NEW_FEATURE_COLUMNS}
        
        extracted = {}
        
        extracted['text_length'] = float(len(text))
        
        words = text.split()
        extracted['word_count'] = float(len(words))
        
        alpha_chars = [c for c in text if c.isalpha()]
        if alpha_chars:
            extracted['uppercase_ratio'] = float(sum(1 for c in alpha_chars if c.isupper()) / len(alpha_chars))
        else:
            extracted['uppercase_ratio'] = 0.0
        
        extracted['exclamation_count'] = float(text.count('!'))
        extracted['question_count'] = float(text.count('?'))
        
        if text:
            extracted['digit_ratio'] = float(sum(1 for c in text if c.isdigit()) / len(text))
            special_chars = sum(1 for c in text if not c.isalnum() and not c.isspace())
            extracted['special_char_ratio'] = float(special_chars / len(text))
        else:
            extracted['digit_ratio'] = 0.0
            extracted['special_char_ratio'] = 0.0
        
        url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
        urls = re.findall(url_pattern, text, re.IGNORECASE)
        extracted['url_count'] = float(len(urls))
        
        ip_urls = len(re.findall(r'https?://\d+\.\d+\.\d+\.\d+', text, re.IGNORECASE))
        extracted['ip_url_count'] = float(ip_urls)
        
        shorteners = ['bit.ly', 'tinyurl', 'goo.gl', 't.co', 'ow.ly', 'is.gd', 'buff.ly', 'dlvr.it']
        shortened = sum(1 for url in urls for s in shorteners if s in url.lower())
        extracted['shortened_url_count'] = float(shortened)
        
        extracted['urgent_word_count'] = float(sum(1 for word in URGENT_WORDS if word in text_lower))
        extracted['financial_word_count'] = float(sum(1 for word in FINANCIAL_WORDS if word in text_lower))
        
        extracted['phishing_pattern_count'] = float(sum(
            1 for pattern in PHISHING_PATTERNS if re.search(pattern, text_lower)
        ))
        
        emails = re.findall(r'[\w\.-]+@[\w\.-]+\.\w+', text)
        extracted['email_count'] = float(len(emails))
        
        html_tags = len(re.findall(r'<[^>]+>', text))
        extracted['html_tag_count'] = float(html_tags)
        
        links = len(re.findall(r'<a\s', text_lower))
        extracted['link_count'] = float(links)
        
        forms = len(re.findall(r'<form', text_lower))
        extracted['form_count'] = float(forms)
        
        return extracted
    
    def analyze(
        self,
        email_data: Dict,
        features: Dict,
        url_risk_level: str = 'UNKNOWN',
        url_risk_score: int = 0,
        url_analysis: Dict = None
    ) -> Tuple[str, float, str]:
        """
        Analyze email for phishing detection - improved version
        
        Args:
            email_data: Parsed email data
            features: Feature vector
            url_risk_level: URL risk level from URL analyzer
            url_risk_score: URL risk score from URL analyzer
            url_analysis: URL analysis results with whitelist info
            
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
            if self.model_type == 'new':
                new_features = self._extract_new_features(email_data, features)
                input_data = [[float(new_features.get(col, 0)) for col in self.feature_names]]
                prediction = self.model.predict(np.array(input_data))
            else:
                input_data = [[float(features.get(col, 0)) for col in self.feature_names]]
                prediction = self.model.predict(np.array(input_data))
            
            if isinstance(prediction, (list, np.ndarray)):
                model_prob = float(prediction[0]) if len(prediction) > 0 else 0.0
            else:
                model_prob = float(prediction)
        else:
            _, model_prob = self._demo_predict(features, email_data)
            model_prob = float(model_prob)
        
        # 可配置的权重 - 从配置文件读取或使用默认值
        model_weight = float(self.config.detection.get('model_weight', 0.6) if hasattr(self.config.detection, 'get') else 0.6)
        url_weight = float(self.config.detection.get('url_weight', 0.4) if hasattr(self.config.detection, 'get') else 0.4)
        
        # 获取规则评分
        _, rule_score = self._demo_predict(features, email_data)
        
        # 三维度融合：模型 + URL + 规则
        if url_risk_level == 'HIGH':
            final_confidence = max(base_confidence, model_prob, url_risk_score / 100)
        elif url_risk_level == 'MEDIUM':
            final_confidence = (
                model_prob * model_weight + 
                (url_risk_score / 100) * url_weight
            )
        else:
            final_confidence = model_prob
        
        # 规则评分微调（±0.1）
        if rule_score > 0.7:
            final_confidence = min(1.0, final_confidence + 0.1)
        elif rule_score < 0.3:
            final_confidence = max(0.0, final_confidence - 0.1)
        
        if features.get('first_external_ip_is_blacklisted'):
            final_confidence = min(1.0, final_confidence + 0.2)
        
        # 改进1: 白名单URL降低风险
        if url_analysis:
            summary = url_analysis.get('summary', {})
            total_urls = summary.get('total_urls', 0)
            whitelisted = summary.get('whitelisted', 0)
            high_risk = summary.get('high_risk', 0)
            
            # 如果所有URL都在白名单中，大幅降低风险
            if total_urls > 0 and whitelisted == total_urls:
                final_confidence = max(0.0, final_confidence - 0.5)
            # 如果大部分URL在白名单中，适当降低风险
            elif total_urls > 0 and whitelisted / total_urls > 0.8:
                final_confidence = max(0.0, final_confidence - 0.3)
            # 如果没有高风险URL，降低风险
            if high_risk == 0 and url_risk_level == 'LOW':
                final_confidence = max(0.0, final_confidence - 0.2)
        
        # 改进2: 邮件认证全部通过降低风险
        spf_pass = features.get('spf_fail', 0) == 0
        dkim_pass = features.get('dkim_fail', 0) == 0
        dmarc_pass = features.get('dmarc_fail', 0) == 0
        
        if spf_pass and dkim_pass and dmarc_pass:
            # 三重认证全部通过，降低风险
            final_confidence = max(0.0, final_confidence - 0.3)
        elif spf_pass and dkim_pass:
            # 双重认证通过，适当降低风险
            final_confidence = max(0.0, final_confidence - 0.15)
        
        # 改进3: 发件人域名与链接域名一致降低风险
        from_email = email_data.get('from_email', '') if email_data else ''
        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
        
        if from_domain:
            # 检查邮件中的链接是否来自同一域名
            urls = email_data.get('urls', []) if email_data else []
            same_domain_count = 0
            for url in urls:
                try:
                    from urllib.parse import urlparse
                    parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
                    link_domain = parsed.netloc.lower()
                    if from_domain in link_domain or link_domain.endswith('.' + from_domain):
                        same_domain_count += 1
                except:
                    pass
            
            # 如果大部分链接来自同一域名，降低风险
            if len(urls) > 0 and same_domain_count / len(urls) > 0.5:
                final_confidence = max(0.0, final_confidence - 0.2)
        
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
        """Build phishing detection result - improved version"""
        reasons = []
        
        if url_reasons:
            reasons.append(f"URL风险: {'; '.join(url_reasons[:3])}")
        
        # 邮件头风险（高权重）
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
        
        # 附件风险（高权重）
        if features.get('has_executable_attachment'):
            reasons.append("包含可执行文件附件")
        if features.get('has_suspicious_attachment'):
            reasons.append("包含可疑附件")
        if features.get('has_double_extension'):
            reasons.append("附件使用双重扩展名")
        if features.get('sandbox_detected'):
            reasons.append("沙箱检测到恶意代码")
        
        # HTML风险（移除低风险特征）
        # has_html_body 和 html_link_count 不再作为钓鱼理由
        # 因为这些是合法营销邮件的正常特征
        if features.get('has_hidden_links'):
            reasons.append("包含隐藏链接")
        if features.get('has_form'):
            reasons.append("包含表单（可能用于窃取信息）")
        if features.get('has_iframe'):
            reasons.append("包含iframe（可能用于恶意重定向）")
        
        # 文本风险（提高阈值）
        if features.get('urgent_keywords_count', 0) > 5:
            reasons.append("包含过多紧急关键词")
        if features.get('financial_keywords_count', 0) > 3:
            reasons.append("包含金融相关关键词")
        if features.get('exclamation_count', 0) > 20:
            reasons.append("感叹号使用异常")
        
        # 添加风险分级
        risk_level = self._get_risk_level(features, reasons)
        
        reason = "；".join(reasons) if reasons else "检测到高置信度钓鱼邮件特征"
        
        # 附加风险等级提示
        if risk_level['high']:
            reason += f"\n[高危项] {'；'.join(risk_level['high'])}"
        
        return "PHISHING", confidence, reason
    
    def _get_risk_level(self, features: Dict, reasons: List[str]) -> Dict:
        """
        获取风险分级
        
        返回: {
            'high': [高危项列表],
            'medium': [中危项列表],
            'low': [低危项列表]
        }
        """
        high_risk = []
        medium_risk = []
        low_risk = []
        
        # 高危特征
        if features.get('has_executable_attachment'):
            high_risk.append("包含可执行文件")
        if features.get('sandbox_detected'):
            high_risk.append("沙箱检测到恶意代码")
        if features.get('spf_fail') and features.get('dkim_fail') and features.get('dmarc_fail'):
            high_risk.append("三重认证全部失败")
        if features.get('first_external_ip_is_blacklisted'):
            high_risk.append("源IP在黑名单中")
        
        # 中风险特征
        if features.get('is_suspicious_from_domain'):
            medium_risk = True
        if features.get('has_hidden_links'):
            medium_risk = True
        if features.get('ip_address_count', 0) > 0:
            medium_risk = True
        
        return {
            'high': len([r for r in reasons if any(k in r for k in ['可执行', '恶意', '黑名单', '沙箱'])]),
            'medium': len(reasons),
            'low': 0
        }
    
    def _get_risk_level(self, features: Dict, reasons: List[str]) -> Dict:
        """获取风险等级分类"""
        high_risk = []
        medium_risk = []
        low_risk = []
        
        for reason in reasons:
            if any(kw in reason for kw in ['可执行', '恶意代码', '黑名单', '沙箱', '双重扩展']):
                high_risk.append(reason)
            elif any(kw in reason for kw in ['可疑', '失败', '隐藏', 'IP地址', '表单']):
                medium_risk.append(reason)
            else:
                low_risk.append(reason)
        
        return {
            'high_risk': high_risk,
            'medium_risk': medium_risk,
            'low_risk': low_risk,
            'total_risk_score': len(high_risk) * 3 + len(medium_risk) * 2 + len(low_risk)
        }
    
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
        """
        规则评分引擎 - 细粒度评分系统
        
        返回: (是否钓鱼, 置信度)
        """
        score = 0.0
        reasons = []  # 记录扣分原因
        
        subject = email_data.get('subject', '') if email_data else ''
        body = ""
        if email_data:
            body = email_data.get('body', '') + email_data.get('html_body', '')
        
        # ==================== 规则1: 域名信誉 (权重: 0.25) ====================
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
        
        if has_trusted_domain:
            score -= 0.3  # 可信域名大幅降低风险
        else:
            # 新域名风险
            domain_age = float(feature_vector.get('avg_domain_age_days', 365))
            if domain_age < 30:
                score += 0.15
                reasons.append("新注册域名（<30天）")
            elif domain_age < 90:
                score += 0.08
                reasons.append("较新域名（<90天）")
        
        # ==================== 规则2: 邮件认证 (权重: 0.20) ====================
        spf_fail = float(feature_vector.get('spf_fail', 0))
        dkim_fail = float(feature_vector.get('dkim_fail', 0))
        dmarc_fail = float(feature_vector.get('dmarc_fail', 0))
        
        if spf_fail and dkim_fail and dmarc_fail:
            score += 0.25
            reasons.append("邮件认证全部失败(SPF/DKIM/DMARC)")
        elif spf_fail or dkim_fail:
            score += 0.12
            reasons.append("邮件认证部分失败")
        
        # ==================== 规则3: 发件人异常 (权重: 0.15) ====================
        if float(feature_vector.get('is_suspicious_from_domain', 0)):
            score += 0.15
            reasons.append("可疑发件人域名")
        
        if float(feature_vector.get('from_display_name_mismatch', 0)):
            score += 0.10
            reasons.append("显示名称与邮箱不匹配")
        
        # ==================== 规则4: URL风险 (权重: 0.20) ====================
        ip_count = float(feature_vector.get('ip_address_count', 0))
        if ip_count > 0:
            score += 0.15
            reasons.append(f"包含{int(ip_count)}个IP地址URL")
        
        short_url = float(feature_vector.get('short_url_count', 0))
        if short_url > 0:
            score += 0.08
            reasons.append(f"包含{int(short_url)}个短链接")
        
        if not has_trusted_domain and len(urls) > 5:
            score += 0.05
            reasons.append("URL数量异常")
        
        # ==================== 规则5: 文本风险 (权重: 0.10) ====================
        urgent_count = float(feature_vector.get('urgent_keywords_count', 0))
        if urgent_count > 3:
            score += 0.10
            reasons.append(f"紧急关键词过多({int(urgent_count)}个)")
        
        financial_count = float(feature_vector.get('financial_keywords_count', 0))
        if financial_count > 2:
            score += 0.08
            reasons.append(f"金融关键词过多({int(financial_count)}个)")
        
        caps_ratio = float(feature_vector.get('caps_ratio', 0))
        if caps_ratio > 0.5:
            score += 0.05
            reasons.append("大写字母比例异常")
        
        exclamation = float(feature_vector.get('exclamation_count', 0))
        if exclamation > 10:
            score += 0.03
            reasons.append("感叹号使用过多")
        
        # ==================== 规则6: 附件风险 (权重: 0.10) ====================
        if float(feature_vector.get('has_executable_attachment', 0)):
            score += 0.20
            reasons.append("包含可执行文件附件")
        
        if float(feature_vector.get('has_suspicious_attachment', 0)):
            score += 0.12
            reasons.append("包含可疑附件")
        
        if float(feature_vector.get('has_double_extension', 0)):
            score += 0.15
            reasons.append("附件使用双重扩展名")
        
        # ==================== 规则7: HTML风险 (权重: 0.05) ====================
        if float(feature_vector.get('has_hidden_links', 0)):
            score += 0.15
            reasons.append("包含隐藏链接")
        
        if float(feature_vector.get('has_form', 0)):
            score += 0.10
            reasons.append("包含表单（可能窃取信息）")
        
        if float(feature_vector.get('has_iframe', 0)):
            score += 0.08
            reasons.append("包含iframe")
        
        # ==================== 规则8: 验证码邮件保护 ====================
        is_verification = self._is_verification_email(subject, body)
        
        if is_verification:
            high_risk_count = sum(1 for f in [
                feature_vector.get('has_executable_attachment', 0),
                feature_vector.get('has_hidden_links', 0),
                feature_vector.get('ip_address_count', 0),
            ] if float(f) > 0)
            
            if high_risk_count == 0:
                score -= 0.35  # 验证码邮件保护
                reasons.append("验证码邮件保护")
            elif high_risk_count == 1:
                score -= 0.15
        
        # ==================== 规则9: 黑名单检查 ====================
        if float(feature_vector.get('first_external_ip_is_blacklisted', 0)):
            score += 0.25
            reasons.append("源IP在黑名单中")
        
        # ==================== 规则10: 沙箱检测 ====================
        if float(feature_vector.get('sandbox_detected', 0)):
            score += 0.40
            reasons.append("沙箱检测到恶意代码")
        
        # ==================== 计算最终置信度 ====================
        import math
        confidence = 1 / (1 + math.exp(-score))
        
        # 保存评分原因
        self._last_rule_reasons = reasons
        
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
