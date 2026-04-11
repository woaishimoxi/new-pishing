"""
检测服务
集成轻量模型检测 + 规则引擎 + AI语义分析
"""
import os
import re
import json
import numpy as np
from typing import Dict, List, Tuple, Optional
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config, DetectionError

# 导入轻量模型服务
from app.services.lightweight_features import extract_features
from app.services.lightweight_model import (
    load_models, 
    is_models_available,
    ensemble_score
)


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
    钓鱼邮件检测服务
    实现多分类检测 (PHISHING/SUSPICIOUS/SAFE)
    集成轻量模型 + 规则引擎 + AI语义分析
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        
        # 加载轻量模型
        load_models()
        self.model_available = is_models_available()
        self.logger.info(f"轻量模型状态: {self.model_available}")
    
    def analyze(
        self,
        email_data: Dict,
        features: Dict,
        ai_analysis: Dict = None,
        url_analysis: Dict = None
    ) -> Tuple[str, float, str, Dict]:
        """
        邮件检测分析
        
        核心原则：
        1. 融合评分 = 最终决策的唯一依据
        2. 高风险指标一票否决
        3. 评分与判定严格一致
        
        Args:
            email_data: 解析后的邮件数据
            features: 特征向量
            ai_analysis: AI语义分析结果（可选）
            url_analysis: URL分析结果（可选）
            
        Returns:
            (label, confidence, reason, model_scores)
        """
        model_scores = {
            'rf': None,
            'xgb': None,
            'anomaly': None,
            'rule': 0.0,
            'ai': None,
            'url': None,
            'kill_switch': None
        }
        
        all_risk_indicators = []
        
        # 1. Kill Switch检查（一票否决规则）
        kill_reason = self._check_kill_switch(features, url_analysis)
        if kill_reason:
            model_scores['kill_switch'] = 1.0
            model_scores['rule'] = 1.0
            all_risk_indicators.append(f"⚠️ {kill_reason}")
            return "PHISHING", 0.99, f"【一票否决】{kill_reason}", model_scores
        
        # 2. 轻量模型检测
        model_score = None
        model_details = {}
        
        try:
            features_35d = extract_features(email_data, '35d')
            features_26d = extract_features(email_data, '26d')
            
            from app.services.lightweight_model import score_with_rf, score_with_xgb, score_with_anomaly_detector
            
            rf_score = score_with_rf(features_35d)
            xgb_score = score_with_xgb(features_35d)
            anomaly_score = score_with_anomaly_detector(features_26d)
            
            model_scores['rf'] = rf_score
            model_scores['xgb'] = xgb_score
            model_scores['anomaly'] = anomaly_score
            
            model_score, model_details = ensemble_score(features_35d, features_26d)
            
            if model_score is not None:
                self.logger.debug(f"轻量模型得分: {model_score:.4f}, RF={rf_score}, XGB={xgb_score}, Anomaly={anomaly_score}")
                
                if rf_score is not None and rf_score > 0.7:
                    all_risk_indicators.append(f"RF模型高风险 ({rf_score:.2f})")
                if xgb_score is not None and xgb_score > 0.7:
                    all_risk_indicators.append(f"XGB模型高风险 ({xgb_score:.2f})")
        except Exception as e:
            self.logger.warning(f"轻量模型检测失败: {e}")
        
        # 3. 规则引擎评分
        rule_score, rule_indicators = self._rule_engine_score_with_indicators(features, email_data)
        model_scores['rule'] = rule_score
        all_risk_indicators.extend(rule_indicators)
        
        # 4. AI语义分析评分
        ai_score = None
        if ai_analysis and ai_analysis.get('is_phishing') is not None:
            ai_score = 0.8 if ai_analysis.get('is_phishing') else 0.2
            if ai_analysis.get('risk_score'):
                ai_score = ai_analysis['risk_score'] / 100.0
            
            if ai_analysis.get('is_phishing'):
                all_risk_indicators.append(f"AI判定为钓鱼 ({ai_score:.2f})")
        model_scores['ai'] = ai_score
        
        # 5. URL分析评分
        url_score = None
        if url_analysis:
            if url_analysis.get('max_risk_score'):
                url_score = url_analysis['max_risk_score'] / 100.0
            
            if url_analysis.get('high_risk_count', 0) > 0:
                all_risk_indicators.append(f"发现{url_analysis['high_risk_count']}个高风险URL")
            
            url_results = url_analysis.get('url_results', [])
            for url_result in url_results[:3]:
                if url_result.get('threatbook_malicious'):
                    all_risk_indicators.append(f"微步在线标记恶意URL: {url_result.get('domain', '')}")
        model_scores['url'] = url_score
        
        # 6. 融合评分（核心逻辑：评分驱动决策）
        # 
        # 权重设计原则（参考网络安全专家建议）：
        # - URL分析是钓鱼检测的核心杀招，权重最高
        # - AI语义分析识别社会工程学，权重次高
        # - RF/异常检测器作为辅助判断
        # - 规则引擎仅作基础参考（已知威胁应走熔断机制）
        #
        scores = []
        weights = []
        score_details = []
        
        # RF/XGB模型（辅助判断）- 权重 1.0
        if model_score is not None:
            scores.append(model_score)
            weights.append(1.0)
            score_details.append(f"模型={model_score:.2f}×1.0")
        
        # 规则引擎（基础参考）- 权重 0.5
        scores.append(rule_score)
        weights.append(0.5)
        score_details.append(f"规则={rule_score:.2f}×0.5")
        
        # AI语义分析（核心主力）- 权重 2.0
        if ai_score is not None:
            scores.append(ai_score)
            weights.append(2.0)
            score_details.append(f"AI={ai_score:.2f}×2.0")
        
        # URL分析（最高优先级）- 权重 3.0
        if url_score is not None:
            scores.append(url_score)
            weights.append(3.0)
            score_details.append(f"URL={url_score:.2f}×3.0")
        
        if scores:
            final_confidence = sum(s * w for s, w in zip(scores, weights)) / sum(weights)
        else:
            final_confidence = rule_score
        
        self.logger.info(f"融合评分: {' + '.join(score_details)} = {final_confidence:.4f}")
        
        # 7. 高风险指标二次检查（确保不漏过）
        high_risk_score = max(
            model_scores.get('rf') or 0,
            model_scores.get('xgb') or 0,
            model_scores.get('ai') or 0,
            model_scores.get('url') or 0
        )
        
        if high_risk_score >= 0.85 and final_confidence < 0.6:
            self.logger.warning(f"高风险指标被低估: 最高单项={high_risk_score}, 融合={final_confidence}")
            final_confidence = max(final_confidence, high_risk_score)
            all_risk_indicators.append("高风险指标修正")
        
        # 8. 阈值判断（严格一致）
        if final_confidence >= 0.60:
            label = "PHISHING"
        elif final_confidence >= 0.35:
            label = "SUSPICIOUS"
        else:
            label = "SAFE"
        
        reason = "；".join(all_risk_indicators) if all_risk_indicators else f"综合评分: {final_confidence:.2%}"
        
        self.logger.info(f"最终判定: {label}, 置信度: {final_confidence:.4f}, 指标数: {len(all_risk_indicators)}")
        
        return label, round(final_confidence, 4), reason, model_scores
    
    def _check_kill_switch(self, features: Dict, url_analysis: Dict = None) -> Optional[str]:
        """
        检查硬规则触发（一票否决规则）
        
        这些规则一旦触发，直接判定为钓鱼邮件，不参与融合评分
        """
        # 1. 沙箱检测到恶意代码 - 最高优先级
        if features.get('sandbox_detected'):
            return "沙箱检测到恶意代码"
        
        # 2. 包含可执行文件附件 - 高风险
        if features.get('has_executable_attachment'):
            return "包含可执行文件附件"
        
        # 3. 源IP在黑名单中 - 高优先级（修复逻辑缺陷）
        if features.get('first_external_ip_is_blacklisted'):
            return "源IP被列入黑名单（高风险来源）"
        
        # 4. 邮件认证全部失败 + 发件人冒充 - 高风险
        if (features.get('spf_fail') and features.get('dkim_fail') and 
            features.get('dmarc_fail') and features.get('from_display_name_mismatch')):
            return "邮件认证全部失败+发件人冒充"
        
        # 5. URL高风险触发
        if url_analysis and url_analysis.get('max_risk_level') == 'HIGH':
            if url_analysis.get('high_risk_count', 0) >= 2:
                return "多个高风险URL检测"
        
        # 6. 双重扩展名附件
        if features.get('has_double_extension'):
            return "附件使用双重扩展名（常见恶意软件手法）"
        
        # 7. 隐藏链接 + 表单（钓鱼特征组合）
        if features.get('has_hidden_links') and features.get('has_form'):
            return "邮件包含隐藏链接和表单（钓鱼特征）"
        
        return None
    
    def _rule_engine_score(self, features: Dict, email_data: Dict) -> float:
        """
        规则引擎评分
        
        修复：调整权重分配，确保高危特征有更高权重
        邮件认证通过不应该大幅降低风险
        """
        score = 0.0
        
        # 【高危特征】- 权重最高
        
        # 源IP在黑名单中（+0.40）- 重大风险
        if features.get('first_external_ip_is_blacklisted'):
            score += 0.40
        
        # 沙箱检测到恶意（+0.50）- 最高优先级
        if features.get('sandbox_detected'):
            score += 0.50
        
        # 包含可执行文件（+0.30）
        if features.get('has_executable_attachment'):
            score += 0.30
        
        # 双重扩展名（+0.25）
        if features.get('has_double_extension'):
            score += 0.25
        
        # 【中高风险特征】
        
        # 可疑发件人域名（+0.20）
        if features.get('is_suspicious_from_domain'):
            score += 0.20
        
        # 邮件认证失败（+0.15 每项）
        if features.get('spf_fail'):
            score += 0.15
        if features.get('dkim_fail'):
            score += 0.15
        if features.get('dmarc_fail'):
            score += 0.15
        
        # 发件人显示名不匹配（+0.15）
        if features.get('from_display_name_mismatch'):
            score += 0.15
        
        # 【中风险特征】
        
        # IP地址URL（+0.20）
        if features.get('ip_address_count', 0) > 0:
            score += 0.20
        
        # 短链接（+0.10）
        if features.get('short_url_count', 0) > 0:
            score += 0.10
        
        # 隐藏链接（+0.20）
        if features.get('has_hidden_links'):
            score += 0.20
        
        # 表单（+0.15）
        if features.get('has_form'):
            score += 0.15
        
        # iframe（+0.10）
        if features.get('has_iframe'):
            score += 0.10
        
        # 【文本特征】
        
        # 紧急关键词过多（+0.15）
        if features.get('urgent_keywords_count', 0) >= 3:
            score += 0.15
        
        # 金融关键词过多（+0.12）
        if features.get('financial_keywords_count', 0) >= 2:
            score += 0.12
        
        # 可疑附件（+0.15）
        if features.get('has_suspicious_attachment'):
            score += 0.15
        
        # 【修复】邮件认证通过不应该大幅降低风险
        # 仅当所有认证都通过且没有其他风险时才稍微降低
        spf_pass = not features.get('spf_fail')
        dkim_pass = not features.get('dkim_fail')
        dmarc_pass = not features.get('dmarc_fail')
        
        if spf_pass and dkim_pass and dmarc_pass:
            # 认证通过，但只降低0.05（之前是降低太多）
            score = max(0.0, score - 0.05)
        
        return min(1.0, score)
    
    def _rule_engine_score_with_indicators(self, features: Dict, email_data: Dict) -> Tuple[float, List[str]]:
        """
        规则引擎评分（带风险指标返回）
        
        Returns:
            (score, indicators) - 评分和风险指标列表
        """
        score = 0.0
        indicators = []
        
        # 【一票否决级】- 这些特征应该已经被Kill Switch捕获，但这里作为备份
        if features.get('first_external_ip_is_blacklisted'):
            score += 0.40
            indicators.append("源IP在黑名单中")
        
        if features.get('sandbox_detected'):
            score += 0.50
            indicators.append("沙箱检测到恶意代码")
        
        if features.get('has_executable_attachment'):
            score += 0.30
            indicators.append("包含可执行文件附件")
        
        if features.get('has_double_extension'):
            score += 0.25
            indicators.append("附件使用双重扩展名")
        
        # 【高危特征】
        if features.get('is_suspicious_from_domain'):
            score += 0.20
            indicators.append("可疑的发件人域名")
        
        auth_failures = []
        if features.get('spf_fail'):
            score += 0.15
            auth_failures.append("SPF")
        if features.get('dkim_fail'):
            score += 0.15
            auth_failures.append("DKIM")
        if features.get('dmarc_fail'):
            score += 0.15
            auth_failures.append("DMARC")
        
        if auth_failures:
            indicators.append(f"邮件认证失败: {', '.join(auth_failures)}")
        
        if features.get('from_display_name_mismatch'):
            score += 0.15
            indicators.append("发件人显示名与邮箱不匹配")
        
        # 【中风险特征】
        if features.get('ip_address_count', 0) > 0:
            score += 0.20
            indicators.append(f"包含{features.get('ip_address_count', 0)}个IP地址URL")
        
        if features.get('short_url_count', 0) > 0:
            score += 0.10
            indicators.append("包含短链接")
        
        if features.get('has_hidden_links'):
            score += 0.20
            indicators.append("包含隐藏链接")
        
        if features.get('has_form'):
            score += 0.15
            indicators.append("包含表单")
        
        if features.get('has_iframe'):
            score += 0.10
            indicators.append("包含iframe")
        
        # 【文本特征】
        if features.get('urgent_keywords_count', 0) >= 3:
            score += 0.15
            indicators.append("包含大量紧急关键词")
        elif features.get('urgent_keywords_count', 0) >= 1:
            score += 0.08
        
        if features.get('financial_keywords_count', 0) >= 2:
            score += 0.12
            indicators.append("包含金融相关关键词")
        
        if features.get('has_suspicious_attachment'):
            score += 0.15
            indicators.append("包含可疑附件")
        
        # 【认证通过】仅当没有其他风险时稍微降低
        spf_pass = not features.get('spf_fail')
        dkim_pass = not features.get('dkim_fail')
        dmarc_pass = not features.get('dmarc_fail')
        
        if spf_pass and dkim_pass and dmarc_pass and score < 0.1:
            score = max(0.0, score - 0.05)
        
        return min(1.0, score), indicators
