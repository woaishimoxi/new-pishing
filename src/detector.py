"""
轻量级检测模型实现模块 - 修复版
本模块使用 LightGBM 作为核心分类器，对提取的特征向量进行钓鱼风险预测。
修复内容：
1. 集成新的URL分析器，修复白名单误报问题
2. 添加域名关键词检测（如phish）
3. 正确过滤非HTTP URL（cid:, mailto:等）
4. 修复域名年龄3650天默认值问题
"""
import os
import json
import pickle
from typing import Dict, List, Tuple, Optional
import numpy as np

# 导入新的URL分析器
try:
    from url_analyzer import analyze_urls, is_trusted_domain, check_domain_keywords
    URL_ANALYZER_AVAILABLE = True
except ImportError:
    URL_ANALYZER_AVAILABLE = False
    print("警告: URL分析器未加载")


# 特征列顺序 (与 features.py 中保持一致) - 39 维
FEATURE_COLUMNS = [
    # 邮件头特征 (8 维)
    'is_suspicious_from_domain', 'received_hops_count',
    'first_external_ip_is_blacklisted',
    'spf_fail', 'dkim_fail', 'dmarc_fail',
    'from_display_name_mismatch', 'from_domain_in_subject',

    # URL 特征 (14 维)
    'avg_domain_age_days', 'max_vt_detection_ratio',
    'min_has_https', 'short_url_count', 'mixed_sld_count',
    'max_domain_length',
    'ip_address_count', 'port_count',
    'at_symbol_count', 'subdomain_count', 'suspicious_param_count',
    'avg_url_length', 'avg_path_depth', 'max_query_length',

    # 文本特征 (7 维)
    'urgent_keywords_count', 'financial_keywords_count',
    'text_length', 'urgency_score', 'exclamation_count',
    'caps_ratio', 'url_count',

    # 附件特征 (5 维)
    'attachment_count', 'has_suspicious_attachment',
    'has_executable_attachment', 'total_attachment_size',
    'has_double_extension',

    # HTML 特征 (5 维)
    'has_html_body', 'html_link_count', 'has_hidden_links',
    'has_form', 'has_iframe',
]

# 三分类阈值定义（修复：更合理的分级）
THRESHOLD_PHISHING = 0.70   # >=70% 判定为钓鱼（高置信度）
THRESHOLD_SUSPICIOUS = 0.40  # >=40% 判定为可疑（中等置信度）
# <40% 判定为安全


class PhishingDetector:
    """
    钓鱼邮件检测器类
    支持加载预训练模型或生成模拟预测结果（用于演示）
    实现二分类（正常、钓鱼）检测逻辑
    """

    def __init__(self, model_path: Optional[str] = None, vt_api_key: Optional[str] = None):
        """
        初始化检测器。

        Args:
            model_path: 预训练模型文件路径 (LightGBM .txt 文件或自定义 Pickle 文件)
            vt_api_key: VirusTotal API 密钥
        """
        self.vt_api_key = vt_api_key
        self.model = None
        self.model_path = model_path or 'models/phish_detector.txt'
        # 定义阈值
        self.THRESHOLD_PHISHING = THRESHOLD_PHISHING
        self.THRESHOLD_SUSPICIOUS = THRESHOLD_SUSPICIOUS

        if model_path and os.path.exists(model_path):
            self.load_model()
        else:
            # 生成演示模型
            self.generate_demo_model()

    def load_model(self) -> bool:
        """
        加载预训练模型。

        Returns:
            bool: 是否成功加载
        """
        # 检查文件是否存在
        import os
        if not os.path.exists(self.model_path):
            print(f"模型文件不存在：{self.model_path}")
            self.model = None
            # 切换到演示模式
            self.generate_demo_model()
            return False
        
        try:
            # 尝试加载 LightGBM 模型
            import lightgbm as lgb
            self.model = lgb.Booster(model_file=self.model_path)
            print(f"成功加载 LightGBM 模型：{self.model_path}")
            return True
        except Exception as e:
            print(f"加载 LightGBM 模型失败：{e}")
            self.model = None
            # 切换到演示模式
            self.generate_demo_model()
            return False

    def generate_demo_model(self):
        """
        生成一个演示用的简单规则模型 (当没有真实训练数据时使用)
        这个模型基于简单的启发式规则进行预测
        """
        # 创建一个基于规则的简易检测函数
        self.is_demo_mode = True
        self.demo_weights = {
            # 邮件头特征 - 高风险
            'is_suspicious_from_domain': 0.30,
            'spf_fail': 0.20,
            'dkim_fail': 0.15,
            'dmarc_fail': 0.15,
            'from_display_name_mismatch': 0.20,
            'received_hops_count': 0.01,
            'first_external_ip_is_blacklisted': 0.25,
            'from_domain_in_subject': 0.10,

            # URL 特征 - 高风险
            'avg_domain_age_days': -0.0002,  # 年龄越小越可疑
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

            # 文本特征
            'urgent_keywords_count': 0.15,
            'financial_keywords_count': 0.12,
            'text_length': -0.0001,
            'urgency_score': 0.25,
            'exclamation_count': 0.05,
            'caps_ratio': 0.10,
            'url_count': 0.03,

            # 附件特征 - 高风险
            'attachment_count': 0.05,
            'has_suspicious_attachment': 0.25,
            'has_executable_attachment': 0.35,
            'total_attachment_size': 0.00001,
            'has_double_extension': 0.30,
            'sandbox_detected': 0.40,
            'max_sandbox_detection_ratio': 0.35,
            'has_sandbox_analysis': 0.05,
            'attachment_risk_score': 0.1,  # 新增：附件风险评分

            # HTML 特征
            'has_html_body': 0.02,
            'html_link_count': 0.02,
            'has_hidden_links': 0.25,
            'has_form': 0.15,
            'has_iframe': 0.20,
            'has_external_script': 0.25,
        }

    def analyze(self, email_data: Dict, features: Dict) -> Tuple[str, float, str]:
        """
        对邮件进行二分类分析 - 修复版。

        Args:
            email_data: 解析后的邮件数据
            features: 特征向量字典

        Returns:
            tuple: (label: str, confidence: float, reason: str)
                - label: 'SAFE', 'PHISHING', 'SUSPICIOUS'
                - confidence: 预测置信度 (0-1 之间的概率值)
                - reason: 判定理由
        """
        # --- 第一步：使用新的URL分析器进行深度URL分析 ---
        url_risk_level = 'UNKNOWN'
        url_risk_score = 0
        url_reasons = []
        
        if URL_ANALYZER_AVAILABLE and email_data.get('urls'):
            try:
                url_analysis = analyze_urls(email_data.get('urls', []))
                url_risk_level = url_analysis.get('max_risk_level', 'UNKNOWN')
                url_risk_score = url_analysis.get('max_risk_score', 0)
                
                # 收集所有风险原因
                for url_result in url_analysis.get('valid_urls', []):
                    if url_result.get('reasons'):
                        url_reasons.extend(url_result['reasons'])
                
                # 去重并限制数量
                url_reasons = list(dict.fromkeys(url_reasons))[:5]
            except Exception as e:
                print(f"URL分析失败: {e}")
        
        # --- 第二步：硬性熔断检查 (Kill Switch) ---
        kill_reason = self._check_kill_switch(features, url_risk_level, url_risk_score)
        if kill_reason:
            return "PHISHING", 0.99, f"Hard Rule Triggered: {kill_reason}"
            
        # --- 第三步：沙箱高危检查 (High Weight) ---
        sandbox_risk = self._check_sandbox_risk(features)
        if sandbox_risk == "HIGH_RISK_FILE_NO_RESULT":
            base_confidence = 0.65
        else:
            base_confidence = 0.0

        # --- 第四步：模型预测 ---
        if self.model:
            # 获取模型原始概率
            input_data = [[float(features.get(col, 0)) for col in FEATURE_COLUMNS]]
            prediction = self.model.predict(np.array(input_data))
            # 确保 prediction 是一个标量
            if isinstance(prediction, (list, np.ndarray)):
                if len(prediction) > 0:
                    model_prob = float(prediction[0])
                else:
                    model_prob = 0.0
            else:
                model_prob = float(prediction)
        else:
            # 降级处理，使用演示模式（传入 email_data 以获取更好的判断）
            _, model_prob = self._demo_predict(features, email_data)
            model_prob = float(model_prob)
            
        # --- 第五步：融合决策逻辑 ---
        # 融合URL风险分数
        url_weight = 0.4
        model_weight = 0.6
        
        # 如果URL分析发现高风险，显著提高置信度
        if url_risk_level == 'HIGH':
            final_confidence = max(base_confidence, model_prob, url_risk_score / 100)
        elif url_risk_level == 'MEDIUM':
            final_confidence = max(base_confidence, model_prob * model_weight + (url_risk_score / 100) * url_weight)
        else:
            final_confidence = max(base_confidence, model_prob)
        
        # 动态调整：如果溯源发现IP黑名单，增加置信度
        if features.get('first_external_ip_is_blacklisted'):
            final_confidence = min(1.0, final_confidence + 0.2)
            
        # --- 第六步：档位划分（修复：更合理的阈值）---
        # >=70%: 钓鱼邮件（高置信度）
        # >=40%: 可疑邮件（中等置信度，需要人工复核）
        # <40%: 安全邮件
        if final_confidence >= self.THRESHOLD_PHISHING:
            label = "PHISHING"
            # 构建详细的判定理由（中文）
            reasons = []
            
            # URL风险
            if url_reasons:
                reasons.append(f"URL风险: {'; '.join(url_reasons[:3])}")
            
            # 邮件头风险
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
            
            # 附件风险
            if features.get('has_executable_attachment'):
                reasons.append("包含可执行文件附件")
            if features.get('has_suspicious_attachment'):
                reasons.append("包含可疑附件")
            if features.get('has_double_extension'):
                reasons.append("附件使用双重扩展名")
            if features.get('sandbox_detected'):
                reasons.append("沙箱检测到恶意代码")
            
            # HTML风险
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
            if features.get('has_external_script'):
                reasons.append("包含外部脚本")
            
            # 文本风险
            if features.get('urgent_keywords_count', 0) > 3:
                reasons.append("包含过多紧急关键词")
            if features.get('financial_keywords_count', 0) > 2:
                reasons.append("包含金融相关关键词")
            if features.get('urgency_score', 0) > 0.7:
                reasons.append("邮件内容具有高度紧迫感")
            
            if reasons:
                reason = "；".join(reasons)
            else:
                reason = "检测到高置信度钓鱼邮件特征"
                
        elif final_confidence >= self.THRESHOLD_SUSPICIOUS:
            label = "SUSPICIOUS"
            # 构建详细的判定理由（中文）
            reasons = []
            
            # URL风险
            if url_reasons:
                reasons.append(f"URL风险: {'; '.join(url_reasons[:2])}")
            
            # 邮件头风险
            if features.get('is_suspicious_from_domain'):
                reasons.append("发件人域名可疑")
            if features.get('spf_fail') or features.get('dkim_fail') or features.get('dmarc_fail'):
                reasons.append("邮件认证存在问题")
            if features.get('from_display_name_mismatch'):
                reasons.append("发件人显示名称与邮箱可能不匹配")
            
            # 附件风险
            if features.get('attachment_count', 0) > 3:
                reasons.append("附件数量异常")
            if features.get('has_suspicious_attachment'):
                reasons.append("存在可疑附件")
            
            # HTML风险
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
            if features.get('has_external_script'):
                reasons.append("包含外部脚本")
            
            # 文本风险
            if features.get('urgent_keywords_count', 0) > 1:
                reasons.append("包含紧急关键词")
            if features.get('exclamation_count', 0) > 5:
                reasons.append("包含过多感叹号")
            
            if reasons:
                reason = "；".join(reasons) + "，建议人工复核"
            else:
                reason = "检测到可疑特征，建议人工复核"
                
        else:
            label = "SAFE"
            # 构建详细的安全理由（中文）
            safe_reasons = []
            
            # 积极因素
            if not features.get('is_suspicious_from_domain'):
                safe_reasons.append("发件人域名正常")
            if not features.get('spf_fail') and not features.get('dkim_fail') and not features.get('dmarc_fail'):
                safe_reasons.append("邮件认证通过")
            if features.get('url_count', 0) == 0:
                safe_reasons.append("未发现可疑链接")
            if features.get('attachment_count', 0) == 0:
                safe_reasons.append("无附件")
            
            if safe_reasons:
                reason = "；".join(safe_reasons)
            else:
                reason = "未检测到显著威胁"
            
        return label, final_confidence, reason

    def _check_kill_switch(self, features: Dict, url_risk_level: str = 'UNKNOWN', 
                           url_risk_score: int = 0) -> Optional[str]:
        """
        检查硬性熔断规则 - 修复版。

        Args:
            features: 特征向量字典
            url_risk_level: URL风险等级
            url_risk_score: URL风险分数

        Returns:
            Optional[str]: 熔断原因，如果未触发则返回 None
        """
        # 沙箱确认为恶意
        if features.get('sandbox_detected'):
            return "Sandbox Detected Malware"
        
        # SPF/DKIM/DMARC 全部失败且发件人域名与显示名称不匹配
        if features.get('spf_fail') and features.get('dkim_fail') and features.get('dmarc_fail') and features.get('from_display_name_mismatch'):
            return "Authentication Failed + Impersonation"
        
        # URL 存在于已知黑名单中（通过 VirusTotal 检测率判断）
        if features.get('max_vt_detection_ratio', 0) > 0.5:
            return "Known Malicious URL"
        
        # 新增：URL分析器发现高风险
        if url_risk_level == 'HIGH' and url_risk_score >= 80:
            return f"High Risk URL Detected (Score: {url_risk_score})"
        
        # 新增：域名包含钓鱼关键词
        if URL_ANALYZER_AVAILABLE:
            try:
                # 从features中获取URL列表并检查域名关键词
                urls = features.get('urls', [])
                for url in urls:
                    from url_analyzer import check_domain_keywords, get_registered_domain
                    keywords = check_domain_keywords(get_registered_domain(url))
                    if keywords:
                        return f"Suspicious Domain Keywords: {', '.join(keywords)}"
            except:
                pass
        
        return None

    def _check_sandbox_risk(self, features: Dict) -> Optional[str]:
        """
        检查沙箱高危情况。

        Args:
            features: 特征向量字典

        Returns:
            Optional[str]: 风险类型，如果无风险则返回 None
        """
        # 高风险文件类型但沙箱未分析出结果
        if features.get('has_executable_attachment') and not features.get('has_sandbox_analysis'):
            return "HIGH_RISK_FILE_NO_RESULT"
        return None

    def _load_whitelist(self):
        """加载白名单配置"""
        import json
        import os
        
        possible_paths = [
            'config/whitelist.json',
            '../config/whitelist.json',
            os.path.join(os.path.dirname(__file__), '..', 'config', 'whitelist.json'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'whitelist.json')
        ]
        
        for path in possible_paths:
            if os.path.exists(path):
                try:
                    with open(path, 'r', encoding='utf-8') as f:
                        config = json.load(f)
                        return config
                except Exception as e:
                    print(f"加载白名单配置失败: {e}")
                    continue
        
        # 返回默认配置
        return {
            "trusted_domains": [
                'qq.com', 'qlogo.cn', 'mail.qq.com', 'weixin.qq.com',
                'steampowered.com', 'google.com', 'microsoft.com'
            ],
            "trusted_senders": [],
            "verification_email_indicators": ["验证码", "verification", "verify", "code"]
        }
    
    @property
    def TRUSTED_DOMAINS(self):
        """动态获取可信域名列表"""
        config = self._load_whitelist()
        return set(config.get("trusted_domains", []))

    # 可疑顶级域名
    SUSPICIOUS_TLDS = {'.xyz', '.top', '.work', '.click', '.loan', '.tk'}

    def _demo_predict(self, feature_vector: Dict, email_data: Dict = None) -> Tuple[bool, float]:
        """
        演示模式下的预测 (基于规则) - 改进版
        
        改进点：
        1. 降低对非白名单域名的敏感度
        2. 考虑域名年龄，而非仅依赖白名单
        3. 识别验证码邮件等正常邮件类型
        4. 综合多维度特征，避免单一特征决定结果

        Args:
            feature_vector: 特征向量
            email_data: 原始邮件数据（用于辅助判断）

        Returns:
            tuple: (is_phish: bool, confidence: float)
        """
        # 确保 demo_weights 存在
        if not hasattr(self, 'demo_weights'):
            self.generate_demo_model()
        
        score = 0.0
        
        # 获取邮件主题和正文用于辅助判断
        subject = ""
        body = ""
        if email_data:
            subject = email_data.get('subject', '')
            body = email_data.get('body', '') + email_data.get('html_body', '')
        
        # 检查是否包含可信域名
        has_trusted_domain = False
        domain_age_values = []
        urls = feature_vector.get('urls', [])
        for url in urls:
            from urllib.parse import urlparse
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            domain = parsed.netloc.split(':')[0]
            domain_parts = domain.split('.')
            if len(domain_parts) >= 2:
                registered_domain = '.'.join(domain_parts[-2:])
                if registered_domain in self.TRUSTED_DOMAINS:
                    has_trusted_domain = True

        # 检查是否为验证码邮件（正常邮件类型）
        is_verification = self._is_verification_email(subject, body)
        
        # 计算风险评分 - 降低所有特征的权重以避免过度敏感
        weight_scale = 0.6  # 整体降低权重系数
        
        for feature, weight in self.demo_weights.items():
            value = float(feature_vector.get(feature, 0))
            adjusted_weight = weight * weight_scale

            # 特殊处理：域名年龄
            if feature == 'avg_domain_age_days':
                # 域名年龄评估改进：
                # - 年龄 > 1年(365天)：认为是正常域名
                # - 年龄 < 30天：新域名，风险较高
                # - 可信域名不考虑年龄风险
                if not has_trusted_domain:
                    if value < 30:  # 新域名
                        score += adjusted_weight * 0.6
                    elif value < 90:  # 较新域名
                        score += adjusted_weight * 0.3
                    elif value < 365:  # 半年内域名
                        score += adjusted_weight * 0.1
                    # 超过1年的域名不增加风险

            # 特殊处理：文本长度
            elif feature == 'text_length':
                score += adjusted_weight * max(0, (1000 - value)) / 1000

            # 其他特征
            else:
                score += adjusted_weight * value

        # 风险评估调整
        # 如果包含可信域名，大幅降低整体风险
        if has_trusted_domain:
            score -= 0.5  # 可信域名降低更多
        
        # 验证码邮件特殊处理
        if is_verification:
            # 检查是否有真正的高危特征
            high_risk_features = [
                feature_vector.get('has_executable_attachment', 0),
                feature_vector.get('sandbox_detected', 0),
                feature_vector.get('has_hidden_links', 0),
                feature_vector.get('ip_address_count', 0),
                feature_vector.get('has_suspicious_attachment', 0),
            ]
            high_risk_count = sum(1 for f in high_risk_features if f > 0)
            
            if high_risk_count == 0:
                # 没有高危特征的验证码邮件大幅降低风险
                score -= 0.4
            elif high_risk_count <= 1:
                # 只有1个高危特征，适当降低
                score -= 0.2

        # 归一化到 0-1 范围，但使用更平滑的映射
        import math
        confidence = 1 / (1 + math.exp(-score))
        
        # 调整阈值，使正常邮件更容易通过
        is_phish = confidence > self.THRESHOLD_PHISHING

        return is_phish, confidence
    
    def _is_verification_email(self, subject: str, body: str) -> bool:
        """
        判断是否为验证码邮件。
        
        Args:
            subject: 邮件主题
            body: 邮件正文
            
        Returns:
            bool: 是否为验证码邮件
        """
        config = self._load_whitelist()
        indicators = config.get("verification_email_indicators", 
                                ["验证码", "verification", "verify", "code", 
                                 "confirm", "激活码", "校验码", "动态密码"])
        
        text = (subject + " " + body).lower()
        
        # 检查是否包含验证码相关词汇
        for indicator in indicators:
            if indicator.lower() in text:
                return True
        
        return False

    def set_thresholds(self, phishing_threshold: float, suspicious_threshold: float = None):
        """
        设置三分类阈值。

        Args:
            phishing_threshold: 钓鱼邮件阈值（默认0.70）
            suspicious_threshold: 可疑邮件阈值（默认0.40）
        """
        self.THRESHOLD_PHISHING = max(0, min(1, phishing_threshold))
        if suspicious_threshold is not None:
            self.THRESHOLD_SUSPICIOUS = max(0, min(self.THRESHOLD_PHISHING, suspicious_threshold))

    def get_thresholds(self) -> Dict[str, float]:
        """获取当前阈值"""
        return {
            'phishing': self.THRESHOLD_PHISHING,
            'suspicious': self.THRESHOLD_SUSPICIOUS
        }


def analyze_phishing_risk(email_data: Dict, feature_vector: Dict, model: Optional[PhishingDetector] = None,
                          vt_api_key: Optional[str] = None) -> Tuple[str, float, str]:
    """
    便捷函数：对一封邮件进行二分类钓鱼风险分析。

    Args:
        email_data: 解析后的邮件数据
        feature_vector: 特征字典
        model: 可选的探测器实例，如果未提供则创建新实例
        vt_api_key: VirusTotal API 密钥

    Returns:
        tuple: (label: str, confidence: float, reason: str)
    """
    if model is None:
        model = PhishingDetector(vt_api_key=vt_api_key)
        # 检查是否有 demo 模型可用
        demo_path = 'models/phish_detector.pkl'
        if os.path.exists(demo_path):
            try:
                with open(demo_path, 'rb') as f:
                    model.model = pickle.load(f)
                print("加载了演示模式模型")
            except:
                model.generate_demo_model()
        else:
            model.generate_demo_model()

    return model.analyze(email_data, feature_vector)


def batch_analyze(email_data_list: List[Dict], feature_vectors: List[Dict], 
                  model: Optional[PhishingDetector] = None, vt_api_key: Optional[str] = None) -> List[Tuple[str, float, str]]:
    """
    批量分析多封邮件。

    Args:
        email_data_list: 解析后的邮件数据列表
        feature_vectors: 特征字典列表
        model: 探测器实例
        vt_api_key: VirusTotal API 密钥

    Returns:
        List[Tuple[str, float, str]]: [(label, confidence, reason), ...]
    """
    results = []
    for email_data, fv in zip(email_data_list, feature_vectors):
        result = analyze_phishing_risk(email_data, fv, model, vt_api_key)
        results.append(result)
    return results


if __name__ == "__main__":
    # 测试示例
    import sys
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from features import build_feature_vector
    from parse_email import parse_email

    test_email = """From: "Bank Security" <security@suspicious-bank.com>
To: user@example.com
Subject: 【紧急】您的账户存在异常登录！

尊敬的客户，

我们检测到您的账户有异常活动。请立即点击以下链接验证您的身份：
http://secure-login-verify.com/account/check

如果不立即处理，您的账户将在 24 小时内被冻结！

此致
银行安全团队
"""

    parsed = parse_email(test_email)
    features = build_feature_vector(parsed)

    detector = PhishingDetector()
    label, confidence, reason = detector.analyze(parsed, features)

    print("=" * 50)
    print("钓鱼邮件检测结果")
    print("=" * 50)
    print(f"判定结果：{label}")
    print(f"置信度：{confidence:.4f}")
    print(f"判定理由：{reason}")
    thresholds = detector.get_thresholds()
    print(f"阈值设置：")
    print(f"  - 钓鱼邮件: >= {thresholds['phishing']:.0%}")
    print(f"  - 可疑邮件: {thresholds['suspicious']:.0%} - {thresholds['phishing']:.0%}")
    print(f"  - 安全邮件: < {thresholds['suspicious']:.0%}")
    print("=" * 50)
