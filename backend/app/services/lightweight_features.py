"""
轻量模型特征提取服务
支持两种特征维度：
- 35维：语义特征（用于RF/XGB分类器）
- 26维：统计特征（用于异常检测器）
"""
from __future__ import annotations

import re
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse, parse_qs

# ==================== 关键词列表 ====================

SUSPICIOUS_KEYWORDS = [
    "urgent", "verify", "suspended", "locked", "confirm", "update", "click here",
    "act now", "limited time", "expire", "account", "password", "security",
    "winner", "prize", "congratulations", "claim", "refund", "tax",
    "紧急", "验证", "暂停", "锁定", "确认", "更新", "点击这里",
    "立即行动", "限时", "过期", "账户", "密码", "安全",
    "中奖", "奖品", "恭喜", "领取", "退款", "税务",
]

URGENCY_WORDS = [
    "urgent", "immediately", "now", "asap", "hurry", "quick", "fast",
    "紧急", "立即", "马上", "尽快", "赶快",
]

THREATENING_LANGUAGE = [
    "suspend", "close", "terminate", "lock", "block", "freeze",
    "冻结", "锁定", "关闭", "暂停", "取消"
]

SEDUCTIVE_LANGUAGE = [
    "free", "bonus", "reward", "prize", "win", "congratulations",
    "免费", "奖励", "奖品", "恭喜", "特价", "优惠"
]

PERSONAL_INFO_KEYWORDS = [
    "social security", "ssn", "credit card", "bank account", "password",
    "pin", "cvv", "date of birth", "driver license",
    "社保", "信用卡", "银行账户", "密码", "身份证",
]

FINANCIAL_KEYWORDS = [
    "wire transfer", "bitcoin", "cryptocurrency", "gift card", "payment",
    "invoice", "refund", "tax", "irs",
    "转账", "比特币", "加密货币", "礼品卡", "付款", "发票", "退款", "税务",
]

BRAND_KEYWORDS = [
    "paypal", "apple", "microsoft", "office 365", "bank of america", "hsbc",
    "中国银行", "工商银行", "建设银行", "招商银行", "支付宝", "微信支付",
]

HIGH_RISK_TLDS = [".top", ".xyz", ".club", ".work", ".click", ".link"]

CHINESE_PHISHING_KEYWORDS = [
    "财务", "发票", "报销", "转账", "汇款", "账号异常", "密码重置",
    "紧急", "立即", "点击", "验证", "升级", "通知", "重要",
    "中奖", "优惠", "免费", "贷款", "信用卡"
]

SUSPICIOUS_ATTACHMENTS = [
    r"\.exe", r"\.scr", r"\.bat", r"\.cmd", r"\.vbs", r"\.js",
]


# ==================== 辅助函数 ====================

def _count_keywords(text: str, keywords: List[str]) -> int:
    """统计关键词出现次数"""
    lower_text = text.lower()
    return sum(1 for kw in keywords if kw.lower() in lower_text)


def _extract_urls(text: str) -> List[str]:
    """提取URL"""
    url_pattern = r'https?://[^\s<>"{}|\\^`\[\]]+'
    return re.findall(url_pattern, text)


def _extract_body(parsed_email: Dict) -> str:
    """提取邮件正文"""
    body = parsed_email.get('body', '')
    html_body = parsed_email.get('html_body', '')
    
    if html_body:
        clean_html = re.sub(r'<style[^>]*>.*?</style>', '', html_body, flags=re.DOTALL | re.IGNORECASE)
        clean_html = re.sub(r'<script[^>]*>.*?</script>', '', clean_html, flags=re.DOTALL | re.IGNORECASE)
        clean_html = re.sub(r'<[^>]+>', ' ', clean_html)
        clean_html = re.sub(r'\s+', ' ', clean_html).strip()
        return body + ' ' + clean_html
    return body


def _extract_sender_domain(parsed_email: Dict) -> Optional[str]:
    """提取发件人域名"""
    from_email = parsed_email.get('from_email', '') or parsed_email.get('from', '')
    if '@' in from_email:
        return from_email.split('@')[-1].lower()
    return None


# ==================== 35维特征提取（简化PhishMMF） ====================

def extract_phishmmf_features_35d(parsed_email: Dict) -> List[float]:
    """
    提取35维简化PhishMMF特征
    """
    subject = parsed_email.get('subject', '')
    from_addr = parsed_email.get('from_email', '') or parsed_email.get('from', '')
    body = _extract_body(parsed_email)
    urls = parsed_email.get('urls', []) or _extract_urls(body)
    
    features = []
    
    # 1. 主题特征 (6维)
    features.extend(_extract_subject_features(subject))
    
    # 2. 发件人特征 (2维)
    features.extend(_extract_sender_features_35d(from_addr))
    
    # 3. 正文特征 (16维)
    features.extend(_extract_content_features_35d(body, urls))
    
    # 4. URL特征 (11维)
    features.extend(_extract_url_features_35d(urls))
    
    return features


def _extract_subject_features(subject: str) -> List[float]:
    """主题特征 (6维)"""
    subject_lower = subject.lower()
    
    urgency_level = 0
    if any(word in subject_lower for word in ["urgent", "immediately", "asap", "紧急", "立即"]):
        urgency_level = 2
    elif any(word in subject_lower for word in ["important", "attention", "notice", "重要", "注意"]):
        urgency_level = 1
    
    threatening = any(word in subject_lower for word in THREATENING_LANGUAGE)
    seductive = any(word in subject_lower for word in SEDUCTIVE_LANGUAGE)
    emergency = any(word in subject_lower for word in ["verify", "confirm", "update", "验证", "确认", "更新"])
    
    positive_words = ["thank", "welcome", "success", "谢谢", "欢迎", "成功"]
    negative_words = ["suspend", "lock", "problem", "暂停", "锁定", "问题"]
    
    pos_count = sum(1 for word in positive_words if word in subject_lower)
    neg_count = sum(1 for word in negative_words if word in subject_lower)
    
    if pos_count + neg_count > 0:
        sentiment_score = (pos_count - neg_count) / (pos_count + neg_count)
    else:
        sentiment_score = 0.0
    
    if sentiment_score < -0.3:
        sentiment_label = 0
    elif sentiment_score > 0.3:
        sentiment_label = 2
    else:
        sentiment_label = 1
    
    return [float(urgency_level), float(threatening), float(seductive), 
            float(emergency), float(sentiment_score), float(sentiment_label)]


def _extract_sender_features_35d(from_addr: str) -> List[float]:
    """发件人特征 (2维)"""
    from_lower = from_addr.lower()
    
    impersonation = 0
    if any(word in from_lower for word in ["bank", "paypal", "visa", "银行"]):
        impersonation = 1
    elif any(word in from_lower for word in ["gov", "irs", "tax", "政府"]):
        impersonation = 2
    elif any(word in from_lower for word in ["amazon", "ebay", "淘宝", "京东"]):
        impersonation = 3
    elif any(word in from_lower for word in ["facebook", "twitter", "微信", "微博"]):
        impersonation = 4
    
    anomaly = 0
    free_domains = ["gmail.com", "yahoo.com", "hotmail.com", "163.com", "qq.com"]
    if impersonation > 0 and any(domain in from_lower for domain in free_domains):
        anomaly = 1
    if any(pattern in from_lower for pattern in ["paypa1", "amaz0n", "g00gle", "micr0soft"]):
        anomaly = 2
    
    return [float(impersonation), float(anomaly)]


def _extract_content_features_35d(body: str, urls: List[str]) -> List[float]:
    """正文特征 (16维)"""
    body_lower = body.lower()
    
    words = re.findall(r'\b\w+\b', body)
    word_count = len(words)
    url_count = len(urls)
    
    spelling_errors = len(re.findall(r'(\w)\1{2,}', body))
    grammar_errors = len(re.findall(r'[!?]{2,}', body))
    
    suspicious_count = _count_keywords(body, SUSPICIOUS_KEYWORDS)
    urgency_count = _count_keywords(body, URGENCY_WORDS)
    
    personal_info_request = any(keyword in body_lower for keyword in PERSONAL_INFO_KEYWORDS)
    financial_request = any(keyword in body_lower for keyword in FINANCIAL_KEYWORDS)
    
    if words:
        avg_word_length = sum(len(w) for w in words) / len(words)
        text_complexity = min(avg_word_length * 10, 100)
    else:
        text_complexity = 0
    
    has_greeting = any(word in body_lower for word in ["dear", "hello", "hi", "您好", "你好"])
    has_signature = any(word in body_lower for word in ["regards", "sincerely", "best", "此致", "敬礼"])
    similarity = (int(has_greeting) + int(has_signature)) / 2.0
    
    has_chinese = bool(re.search(r'[\u4e00-\u9fff]', body))
    has_english = bool(re.search(r'[a-zA-Z]', body))
    if has_chinese and has_english:
        language = 2
    elif has_chinese:
        language = 1
    else:
        language = 0
    
    obfuscated = bool(re.search(r'[0O]{2,}|[1lI]{3,}', body))
    otp_request = any(word in body_lower for word in ["otp", "verification code", "验证码", "动态密码"])
    
    phishing_cta = any(phrase in body_lower for phrase in [
        "click here", "verify now", "update now", "confirm identity",
        "点击这里", "立即验证", "立即更新", "确认身份"
    ])
    
    positive_words = ["thank", "welcome", "success", "谢谢", "欢迎", "成功"]
    negative_words = ["problem", "issue", "suspend", "问题", "暂停"]
    
    pos_count = sum(1 for word in positive_words if word in body_lower)
    neg_count = sum(1 for word in negative_words if word in body_lower)
    
    if neg_count > pos_count:
        text_sentiment = 0
    elif pos_count > neg_count:
        text_sentiment = 2
    else:
        text_sentiment = 1
    
    if pos_count + neg_count > 0:
        text_sentiment_score = (pos_count - neg_count) / (pos_count + neg_count)
    else:
        text_sentiment_score = 0.0
    
    return [float(word_count), float(url_count), float(spelling_errors), float(grammar_errors),
            float(suspicious_count), float(urgency_count), float(personal_info_request), 
            float(financial_request), float(text_complexity), float(similarity), float(language),
            float(obfuscated), float(otp_request), float(phishing_cta), 
            float(text_sentiment), float(text_sentiment_score)]


def _extract_url_features_35d(urls: List[str]) -> List[float]:
    """URL特征 (11维)"""
    if not urls:
        return [0.0] * 11
    
    url = urls[0]
    
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query
    except:
        return [0.0] * 11
    
    domain_length = len(domain)
    dot_count = domain.count('.')
    
    ip_pattern = r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}'
    contains_ip = bool(re.match(ip_pattern, domain.split(':')[0]))
    
    contains_at = '@' in url
    contains_hyphen = '-' in domain
    path_length = len(path)
    
    parts = domain.split(':')[0].split('.')
    subdomains_count = max(0, len(parts) - 2)
    
    tld_map = {"com": 0, "org": 1, "net": 2, "edu": 3, "gov": 4}
    if parts:
        tld = tld_map.get(parts[-1].lower(), 5)
    else:
        tld = 5
    
    query_params = query.split('&') if query else []
    query_params_count = len(query_params)
    
    suspicious_param_names = ["redirect", "url", "link", "goto", "next"]
    has_suspicious = any(param in query.lower() for param in suspicious_param_names)
    suspicious_params_count = sum(1 for param in suspicious_param_names if param in query.lower())
    
    return [float(domain_length), float(dot_count), float(contains_ip), float(contains_at),
            float(contains_hyphen), float(path_length), float(subdomains_count), float(tld),
            float(query_params_count), float(has_suspicious), float(suspicious_params_count)]


# ==================== 26维特征提取（IsolationForest） ====================

def extract_iforest_features_26d(parsed_email: Dict) -> List[float]:
    """
    提取26维IsolationForest特征
    基于analysis.py中的build_feature_vector函数
    """
    subject = parsed_email.get('subject', '')
    from_email = parsed_email.get('from_email', '') or parsed_email.get('from', '')
    body = _extract_body(parsed_email)
    html_body = parsed_email.get('html_body', '')
    full_content = f"From: {from_email}\nSubject: {subject}\n\n{body}"
    
    urls = parsed_email.get('urls', []) or _extract_urls(full_content)
    headers = parsed_email.get('headers', {})
    
    # 提取钓鱼模式特征
    phishing_patterns = _extract_phishing_patterns(full_content)
    
    # 构建26维特征向量
    vector = [
        # 基础统计特征 (6个)
        float(len(full_content)),  # num_chars
        float(len(full_content.splitlines())),  # num_lines
        float(len(urls)),  # num_urls
        float(len(subject)),  # subject_len
        float(_count_keywords(full_content, SUSPICIOUS_KEYWORDS)),  # keyword_hit_count
        float(_count_keywords(full_content, BRAND_KEYWORDS)),  # brand_hit_count
        
        # URL和域名特征 (4个)
        float(_count_high_risk_urls(urls)),  # high_risk_url_count
        float(phishing_patterns.get("anchor_mismatch_count", 0)),  # anchor_mismatch_count
        float(phishing_patterns.get("unique_domains", 0)),  # unique_domains
        1.0 if phishing_patterns.get("has_ip_url") else 0.0,  # has_ip_url
        
        # HTML和脚本特征 (3个)
        1.0 if html_body else 0.0,  # has_html
        1.0 if re.search(r'<(script|form|input)', full_content, re.IGNORECASE) else 0.0,  # has_script_or_form
        1.0 if re.search(r'attachment;|filename=|\.zip|\.rar|\.exe', full_content, re.IGNORECASE) else 0.0,  # has_attachment_hint
        
        # 钓鱼模式特征 (8个)
        float(phishing_patterns.get("fake_sender_score", 0)),  # fake_sender_score
        1.0 if phishing_patterns.get("has_base64") else 0.0,  # has_base64
        float(phishing_patterns.get("base64_blocks", 0)),  # base64_blocks
        float(phishing_patterns.get("chinese_keyword_count", 0)),  # chinese_keyword_count
        float(phishing_patterns.get("attachment_risk_score", 0)),  # attachment_risk_score
        float(phishing_patterns.get("received_count", 0)),  # received_count
        float(phishing_patterns.get("boundary_count", 0)),  # boundary_count
        1.0 if phishing_patterns.get("has_x_mailer") else 0.0,  # has_x_mailer
        
        # 邮件认证特征 (5个)
        1.0 if headers.get('spf_result') == 'fail' else 0.0,  # spf_fail
        1.0 if headers.get('dkim_result') == 'fail' else 0.0,  # dkim_fail
        1.0 if headers.get('dmarc_result') == 'fail' else 0.0,  # dmarc_fail
        1.0 if phishing_patterns.get("dkim_present") else 0.0,  # dkim_present
        1.0 if phishing_patterns.get("spf_present") else 0.0,  # spf_present
    ]
    
    return vector


def _extract_phishing_patterns(content: str) -> Dict[str, Any]:
    """提取钓鱼模式特征"""
    lower_content = content.lower()
    
    # 检测伪造发件人
    suspicious_sender_patterns = [
        r"from:.*@.*\.(top|xyz|club|work|click|link)",
        r"reply-to:.*@(gmail|qq|163|hotmail|outlook)\.com",
    ]
    fake_sender_score = sum(1 for p in suspicious_sender_patterns if re.search(p, lower_content, re.IGNORECASE))
    
    # 检测base64
    has_base64 = bool(re.search(r"content-transfer-encoding:\s*base64", lower_content))
    base64_blocks = len(re.findall(r"^[A-Za-z0-9+/]{40,}={0,2}$", content, re.MULTILINE))
    
    # 中文关键词
    chinese_keyword_count = sum(1 for kw in CHINESE_PHISHING_KEYWORDS if kw in content)
    
    # 附件风险
    attachment_risk_score = sum(1 for p in SUSPICIOUS_ATTACHMENTS if re.search(p, lower_content))
    
    # 邮件头部
    received_count = len(re.findall(r"^received:", lower_content, re.MULTILINE))
    has_x_mailer = bool(re.search(r"x-mailer:", lower_content))
    
    # URL特征
    urls = _extract_urls(content)
    url_domains = [urlparse(url).netloc.lower() for url in urls if urlparse(url).netloc]
    unique_domains = len(set(url_domains))
    has_ip_url = any(re.match(r"\d+\.\d+\.\d+\.\d+", d) for d in url_domains)
    
    # 邮件结构
    boundary_count = len(re.findall(r"boundary=", lower_content))
    
    # 认证
    dkim_present = bool(re.search(r"dkim-signature:", lower_content))
    spf_present = bool(re.search(r"received-spf:", lower_content))
    
    # 链接不匹配
    anchor_pattern = re.compile(r'<a[^>]*href=["\']([^"\']+)["\'][^>]*>(.*?)</a>', re.IGNORECASE | re.DOTALL)
    anchor_mismatch_count = 0
    for m in anchor_pattern.finditer(content):
        href = m.group(1)
        text = re.sub(r'<.*?>', '', m.group(2)).strip()
        href_domain = _base_domain(urlparse(href).netloc.lower()) if urlparse(href).netloc else ""
        text_domain_match = re.search(r"([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})", text)
        text_domain = _base_domain(text_domain_match.group(1).lower()) if text_domain_match else ""
        if href_domain and text_domain and href_domain != text_domain:
            anchor_mismatch_count += 1
    
    return {
        "fake_sender_score": fake_sender_score,
        "has_base64": has_base64,
        "base64_blocks": base64_blocks,
        "chinese_keyword_count": chinese_keyword_count,
        "attachment_risk_score": attachment_risk_score,
        "received_count": received_count,
        "has_x_mailer": has_x_mailer,
        "unique_domains": unique_domains,
        "has_ip_url": has_ip_url,
        "boundary_count": boundary_count,
        "dkim_present": dkim_present,
        "spf_present": spf_present,
        "anchor_mismatch_count": anchor_mismatch_count,
    }


def _base_domain(domain: str) -> str:
    """提取基础域名"""
    parts = domain.split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return domain


def _count_high_risk_urls(urls: List[str]) -> int:
    """统计高风险URL数量"""
    count = 0
    for url in urls:
        for tld in HIGH_RISK_TLDS:
            if tld in url.lower():
                count += 1
                break
    return count


# ==================== 统一接口 ====================

def extract_features(parsed_email: Dict, feature_type: str = '35d') -> List[float]:
    """
    统一特征提取接口
    
    Args:
        parsed_email: 解析后的邮件数据
        feature_type: 特征类型 ('35d', '26d')
    
    Returns:
        特征向量
    """
    if feature_type == '35d':
        return extract_phishmmf_features_35d(parsed_email)
    elif feature_type == '26d':
        return extract_iforest_features_26d(parsed_email)
    else:
        raise ValueError(f"Unsupported feature type: {feature_type}")
