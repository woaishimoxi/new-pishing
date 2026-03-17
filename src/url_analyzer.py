"""
URL安全分析模块 - 修复版
修复以下问题：
1. qq.com等可信域名被误报
2. 域名关键词（如phish）检测缺失
3. 非HTTP URL（cid:, mailto:）被错误分析
4. 域名年龄3650天默认值问题
"""
import re
import time
import whois
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional, Set
from datetime import datetime


# 可信域名白名单
# 注意：deepphish.cn已移除，因为它包含"phish"可疑关键词
TRUSTED_DOMAINS = {
    'qq.com', 'qlogo.cn', 'mail.qq.com', 'weixin.qq.com',
    'steampowered.com', 'steamcommunity.com', 'steamstatic.com',
    'valvesoftware.com', 'google.com', 'microsoft.com',
    'facebook.com', 'baidu.com', 'taobao.com', 'jd.com',
    'aliyun.com', 'alipay.com', 'wechat.com', '163.com', '126.com',
    'sina.com', 'sohu.com'
}

# 可疑域名关键词（品牌滥用、钓鱼相关）
SUSPICIOUS_DOMAIN_KEYWORDS = [
    'phish', 'phishing', 'fake', 'scam', 'fraud', 'hack', 'steal',
    'login', 'verify', 'secure', 'account', 'update', 'confirm',
    'paypa1', 'g00gle', 'micr0soft', 'amaz0n', 'faceb00k',
    'security', 'service', 'support', 'team', 'admin'
]

# 品牌名（用于检测品牌滥用）
BRAND_NAMES = [
    'paypal', 'google', 'microsoft', 'amazon', 'facebook', 'apple',
    'linkedin', 'twitter', 'instagram', 'netflix', 'dropbox',
    'alipay', 'wechat', 'taobao', 'jd', 'icbc', 'ccb', 'bank'
]

# 域名年龄缓存
DOMAIN_AGE_CACHE = {}


def is_valid_http_url(url: str) -> bool:
    """
    检查是否是有效的HTTP/HTTPS URL
    过滤掉 cid:, mailto:, javascript: 等非HTTP协议
    """
    if not url or not isinstance(url, str):
        return False
    
    try:
        # 处理没有scheme的URL
        if not url.startswith(('http://', 'https://')):
            # 如果看起来像域名，添加http://前缀
            if '.' in url and not url.startswith(('cid:', 'mailto:', 'javascript:', 'data:')):
                url = 'http://' + url
            else:
                return False
        
        parsed = urlparse(url)
        
        # 必须是http或https协议
        if parsed.scheme not in ['http', 'https']:
            return False
        
        # 必须有域名或IP
        if not parsed.netloc:
            return False
        
        return True
    except Exception:
        return False


def filter_urls(urls: List[str]) -> Tuple[List[str], List[Dict]]:
    """
    过滤URL列表，分离有效HTTP URL和非HTTP URL
    
    Returns:
        (valid_urls, skipped_urls)
        valid_urls: 有效的HTTP/HTTPS URL列表
        skipped_urls: 被跳过的URL信息列表，包含跳过原因
    """
    valid_urls = []
    skipped_urls = []
    
    for url in urls:
        if is_valid_http_url(url):
            valid_urls.append(url)
        else:
            # 记录被跳过的URL及原因
            skipped_info = {
                'url': url[:100] if len(url) > 100 else url,  # 截断过长URL
                'reason': '非HTTP/HTTPS协议或无效URL'
            }
            
            # 尝试识别协议类型
            if ':' in url:
                scheme = url.split(':')[0].lower()
                if scheme in ['cid', 'mailto', 'javascript', 'data', 'file']:
                    skipped_info['scheme'] = scheme
                    skipped_info['reason'] = f'{scheme}协议，跳过分析'
            
            skipped_urls.append(skipped_info)
    
    return valid_urls, skipped_urls


def get_registered_domain(domain: str) -> str:
    """
    提取注册域名（最后两部分，如 example.com）
    """
    parts = domain.lower().split('.')
    if len(parts) >= 2:
        return '.'.join(parts[-2:])
    return domain.lower()


def is_trusted_domain(domain: str) -> bool:
    """
    检查域名是否在白名单中
    """
    registered = get_registered_domain(domain)
    return registered in TRUSTED_DOMAINS


def check_domain_keywords(domain: str) -> List[str]:
    """
    检查域名是否包含可疑关键词
    
    Returns:
        发现的关键词列表，如果没有则返回空列表
    """
    domain_lower = domain.lower()
    found_keywords = []
    
    for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
        if keyword in domain_lower:
            found_keywords.append(keyword)
    
    return found_keywords


def check_brand_abuse(domain: str) -> List[str]:
    """
    检查域名是否滥用品牌名（如 paypa1.com 冒充 paypal.com）
    
    Returns:
        被滥用的品牌列表
    """
    domain_lower = domain.lower()
    abused_brands = []
    
    for brand in BRAND_NAMES:
        # 检查是否包含品牌名变体（如 paypa1, g00gle）
        brand_variations = [
            brand.replace('o', '0').replace('l', '1').replace('e', '3'),
            brand.replace('a', '@').replace('i', '1'),
            brand + '-',
            brand + '_',
        ]
        
        for variant in brand_variations:
            if variant in domain_lower and brand not in domain_lower:
                abused_brands.append(f'{brand}(变体:{variant})')
                break
    
    return abused_brands


def get_domain_age(domain: str) -> Optional[float]:
    """
    查询域名注册年龄（天数）- 修复版
    
    Returns:
        float: 域名注册天数，查询失败返回None（不再是3650默认值）
    """
    # 检查缓存
    if domain in DOMAIN_AGE_CACHE:
        cached_value = DOMAIN_AGE_CACHE[domain]
        # 如果缓存的是None，也返回None
        return cached_value
    
    # 检查是否是IP地址
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain):
        DOMAIN_AGE_CACHE[domain] = None
        return None
    
    try:
        w = whois.whois(domain)
        
        if not w or not hasattr(w, 'creation_date') or not w.creation_date:
            DOMAIN_AGE_CACHE[domain] = None
            return None
        
        creation_date = w.creation_date
        
        # 处理可能的list类型
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        
        # 计算年龄
        if isinstance(creation_date, datetime):
            age_days = (datetime.now() - creation_date).days
            # 验证合理性
            if 0 <= age_days <= 10950:  # 0到30年之间
                DOMAIN_AGE_CACHE[domain] = float(age_days)
                return float(age_days)
        
        # 解析失败
        DOMAIN_AGE_CACHE[domain] = None
        return None
        
    except Exception as e:
        # 查询失败，缓存None
        DOMAIN_AGE_CACHE[domain] = None
        return None


def analyze_single_url(url: str, check_whitelist: bool = True) -> Dict:
    """
    分析单个URL的安全风险 - 修复版
    
    Args:
        url: URL字符串
        check_whitelist: 是否检查白名单
        
    Returns:
        包含风险分析结果的字典
    """
    result = {
        'url': url,
        'is_valid': False,
        'risk_level': 'UNKNOWN',
        'risk_score': 0,
        'is_whitelisted': False,
        'domain': None,
        'registered_domain': None,
        'domain_age_days': None,
        'has_https': False,
        'is_ip_address': False,
        'suspicious_keywords': [],
        'brand_abuse': [],
        'reasons': []
    }
    
    # 1. 验证URL有效性
    if not is_valid_http_url(url):
        result['reasons'].append('无效的HTTP/HTTPS URL')
        result['risk_level'] = 'SKIP'
        return result
    
    result['is_valid'] = True
    
    # 2. 解析URL
    try:
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.split(':')[0]  # 移除端口号
        result['domain'] = domain
        result['registered_domain'] = get_registered_domain(domain)
        result['has_https'] = parsed.scheme == 'https'
    except Exception as e:
        result['reasons'].append(f'URL解析失败: {str(e)}')
        result['risk_level'] = 'ERROR'
        return result
    
    # 3. 白名单检查
    if check_whitelist and is_trusted_domain(domain):
        result['is_whitelisted'] = True
        result['risk_level'] = 'SAFE'
        result['risk_score'] = 0
        result['reasons'].append(f'可信域名: {result["registered_domain"]}')
        
        # 可信域名仍查询年龄用于信息展示
        age = get_domain_age(result['registered_domain'])
        if age is not None:
            result['domain_age_days'] = age
        
        return result
    
    # 4. 风险评分计算
    risk_score = 0
    reasons = []
    
    # 检查是否为IP地址
    ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
    if re.match(ip_pattern, domain):
        result['is_ip_address'] = True
        risk_score += 40
        reasons.append('使用IP地址而非域名')
    
    # 查询域名年龄
    domain_age = get_domain_age(result['registered_domain'])
    if domain_age is not None:
        result['domain_age_days'] = domain_age
        # 新域名风险更高
        if domain_age < 30:
            risk_score += 35
            reasons.append(f'新域名（{int(domain_age)}天）')
        elif domain_age < 90:
            risk_score += 20
            reasons.append(f'较新域名（{int(domain_age)}天）')
        elif domain_age < 365:
            risk_score += 10
            reasons.append(f'一年内新域名（{int(domain_age)}天）')
    else:
        # 无法查询域名年龄，适度增加风险
        risk_score += 5
        reasons.append('无法查询域名年龄')
    
    # 检查可疑关键词
    suspicious_keywords = check_domain_keywords(domain)
    if suspicious_keywords:
        result['suspicious_keywords'] = suspicious_keywords
        risk_score += 50  # 高权重
        reasons.append(f'域名包含可疑关键词: {", ".join(suspicious_keywords)}')
    
    # 检查品牌滥用
    brand_abuse = check_brand_abuse(domain)
    if brand_abuse:
        result['brand_abuse'] = brand_abuse
        risk_score += 45
        reasons.append(f'疑似品牌滥用: {", ".join(brand_abuse)}')
    
    # HTTPS检查（非HTTPS适度增加风险）
    if not result['has_https']:
        risk_score += 10
        reasons.append('未使用HTTPS加密')
    
    # URL长度检查
    if len(url) > 200:
        risk_score += 5
        reasons.append('URL过长')
    
    # 5. 确定风险等级
    result['risk_score'] = min(risk_score, 100)  # 最高100分
    
    if risk_score >= 60:
        result['risk_level'] = 'HIGH'
    elif risk_score >= 30:
        result['risk_level'] = 'MEDIUM'
    elif risk_score > 0:
        result['risk_level'] = 'LOW'
    else:
        result['risk_level'] = 'SAFE'
    
    result['reasons'] = reasons
    
    return result


def analyze_urls(urls: List[str], check_whitelist: bool = True) -> Dict:
    """
    批量分析URL列表 - 修复版
    
    Returns:
        {
            'valid_urls': 有效的HTTP URL分析结果列表,
            'skipped_urls': 被跳过的URL信息列表,
            'max_risk_level': 最高风险等级,
            'max_risk_score': 最高风险分数,
            'summary': 分析摘要
        }
    """
    # 1. 过滤URL
    valid_urls, skipped_urls = filter_urls(urls)
    
    # 2. 分析有效URL
    analysis_results = []
    high_risk_count = 0
    medium_risk_count = 0
    low_risk_count = 0
    safe_count = 0
    
    for url in valid_urls:
        result = analyze_single_url(url, check_whitelist)
        analysis_results.append(result)
        
        # 统计风险等级
        if result['risk_level'] == 'HIGH':
            high_risk_count += 1
        elif result['risk_level'] == 'MEDIUM':
            medium_risk_count += 1
        elif result['risk_level'] == 'LOW':
            low_risk_count += 1
        elif result['risk_level'] == 'SAFE':
            safe_count += 1
    
    # 3. 计算最高风险
    max_risk_score = max([r['risk_score'] for r in analysis_results], default=0)
    
    risk_levels_priority = ['HIGH', 'MEDIUM', 'LOW', 'SAFE', 'UNKNOWN', 'SKIP']
    max_risk_level = 'UNKNOWN'
    for level in risk_levels_priority:
        if any(r['risk_level'] == level for r in analysis_results):
            max_risk_level = level
            break
    
    # 4. 生成摘要
    summary = {
        'total_urls': len(urls),
        'valid_urls': len(valid_urls),
        'skipped_urls': len(skipped_urls),
        'high_risk': high_risk_count,
        'medium_risk': medium_risk_count,
        'low_risk': low_risk_count,
        'safe': safe_count,
        'whitelisted': sum(1 for r in analysis_results if r['is_whitelisted'])
    }
    
    return {
        'valid_urls': analysis_results,
        'skipped_urls': skipped_urls,
        'max_risk_level': max_risk_level,
        'max_risk_score': max_risk_score,
        'summary': summary
    }


# 便捷函数
def quick_check_url(url: str) -> Tuple[str, int, List[str]]:
    """
    快速检查URL
    
    Returns:
        (risk_level, risk_score, reasons)
    """
    result = analyze_single_url(url)
    return result['risk_level'], result['risk_score'], result['reasons']


if __name__ == "__main__":
    # 测试示例
    test_urls = [
        'http://qq.com',  # 应该被识别为安全（白名单）
        'https://www.qq.com/',  # 应该被识别为安全（白名单）
        'http://deepphish.cn',  # 应该被识别为高风险（包含phish）
        'cid:020362C0@0541ED24.A911B16900000000.png',  # 应该被跳过
        'mailto:support@deepphish.cn',  # 应该被跳过
        'http://paypa1-security.com',  # 应该被识别为高风险（品牌滥用）
        'http://192.168.1.100/login',  # 应该被识别为高风险（IP地址）
        'http://suspicious-login.xyz',  # 应该被识别为中等风险（新域名+可疑关键词）
    ]
    
    print("=" * 70)
    print("URL安全分析测试")
    print("=" * 70)
    
    results = analyze_urls(test_urls)
    
    print("\n【有效URL分析结果】")
    for r in results['valid_urls']:
        print(f"\nURL: {r['url']}")
        print(f"  风险等级: {r['risk_level']}")
        print(f"  风险分数: {r['risk_score']}")
        print(f"  域名: {r['domain']}")
        print(f"  注册域名: {r['registered_domain']}")
        print(f"  域名年龄: {r['domain_age_days'] if r['domain_age_days'] else '未知'}天")
        print(f"  白名单: {r['is_whitelisted']}")
        print(f"  原因: {'; '.join(r['reasons']) if r['reasons'] else '无'}")
    
    print("\n【被跳过的URL】")
    for s in results['skipped_urls']:
        print(f"  - {s['url'][:50]}")
        print(f"    原因: {s['reason']}")
    
    print("\n【分析摘要】")
    for key, value in results['summary'].items():
        print(f"  {key}: {value}")
    
    print(f"\n整体最高风险: {results['max_risk_level']} ({results['max_risk_score']}分)")
    print("=" * 70)
