"""
自动化溯源模块
溯源是本系统区别于传统工具的核心亮点。它旨在回答两个关键问题：
1. 邮件从哪里来？
2. 恶意链接指向哪里？
"""
import re
import time
import requests
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple


def extract_source_ip_and_path(received_chain: List[str]) -> Dict:
    """
    从 Received 链中提取攻击源 IP 和完整的传输路径。

    Args:
        received_chain: 邮件头中的 Received 字段列表

    Returns:
        Dict: 包含'source_ip'和'path'的字典
    """
    path = []
    source_ip = "Unknown"

    # 正则匹配 IPv4 地址（在方括号中）
    ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'

    # 逆序遍历，从最后一跳 (最接近收件人) 开始
    for i, line in enumerate(reversed(received_chain)):
        ip_match = re.search(ip_pattern, line)
        if ip_match:
            ip = ip_match.group(1)

            # 排除私有 IP 地址
            if not _is_private_ip(ip):
                path.append(ip)
                if i == len(received_chain) - 1:  # 第一个找到的外部 IP 即为源
                    source_ip = ip

    return {
        "source_ip": source_ip,
        "full_path": "->".join(reversed(path)),
        "hops": list(reversed(path))
    }


def _is_private_ip(ip: str) -> bool:
    """
    检查 IP 是否为私有地址。

    Args:
        ip: IP 地址

    Returns:
        bool: 是否为私有 IP
    """
    parts = ip.split('.')
    if len(parts) != 4:
        return False

    try:
        first = int(parts[0])
        second = int(parts[1])

        # 10.0.0.0/8
        if first == 10:
            return True
        # 172.16.0.0/12
        if first == 172 and 16 <= second <= 31:
            return True
        # 192.168.0.0/16
        if first == 192 and second == 168:
            return True
        # 127.0.0.0/8 (localhost)
        if first == 127:
            return True
        # 0.0.0.0
        if first == 0:
            return True
    except ValueError:
        pass

    return False


def get_ip_geolocation(ip: str, ip_api_url: str = 'http://ip-api.com/json/') -> Dict:
    """
    查询 IP 地理位置信息。

    Args:
        ip: IP 地址
        ip_api_url: IP 地理位置 API 的 URL

    Returns:
        Dict: 包含地理位置信息的字典
    """
    locations = {
        'ip': ip,
        'country': 'Unknown',
        'region': 'Unknown',
        'city': 'Unknown',
        'isp': 'Unknown'
    }

    try:
        # 使用 IP 定位 API
        response = requests.get(f'{ip_api_url}{ip}', timeout=5)
        if response.status_code == 200:
            data = response.json()
            if data.get('status') == 'success':
                locations['country'] = data.get('country', 'Unknown')
                locations['regionName'] = data.get('regionName', 'Unknown')
                locations['city'] = data.get('city', 'Unknown')
                locations['isp'] = data.get('isp', 'Unknown')
    except Exception as e:
        print(f"IP 地理定位查询失败：{e}")

    return locations


def trace_url_redirects(initial_url: str, max_hops: int = 5) -> List[str]:
    """
    跟踪 URL 的跳转链路。

    Args:
        initial_url: 初始 URL
        max_hops: 最大跳转次数

    Returns:
        List[str]: 完整的跳转 URL 列表
    """
    redirects = [initial_url]
    current_url = initial_url
    visited = {initial_url.lower()}

    for _ in range(max_hops):
        try:
            # 使用 HEAD 请求，只获取响应头
            resp = requests.head(
                current_url,
                allow_redirects=False,
                timeout=3,
                headers={'User-Agent': 'Mozilla/5.0'}
            )

            if resp.status_code in (301, 302, 303, 307, 308) and 'Location' in resp.headers:
                next_url = resp.headers['Location']
                # 处理相对路径
                if not next_url.startswith(('http://', 'https://')):
                    next_url = urljoin(current_url, next_url)

                # 避免循环
                if next_url.lower() in visited:
                    break

                visited.add(next_url.lower())
                redirects.append(next_url)
                current_url = next_url
            else:
                break
        except requests.RequestException:
            # 网络错误静默处理，不影响主流程
            break

    return redirects


# 可信域名白名单
TRUSTED_DOMAINS = {
    'qq.com', 'qlogo.cn', 'mail.qq.com', 'weixin.qq.com',
    'steampowered.com', 'steamcommunity.com', 'steamstatic.com',
    'valvesoftware.com', 'google.com', 'microsoft.com',
    'facebook.com', 'baidu.com', 'taobao.com', 'jd.com'
}

# 域名年龄缓存
DOMAIN_AGE_CACHE = {}

def analyze_domain_info(domain: str) -> Dict:
    """
    分析域名信息。

    Args:
        domain: 域名

    Returns:
        Dict: 包含域名分析信息的字典
    """
    info = {
        'domain': domain,
        'is_valid': False,
        'has_mx_record': False,
        'registrar': 'Unknown',
        'creation_date': None,
        'expiry_date': None,
        'age_days': 0
    }

    # 检查缓存
    if domain in DOMAIN_AGE_CACHE:
        cached_info = DOMAIN_AGE_CACHE[domain]
        info.update(cached_info)
        return info

    # 检查白名单
    domain_parts = domain.split('.')
    if len(domain_parts) >= 2:
        registered_domain = '.'.join(domain_parts[-2:])
        if registered_domain in TRUSTED_DOMAINS:
            info['is_valid'] = True
            info['registrar'] = 'Trusted Domain'
            info['age_days'] = 3650  # 10年
            DOMAIN_AGE_CACHE[domain] = info
            return info

    try:
        import whois
        w = whois.get(domain)
        if not w or not hasattr(w, 'creation_date'):
            # 查询失败时返回默认值，避免误判为新域名
            info['is_valid'] = True
            info['age_days'] = 3650  # 默认为10年
            DOMAIN_AGE_CACHE[domain] = info
            return info

        info['is_valid'] = True

        # 注册商 (新版 whois 返回单个字符串或列表)
        registrar = w.registrar
        if isinstance(registrar, list):
            registrar = registrar[0] if registrar else 'Unknown'
        elif registrar is None:
            registrar = 'Unknown'
        info['registrar'] = str(registrar)

        # 创建日期 - 兼容新旧版本 whois
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
                    age_seconds = 0
                info['creation_date'] = creation_date
                info['age_days'] = int(age_seconds / 86400)
            except Exception:
                info['age_days'] = 3650  # 解析失败时默认为10年
        else:
            info['age_days'] = 3650  # 没有创建日期时默认为10年

        # 过期日期
        expiry_date = w.expiration_date
        if isinstance(expiry_date, list):
            expiry_date = expiry_date[0]
        info['expiry_date'] = expiry_date

    except Exception:
        # 域名信息查询失败时默认为10年，避免误判
        info['is_valid'] = True
        info['age_days'] = 3650

    # 缓存结果
    DOMAIN_AGE_CACHE[domain] = info
    return info


def check_blacklist(ip: str) -> Dict:
    """
    检查 IP 是否在黑名单中。

    Args:
        ip: IP 地址

    Returns:
        Dict: 包含黑名单检查结果的信息
    """
    result = {
        'ip': ip,
        'is_blacklisted': False,
        'blacklists': []
    }

    # 常见的 DNSBL 服务
    dnsbl_servers = [
        ('zen.spamhaus.org', 'Spamhaus'),
        ('b.barracudacentral.org', 'Barracuda'),
        ('ubl.unsubscore.com', 'Unsubscribe'),
    ]

    try:
        # 将 IP 反转用于 DNSBL 查询
        reversed_ip = '.'.join(ip.split('.')[::-1])

        for server, name in dnsbl_servers:
            query = f"{reversed_ip}.{server}"
            try:
                import socket
                socket.gethostbyname(query)
                result['is_blacklisted'] = True
                result['blacklists'].append(name)
            except socket.gaierror:
                pass
    except Exception as e:
        print(f"黑名单查询失败：{e}")

    return result


def generate_traceback_report(parsed_email: Dict, vt_api_key: str = "", ip_api_url: str = 'http://ip-api.com/json/') -> Dict:
    """
    生成完整的溯源报告。

    Args:
        parsed_email: 解析后的邮件数据
        vt_api_key: VirusTotal API 密钥
        ip_api_url: IP 地理位置 API 的 URL

    Returns:
        Dict: 完整的溯源报告
    """
    report = {
        'email_source': {},
        'url_analysis': [],
        'risk_indicators': []
    }

    # 邮件来源分析
    received_chain = parsed_email.get('received_chain', [])
    if received_chain:
        source_info = extract_source_ip_and_path(received_chain)
        report['email_source']['source_ip'] = source_info['source_ip']
        report['email_source']['full_path'] = source_info['full_path']
        report['email_source']['hops'] = source_info['hops']

        # 查询源 IP 地理位置
        if source_info['source_ip'] != 'Unknown':
            geo_info = get_ip_geolocation(source_info['source_ip'], ip_api_url)
            report['email_source']['geolocation'] = geo_info

            # 检查黑名单
            blacklist_info = check_blacklist(source_info['source_ip'])
            report['email_source']['blacklist_check'] = blacklist_info

            if blacklist_info['is_blacklisted']:
                report['risk_indicators'].append({
                    'type': 'BLACKLISTED_IP',
                    'description': f"源 IP {source_info['source_ip']} 被以下黑名单标记：{', '.join(blacklist_info['blacklists'])}",
                    'severity': 'high'
                })

    # URL 分析
    urls = parsed_email.get('urls', [])
    for url in urls:
        url_analysis = {
            'url': url,
            'redirect_chain': [],
            'domain_info': {},
            'risks': []
        }

        # 追踪跳转
        redirect_chain = trace_url_redirects(url)
        if len(redirect_chain) > 1:
            url_analysis['redirect_chain'] = redirect_chain
            url_analysis['risks'].append({
                'type': 'MULTIPLE_REDIRECTS',
                'description': f"URL 经过 {len(redirect_chain)-1} 次跳转",
                'severity': 'medium'
            })

        # 分析域名
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.split(':')[0]
        if domain:
            domain_info = analyze_domain_info(domain)
            url_analysis['domain_info'] = domain_info

            # 检查域名年龄
            if domain_info['age_days'] < 30:
                url_analysis['risks'].append({
                    'type': 'NEW_DOMAIN',
                    'description': f"域名注册仅 {domain_info['age_days']} 天",
                    'severity': 'high'
                })

            # 检查仿冒特征
            if '-' in domain or any(c.isdigit() for c in domain.split('.')[0]):
                url_analysis['risks'].append({
                    'type': 'SUSPICIOUS_DOMAIN_PATTERN',
                    'description': "域名包含连字符或数字，可能存在仿冒嫌疑",
                    'severity': 'medium'
                })

        report['url_analysis'].append(url_analysis)

    return report


if __name__ == "__main__":
    from parse_email import parse_email

    test_email = """From: "Security Team" <noreply@suspicious-site.com>
To: user@example.com
Subject: 账户验证通知

尊敬的用户，

请点击以下链接进行验证：
http://bit.ly/3xyz123

谢谢！
"""

    parsed = parse_email(test_email)

    print("=" * 60)
    print("邮件溯源分析报告")
    print("=" * 60)

    report = generate_traceback_report(parsed)

    print("\n【邮件来源】")
    if report['email_source']:
        print(f"源 IP: {report['email_source'].get('source_ip', 'Unknown')}")
        print(f"传输路径：{report['email_source'].get('full_path', 'N/A')}")
    else:
        print("无 Received 链信息")

    print("\n【URL 分析】")
    for ua in report['url_analysis']:
        print(f"\nURL: {ua['url']}")
        if ua['redirect_chain']:
            print(f"跳转链路：{' -> '.join(ua['redirect_chain'])}")
        if ua['domain_info']:
            info = ua['domain_info']
            print(f"域名：{info.get('domain')}")
            print(f"注册商：{info.get('registrar')}")
            print(f"注册天数：{info.get('age_days')}")

    print("\n【风险指标】")
    for indicator in report['risk_indicators']:
        print(f"[{indicator['severity'].upper()}] {indicator['description']}")

    print("=" * 60)
