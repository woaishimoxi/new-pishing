"""
Traceback Service - 优化版
Email source tracing with timeout control, caching, and parallel queries
"""
import re
import time
import requests
import socket
import json
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple, Set
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config


# 全局配置
TRUSTED_DOMAINS: Set[str] = set()
BLACKLISTED_DOMAINS: Set[str] = set()
BLACKLISTED_IPS: Set[str] = set()
KNOWN_MALICIOUS_IOCS: Dict = {
    'ips': set(),
    'domains': set(),
    'urls': set(),
    'hashes': set(),
    'domain_patterns': [],
    'url_patterns': [],
    'ip_patterns': []
}

# 缓存
DOMAIN_AGE_CACHE: Dict = {}
IP_GEO_CACHE: Dict = {}
BLACKLIST_CACHE: Dict = {}

_CONFIG_LOADED = False

# 超时配置（秒）
WHOIS_TIMEOUT = 5
IP_API_TIMEOUT = 3
URL_TRACE_TIMEOUT = 3
BLACKLIST_TIMEOUT = 2

# 扩展的DNSBL服务器列表
DNSBL_SERVERS = [
    ('zen.spamhaus.org', 'Spamhaus'),
    ('b.barracudacentral.org', 'Barracuda'),
    ('bl.spamcop.net', 'SpamCop'),
    ('dnsbl.sorbs.net', 'SORBS'),
    ('psbl.surriel.com', 'PSBL'),
    ('all.s5h.net', 'S5H'),
    ('rbl.interserver.net', 'InterServer'),
    ('spam.rbl.blockedservers.com', 'BlockedServers'),
    ('spam.dnsbl.sorbs.net', 'SORBS Spam'),
    ('ubl.unsubscore.com', 'Unsubscribe'),
]


def _load_config():
    """Load whitelist, blacklist and IOC config"""
    global TRUSTED_DOMAINS, BLACKLISTED_DOMAINS, BLACKLISTED_IPS
    global KNOWN_MALICIOUS_IOCS, _CONFIG_LOADED
    
    if _CONFIG_LOADED:
        return
    
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    
    # 加载白名单
    whitelist_file = os.path.join(base_dir, 'config', 'whitelist.json')
    if os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                whitelist = json.load(f)
                TRUSTED_DOMAINS = set(whitelist.get('trusted_domains', []))
        except Exception as e:
            print(f"Failed to load whitelist: {e}")
    
    # 加载黑名单
    blacklist_file = os.path.join(base_dir, 'config', 'blacklist.json')
    if os.path.exists(blacklist_file):
        try:
            with open(blacklist_file, 'r', encoding='utf-8') as f:
                blacklist = json.load(f)
                BLACKLISTED_DOMAINS = set(blacklist.get('domains', []))
                BLACKLISTED_IPS = set(blacklist.get('ips', []))
        except Exception as e:
            print(f"Failed to load blacklist: {e}")
    
    # 加载IOC数据库
    ioc_file = os.path.join(base_dir, 'config', 'ioc_database.json')
    if os.path.exists(ioc_file):
        try:
            with open(ioc_file, 'r', encoding='utf-8') as f:
                ioc_data = json.load(f)
                KNOWN_MALICIOUS_IOCS['ips'].update(ioc_data.get('malicious_ips', []))
                KNOWN_MALICIOUS_IOCS['domains'].update(ioc_data.get('malicious_domains', []))
                KNOWN_MALICIOUS_IOCS['urls'].update(ioc_data.get('malicious_urls', []))
                KNOWN_MALICIOUS_IOCS['hashes'].update(ioc_data.get('malicious_hashes', []))
                KNOWN_MALICIOUS_IOCS['domain_patterns'] = ioc_data.get('malicious_domain_patterns', [])
                KNOWN_MALICIOUS_IOCS['url_patterns'] = ioc_data.get('malicious_url_patterns', [])
                KNOWN_MALICIOUS_IOCS['ip_patterns'] = ioc_data.get('malicious_ip_patterns', [])
        except Exception as e:
            print(f"Failed to load IOC database: {e}")
    
    _CONFIG_LOADED = True


def reload_config():
    """Reload configuration files"""
    global _CONFIG_LOADED
    _CONFIG_LOADED = False
    DOMAIN_AGE_CACHE.clear()
    IP_GEO_CACHE.clear()
    BLACKLIST_CACHE.clear()
    _load_config()
    return {
        'trusted_domains': len(TRUSTED_DOMAINS),
        'blacklisted_domains': len(BLACKLISTED_DOMAINS),
        'blacklisted_ips': len(BLACKLISTED_IPS),
        'malicious_ips': len(KNOWN_MALICIOUS_IOCS['ips']),
        'malicious_domains': len(KNOWN_MALICIOUS_IOCS['domains'])
    }


def get_config_stats():
    """Get configuration statistics"""
    _load_config()
    return {
        'trusted_domains': len(TRUSTED_DOMAINS),
        'trusted_domains_list': sorted(list(TRUSTED_DOMAINS))[:50],
        'blacklisted_domains': len(BLACKLISTED_DOMAINS),
        'blacklisted_domains_list': sorted(list(BLACKLISTED_DOMAINS))[:50],
        'blacklisted_ips': len(BLACKLISTED_IPS),
        'blacklisted_ips_list': sorted(list(BLACKLISTED_IPS))[:50],
        'malicious_ips': len(KNOWN_MALICIOUS_IOCS['ips']),
        'malicious_domains': len(KNOWN_MALICIOUS_IOCS['domains']),
        'malicious_urls': len(KNOWN_MALICIOUS_IOCS['urls']),
        'cache_size': {
            'domain_age': len(DOMAIN_AGE_CACHE),
            'ip_geo': len(IP_GEO_CACHE),
            'blacklist': len(BLACKLIST_CACHE)
        }
    }


def add_to_whitelist(domains: List[str]):
    """Add domains to whitelist"""
    _load_config()
    TRUSTED_DOMAINS.update(domains)
    _save_whitelist()


def remove_from_whitelist(domains: List[str]):
    """Remove domains from whitelist"""
    _load_config()
    TRUSTED_DOMAINS.difference_update(domains)
    _save_whitelist()


def add_to_blacklist(domains: List[str] = None, ips: List[str] = None):
    """Add to blacklist"""
    _load_config()
    if domains:
        BLACKLISTED_DOMAINS.update(domains)
    if ips:
        BLACKLISTED_IPS.update(ips)
    _save_blacklist()


def remove_from_blacklist(domains: List[str] = None, ips: List[str] = None):
    """Remove from blacklist"""
    _load_config()
    if domains:
        BLACKLISTED_DOMAINS.difference_update(domains)
    if ips:
        BLACKLISTED_IPS.difference_update(ips)
    _save_blacklist()


def _save_whitelist():
    """Save whitelist to file"""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    whitelist_file = os.path.join(base_dir, 'config', 'whitelist.json')
    
    try:
        if os.path.exists(whitelist_file):
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                data = json.load(f)
        else:
            data = {}
        
        data['trusted_domains'] = sorted(list(TRUSTED_DOMAINS))
        
        with open(whitelist_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Failed to save whitelist: {e}")


def _save_blacklist():
    """Save blacklist to file"""
    base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
    blacklist_file = os.path.join(base_dir, 'config', 'blacklist.json')
    
    try:
        data = {
            'domains': sorted(list(BLACKLISTED_DOMAINS)),
            'ips': sorted(list(BLACKLISTED_IPS)),
            'last_updated': datetime.now().isoformat()
        }
        
        with open(blacklist_file, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"Failed to save blacklist: {e}")


class TracebackService:
    """
    Traceback service - 优化版
    支持超时控制、缓存机制、并行查询
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        _load_config()
        self.executor = ThreadPoolExecutor(max_workers=10)
    
    def generate_report(
        self,
        parsed_email: Dict,
        vt_api_key: str = "",
        ip_api_url: str = 'http://ip-api.com/json/'
    ) -> Dict:
        """
        Generate complete traceback report with correlation analysis
        """
        report = {
            'email_source': {},
            'url_analysis': [],
            'risk_indicators': [],
            'correlation_analysis': {
                'attack_chain': [],
                'ioc_matches': [],
                'related_campaigns': [],
                'threat_score': 0
            },
            'ioc_matches': {
                'malicious_ips': [],
                'malicious_domains': [],
                'malicious_urls': [],
                'suspicious_patterns': []
            }
        }
        
        # 分析邮件来源
        received_chain = parsed_email.get('received_chain', [])
        if received_chain:
            source_info = self._extract_source_ip_and_path(received_chain)
            report['email_source']['source_ip'] = source_info['source_ip']
            report['email_source']['full_path'] = source_info['full_path']
            report['email_source']['hops'] = source_info['hops']
            
            if source_info['source_ip'] != 'Unknown':
                # 并行查询IP信息和黑名单
                futures = {}
                
                # IP地理位置查询
                futures['geo'] = self.executor.submit(
                    self._get_ip_geolocation, source_info['source_ip'], ip_api_url
                )
                
                # 黑名单检查
                futures['blacklist'] = self.executor.submit(
                    self._check_blacklist_parallel, source_info['source_ip']
                )
                
                # 等待结果
                try:
                    geo_info = futures['geo'].result(timeout=IP_API_TIMEOUT + 1)
                    report['email_source']['geolocation'] = geo_info
                except Exception:
                    report['email_source']['geolocation'] = {'ip': source_info['source_ip'], 'error': 'timeout'}
                
                try:
                    blacklist_info = futures['blacklist'].result(timeout=BLACKLIST_TIMEOUT * 2 + 1)
                    report['email_source']['blacklist_check'] = blacklist_info
                except Exception:
                    report['email_source']['blacklist_check'] = {'ip': source_info['source_ip'], 'is_blacklisted': False}
                
                if report['email_source'].get('blacklist_check', {}).get('is_blacklisted'):
                    report['risk_indicators'].append({
                        'type': 'BLACKLISTED_IP',
                        'description': f"源IP {source_info['source_ip']} 被以下黑名单标记：{', '.join(report['email_source']['blacklist_check'].get('blacklists', []))}",
                        'severity': 'high'
                    })
                    report['correlation_analysis']['ioc_matches'].append({
                        'type': 'ip',
                        'value': source_info['source_ip'],
                        'reason': 'Blacklisted IP'
                    })
                
                # IOC匹配：检查本地黑名单
                if source_info['source_ip'] in BLACKLISTED_IPS or source_info['source_ip'] in KNOWN_MALICIOUS_IOCS['ips']:
                    report['ioc_matches']['malicious_ips'].append(source_info['source_ip'])
                    report['correlation_analysis']['threat_score'] += 50
        
        # 并行分析URL
        urls = parsed_email.get('urls', [])
        if urls:
            url_futures = []
            for url in urls[:10]:  # 最多分析10个URL
                future = self.executor.submit(self._analyze_single_url, url)
                url_futures.append(future)
            
            for future in as_completed(url_futures, timeout=URL_TRACE_TIMEOUT * 3):
                try:
                    url_analysis = future.result()
                    if url_analysis:
                        report['url_analysis'].append(url_analysis)
                        
                        # IOC匹配
                        domain = url_analysis.get('domain_info', {}).get('domain', '')
                        url = url_analysis.get('url', '')
                        
                        if domain in BLACKLISTED_DOMAINS or domain in KNOWN_MALICIOUS_IOCS['domains']:
                            report['ioc_matches']['malicious_domains'].append(domain)
                            report['correlation_analysis']['threat_score'] += 40
                        
                        if url in KNOWN_MALICIOUS_IOCS['urls']:
                            report['ioc_matches']['malicious_urls'].append(url)
                            report['correlation_analysis']['threat_score'] += 50
                        
                        # 模式匹配
                        for pattern in KNOWN_MALICIOUS_IOCS.get('domain_patterns', []):
                            try:
                                if re.match(pattern, domain, re.IGNORECASE):
                                    report['ioc_matches']['suspicious_patterns'].append(f'域名匹配模式: {pattern}')
                                    report['correlation_analysis']['threat_score'] += 25
                                    break
                            except re.error:
                                pass
                except Exception as e:
                    self.logger.warning(f"URL analysis failed: {e}")
        
        # 构建攻击链
        report['correlation_analysis']['attack_chain'] = self._build_attack_chain(
            report['email_source'],
            report['url_analysis'],
            parsed_email
        )
        
        # 计算最终威胁分数
        threat_score = report['correlation_analysis']['threat_score']
        threat_score += len(report['risk_indicators']) * 10
        threat_score += len(report['ioc_matches']['malicious_ips']) * 30
        threat_score += len(report['ioc_matches']['malicious_domains']) * 25
        threat_score += len(report['ioc_matches']['malicious_urls']) * 35
        report['correlation_analysis']['threat_score'] = min(threat_score, 100)
        
        return report
    
    def _analyze_single_url(self, url: str) -> Dict:
        """Analyze single URL with timeout control"""
        url_analysis = {
            'url': url,
            'redirect_chain': [],
            'domain_info': {},
            'risks': []
        }
        
        try:
            # URL重定向追踪（带超时）
            redirect_chain = self._trace_url_redirects(url)
            if len(redirect_chain) > 1:
                url_analysis['redirect_chain'] = redirect_chain
                url_analysis['risks'].append({
                    'type': 'MULTIPLE_REDIRECTS',
                    'description': f"URL经过{len(redirect_chain)-1}次跳转",
                    'severity': 'medium'
                })
        except Exception:
            pass
        
        # 域名分析
        parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
        domain = parsed.netloc.split(':')[0]
        if domain:
            domain_info = self._analyze_domain_info(domain)
            url_analysis['domain_info'] = domain_info
            url_analysis['domain'] = domain
            
            if domain_info.get('age_days') and domain_info['age_days'] < 30:
                url_analysis['risks'].append({
                    'type': 'NEW_DOMAIN',
                    'description': f"域名注册仅{domain_info['age_days']}天",
                    'severity': 'high'
                })
            
            if '-' in domain or any(c.isdigit() for c in domain.split('.')[0]):
                url_analysis['risks'].append({
                    'type': 'SUSPICIOUS_DOMAIN_PATTERN',
                    'description': "域名包含连字符或数字，可能存在仿冒嫌疑",
                    'severity': 'medium'
                })
        
        return url_analysis
    
    def _build_attack_chain(self, email_source: Dict, url_analysis: List, parsed_email: Dict) -> List[Dict]:
        """Build attack chain from collected evidence"""
        chain = []
        
        if email_source.get('source_ip'):
            chain.append({
                'step': 1,
                'type': 'email_source',
                'description': f'邮件来自IP: {email_source["source_ip"]}',
                'details': {
                    'ip': email_source['source_ip'],
                    'geolocation': email_source.get('geolocation', {}),
                    'path': email_source.get('full_path', '')
                }
            })
        
        from_email = parsed_email.get('from_email', '')
        if from_email:
            chain.append({
                'step': 2,
                'type': 'sender',
                'description': f'发件人: {from_email}',
                'details': {
                    'email': from_email,
                    'display_name': parsed_email.get('from_display_name', '')
                }
            })
        
        malicious_urls = [ua for ua in url_analysis if ua.get('risks')]
        if malicious_urls:
            chain.append({
                'step': 3,
                'type': 'malicious_urls',
                'description': f'发现{len(malicious_urls)}个可疑URL',
                'details': {
                    'urls': [ua['url'] for ua in malicious_urls[:5]]
                }
            })
        
        to_email = parsed_email.get('to', '')
        if to_email:
            chain.append({
                'step': 4,
                'type': 'target',
                'description': f'攻击目标: {to_email}',
                'details': {'target': to_email}
            })
        
        return chain
    
    def _extract_source_ip_and_path(self, received_chain: List[str]) -> Dict:
        """Extract source IP and path from Received chain"""
        path = []
        source_ip = "Unknown"
        ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
        
        for i, line in enumerate(reversed(received_chain)):
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                ip = ip_match.group(1)
                if not self._is_private_ip(ip):
                    path.append(ip)
                    if i == len(received_chain) - 1:
                        source_ip = ip
        
        return {
            "source_ip": source_ip,
            "full_path": "->".join(reversed(path)),
            "hops": list(reversed(path))
        }
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private"""
        parts = ip.split('.')
        if len(parts) != 4:
            return False
        try:
            first = int(parts[0])
            second = int(parts[1])
            if first == 10:
                return True
            if first == 172 and 16 <= second <= 31:
                return True
            if first == 192 and second == 168:
                return True
            if first == 127:
                return True
            if first == 0:
                return True
        except ValueError:
            pass
        return False
    
    def _get_ip_geolocation(self, ip: str, ip_api_url: str) -> Dict:
        """Get IP geolocation info with caching and timeout"""
        # 检查缓存
        if ip in IP_GEO_CACHE:
            return IP_GEO_CACHE[ip]
        
        locations = {
            'ip': ip,
            'country': 'Unknown',
            'regionName': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }
        
        try:
            response = requests.get(f'{ip_api_url}{ip}', timeout=IP_API_TIMEOUT)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    locations['country'] = data.get('country', 'Unknown')
                    locations['regionName'] = data.get('regionName', 'Unknown')
                    locations['city'] = data.get('city', 'Unknown')
                    locations['isp'] = data.get('isp', 'Unknown')
        except requests.Timeout:
            self.logger.warning(f"IP geolocation timeout for {ip}")
        except Exception as e:
            self.logger.error(f"IP geolocation query failed: {e}")
        
        # 缓存结果
        IP_GEO_CACHE[ip] = locations
        return locations
    
    def _trace_url_redirects(self, initial_url: str, max_hops: int = 5) -> List[str]:
        """Trace URL redirect chain with timeout"""
        redirects = [initial_url]
        current_url = initial_url
        visited = {initial_url.lower()}
        
        for _ in range(max_hops):
            try:
                resp = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=URL_TRACE_TIMEOUT,
                    headers={'User-Agent': 'Mozilla/5.0'}
                )
                
                if resp.status_code in (301, 302, 303, 307, 308) and 'Location' in resp.headers:
                    next_url = resp.headers['Location']
                    if not next_url.startswith(('http://', 'https://')):
                        next_url = urljoin(current_url, next_url)
                    
                    if next_url.lower() in visited:
                        break
                    
                    visited.add(next_url.lower())
                    redirects.append(next_url)
                    current_url = next_url
                else:
                    break
            except requests.Timeout:
                self.logger.warning(f"URL redirect trace timeout: {current_url}")
                break
            except requests.RequestException:
                break
        
        return redirects
    
    def _analyze_domain_info(self, domain: str) -> Dict:
        """Analyze domain info with caching and timeout"""
        # 检查缓存
        if domain in DOMAIN_AGE_CACHE:
            return DOMAIN_AGE_CACHE[domain]
        
        info = {
            'domain': domain,
            'is_valid': False,
            'has_mx_record': False,
            'registrar': 'Unknown',
            'creation_date': None,
            'expiry_date': None,
            'age_days': 0
        }
        
        # 检查是否为可信域名
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            registered_domain = '.'.join(domain_parts[-2:])
            if registered_domain in TRUSTED_DOMAINS:
                info['is_valid'] = True
                info['registrar'] = 'Trusted Domain'
                info['age_days'] = 3650
                DOMAIN_AGE_CACHE[domain] = info
                return info
        
        # 检查是否为黑名单域名
        if domain in BLACKLISTED_DOMAINS:
            info['is_valid'] = True
            info['registrar'] = 'Blacklisted Domain'
            info['age_days'] = 0
            DOMAIN_AGE_CACHE[domain] = info
            return info
        
        # WHOIS查询（带超时）
        try:
            import whois
            w = whois.whois(domain)
            
            if w and hasattr(w, 'creation_date') and w.creation_date:
                info['is_valid'] = True
                
                registrar = w.registrar
                if isinstance(registrar, list):
                    registrar = registrar[0] if registrar else 'Unknown'
                elif registrar is None:
                    registrar = 'Unknown'
                info['registrar'] = str(registrar)
                
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
                        info['creation_date'] = str(creation_date)
                        info['age_days'] = max(0, int(age_seconds / 86400))
                    except Exception:
                        info['age_days'] = 3650
                else:
                    info['age_days'] = 3650
                
                expiry_date = w.expiration_date
                if isinstance(expiry_date, list):
                    expiry_date = expiry_date[0]
                info['expiry_date'] = str(expiry_date) if expiry_date else None
            else:
                info['is_valid'] = True
                info['age_days'] = 3650
        except Exception as e:
            self.logger.warning(f"WHOIS query failed for {domain}: {e}")
            info['is_valid'] = True
            info['age_days'] = 3650
        
        # 缓存结果
        DOMAIN_AGE_CACHE[domain] = info
        return info
    
    def _check_blacklist_parallel(self, ip: str) -> Dict:
        """Check if IP is blacklisted using parallel DNSBL queries"""
        # 检查缓存
        if ip in BLACKLIST_CACHE:
            return BLACKLIST_CACHE[ip]
        
        result = {
            'ip': ip,
            'is_blacklisted': False,
            'blacklists': []
        }
        
        # 检查本地黑名单
        if ip in BLACKLISTED_IPS:
            result['is_blacklisted'] = True
            result['blacklists'].append('Local Blacklist')
            BLACKLIST_CACHE[ip] = result
            return result
        
        try:
            reversed_ip = '.'.join(ip.split('.')[::-1])
            
            # 并行查询多个DNSBL
            futures = {}
            for server, name in DNSBL_SERVERS:
                future = self.executor.submit(self._query_single_dnsbl, reversed_ip, server, name)
                futures[future] = name
            
            for future in as_completed(futures, timeout=BLACKLIST_TIMEOUT * 2):
                try:
                    is_listed, server_name = future.result()
                    if is_listed:
                        result['is_blacklisted'] = True
                        result['blacklists'].append(server_name)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Blacklist check failed: {e}")
        
        # 缓存结果
        BLACKLIST_CACHE[ip] = result
        return result
    
    def _query_single_dnsbl(self, reversed_ip: str, server: str, name: str) -> Tuple[bool, str]:
        """Query single DNSBL server with timeout"""
        query = f"{reversed_ip}.{server}"
        try:
            socket.setdefaulttimeout(BLACKLIST_TIMEOUT)
            socket.gethostbyname(query)
            return True, name
        except socket.gaierror:
            return False, name
        except socket.timeout:
            return False, name
        finally:
            socket.setdefaulttimeout(None)
