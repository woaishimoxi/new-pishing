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


class IOCQueryService:
    """IOC查询服务：先查本地，再查云端"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self._load_local_ioc()
    
    def _load_local_ioc(self):
        """加载本地IOC数据库"""
        _load_config()
    
    def query_ip(self, ip: str) -> Dict:
        """
        查询IP的威胁情报
        逻辑：先查本地IOC库，如果本地已标记则直接返回，否则调用云端API
        """
        result = {
            'ip': ip,
            'is_malicious': False,
            'source': None,
            'details': {}
        }
        
        if ip in KNOWN_MALICIOUS_IOCS['ips']:
            result['is_malicious'] = True
            result['source'] = 'local'
            result['details']['message'] = '本地IOC库已标记为恶意'
            return result
        
        if ip in BLACKLISTED_IPS:
            result['is_malicious'] = True
            result['source'] = 'local_blacklist'
            result['details']['message'] = '本地黑名单已标记'
            return result
        
        if self.config.api.ioc_remote_enabled and self.config.api.threatbook_api_key:
            cloud_result = self._query_threatbook_ip(ip)
            if cloud_result:
                result.update(cloud_result)
                result['source'] = 'cloud'
                if result['is_malicious']:
                    self._update_local_ioc('ip', ip)
        
        return result
    
    def query_domain(self, domain: str) -> Dict:
        """
        查询域名的威胁情报
        逻辑：先查本地IOC库，如果本地已标记则直接返回，否则调用云端API
        """
        result = {
            'domain': domain,
            'is_malicious': False,
            'source': None,
            'details': {}
        }
        
        if domain in KNOWN_MALICIOUS_IOCS['domains']:
            result['is_malicious'] = True
            result['source'] = 'local'
            result['details']['message'] = '本地IOC库已标记为恶意'
            return result
        
        if domain in BLACKLISTED_DOMAINS:
            result['is_malicious'] = True
            result['source'] = 'local_blacklist'
            result['details']['message'] = '本地黑名单已标记'
            return result
        
        for pattern in KNOWN_MALICIOUS_IOCS.get('domain_patterns', []):
            if pattern.lower() in domain.lower():
                result['is_malicious'] = True
                result['source'] = 'local_pattern'
                result['details']['message'] = f'匹配恶意域名模式: {pattern}'
                return result
        
        if self.config.api.ioc_remote_enabled and self.config.api.threatbook_api_key:
            cloud_result = self._query_threatbook_domain(domain)
            if cloud_result:
                result.update(cloud_result)
                result['source'] = 'cloud'
                if result['is_malicious']:
                    self._update_local_ioc('domain', domain)
        
        return result
    
    def query_url(self, url: str) -> Dict:
        """
        查询URL的威胁情报
        逻辑：先查本地IOC库，如果本地已标记则直接返回，否则调用云端API
        """
        result = {
            'url': url,
            'is_malicious': False,
            'source': None,
            'details': {}
        }
        
        if url in KNOWN_MALICIOUS_IOCS['urls']:
            result['is_malicious'] = True
            result['source'] = 'local'
            result['details']['message'] = '本地IOC库已标记为恶意'
            return result
        
        for pattern in KNOWN_MALICIOUS_IOCS.get('url_patterns', []):
            if pattern.lower() in url.lower():
                result['is_malicious'] = True
                result['source'] = 'local_pattern'
                result['details']['message'] = f'匹配恶意URL模式: {pattern}'
                return result
        
        if self.config.api.ioc_remote_enabled and self.config.api.threatbook_api_key:
            cloud_result = self._query_threatbook_url(url)
            if cloud_result:
                result.update(cloud_result)
                result['source'] = 'cloud'
                if result['is_malicious']:
                    self._update_local_ioc('url', url)
        
        return result
    
    def _query_threatbook_ip(self, ip: str) -> Dict:
        """查询微步在线IP威胁情报"""
        try:
            params = {
                'apikey': self.config.api.threatbook_api_key,
                'resource': ip
            }
            response = requests.get(
                f'{self.config.api.threatbook_api_url}/ip/query',
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 0:
                    ip_data = data.get('data', {}).get(ip, {})
                    severity = ip_data.get('severity', '')
                    
                    is_malicious = severity in ['critical', 'high', 'medium']
                    
                    return {
                        'is_malicious': is_malicious,
                        'details': {
                            'severity': severity,
                            'judgments': ip_data.get('judgments', []),
                            'tags': ip_data.get('tags', []),
                            'confidence': ip_data.get('confidence', 0)
                        }
                    }
        except Exception as e:
            self.logger.warning(f"ThreatBook IP query failed: {e}")
        
        return None
    
    def _query_threatbook_domain(self, domain: str) -> Dict:
        """查询微步在线域名威胁情报"""
        try:
            params = {
                'apikey': self.config.api.threatbook_api_key,
                'resource': domain
            }
            response = requests.get(
                f'{self.config.api.threatbook_api_url}/domain/report',
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 0:
                    domain_data = data.get('data', {}).get(domain, {})
                    severity = domain_data.get('severity', '')
                    
                    is_malicious = severity in ['critical', 'high', 'medium']
                    
                    return {
                        'is_malicious': is_malicious,
                        'details': {
                            'severity': severity,
                            'judgments': domain_data.get('judgments', []),
                            'tags': domain_data.get('tags', [])
                        }
                    }
        except Exception as e:
            self.logger.warning(f"ThreatBook domain query failed: {e}")
        
        return None
    
    def _query_threatbook_url(self, url: str) -> Dict:
        """查询微步在线URL威胁情报"""
        try:
            params = {
                'apikey': self.config.api.threatbook_api_key,
                'url': url
            }
            response = requests.get(
                f'{self.config.api.threatbook_api_url}/url/report',
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                if data.get('response_code') == 0:
                    url_data = data.get('data', {}).get(url, {})
                    severity = url_data.get('severity', '')
                    
                    is_malicious = severity in ['critical', 'high', 'medium']
                    
                    return {
                        'is_malicious': is_malicious,
                        'details': {
                            'severity': severity,
                            'judgments': url_data.get('judgments', []),
                            'threat_level': url_data.get('threat_level', 'unknown')
                        }
                    }
        except Exception as e:
            self.logger.warning(f"ThreatBook URL query failed: {e}")
        
        return None
    
    def _update_local_ioc(self, ioc_type: str, value: str):
        """更新本地IOC数据库（缓存云端查询结果）"""
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            ioc_file = os.path.join(base_dir, 'config', 'ioc_database.json')
            
            if os.path.exists(ioc_file):
                with open(ioc_file, 'r', encoding='utf-8') as f:
                    ioc_data = json.load(f)
            else:
                ioc_data = {
                    'malicious_ips': [],
                    'malicious_domains': [],
                    'malicious_urls': [],
                    'malicious_hashes': []
                }
            
            type_mapping = {
                'ip': 'malicious_ips',
                'domain': 'malicious_domains',
                'url': 'malicious_urls'
            }
            
            if ioc_type in type_mapping:
                key = type_mapping[ioc_type]
                if value not in ioc_data.get(key, []):
                    ioc_data.setdefault(key, []).append(value)
                    
                    with open(ioc_file, 'w', encoding='utf-8') as f:
                        json.dump(ioc_data, f, indent=2, ensure_ascii=False)
                    
                    if ioc_type == 'ip':
                        KNOWN_MALICIOUS_IOCS['ips'].add(value)
                    elif ioc_type == 'domain':
                        KNOWN_MALICIOUS_IOCS['domains'].add(value)
                    elif ioc_type == 'url':
                        KNOWN_MALICIOUS_IOCS['urls'].add(value)
                    
                    self.logger.info(f"Updated local IOC: {ioc_type}={value}")
        except Exception as e:
            self.logger.error(f"Failed to update local IOC: {e}")


ioc_query_service = IOCQueryService()


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
        vt_api_key: str = ""
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
                    self._get_ip_geolocation, source_info['source_ip']
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
            for url in urls[:5]:  # 最多分析5个URL
                future = self.executor.submit(self._analyze_single_url, url)
                url_futures.append(future)
            
            try:
                for future in as_completed(url_futures, timeout=30):
                    try:
                        url_analysis = future.result(timeout=5)
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
                    except Exception as e:
                        self.logger.warning(f"URL analysis failed: {e}")
            except Exception as e:
                self.logger.warning(f"URL parallel processing timeout: {e}")
        
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
        first_ip_found = None
        
        # Pattern to match both IPv4 and IPv6 addresses in brackets
        ip_pattern = r'\[([^\]]+)\]'
        
        for i, line in enumerate(reversed(received_chain)):
            ip_match = re.search(ip_pattern, line)
            if ip_match:
                potential_ip = ip_match.group(1)
                # Validate if it's a valid IP address (IPv4 or IPv6)
                if self._is_valid_ip_address(potential_ip):
                    # Remember the first IP we find (for fallback)
                    if first_ip_found is None:
                        first_ip_found = potential_ip
                    
                    # If it's not private, add to path and consider as source
                    if not self._is_private_ip(potential_ip):
                        path.append(potential_ip)
                        # The first non-private IP we find (going bottom-up) is the source
                        if source_ip == "Unknown":
                            source_ip = potential_ip
        
        # If we didn't find any non-private IP, use the first IP we found as fallback
        if source_ip == "Unknown" and first_ip_found is not None:
            source_ip = first_ip_found
            # Also add it to the path for consistency
            if first_ip_found not in path:
                path.append(first_ip_found)
        
        return {
            "source_ip": source_ip,
            "full_path": "->".join(reversed(path)),
            "hops": list(reversed(path))
        }
    
    def _is_valid_ip_address(self, ip: str) -> bool:
        """Validate if string is a valid IP address (IPv4 or IPv6)"""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        # IPv6 pattern (simplified, covers common formats)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        ipv6_pattern_compressed = r'^([0-9a-fA-F]{1,4}:)*::([0-9a-fA-F]{1,4}:)*[0-9a-fA-F]{1,4}$'
        
        if re.match(ipv4_pattern, ip):
            # Additional validation for IPv4 octets
            parts = ip.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        elif re.match(ipv6_pattern, ip) or re.match(ipv6_pattern_compressed, ip):
            return True
        elif ':' in ip and ip.count(':') >= 2:  # Basic IPv6 check
            return True
            
        return False
    
    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is private (IPv4 or IPv6)"""
        # IPv4 private addresses
        if '.' in ip:
            parts = ip.split('.')
            if len(parts) == 4:
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
        
        # IPv6 private/link-local addresses
        elif ':' in ip:
            # Check for link-local (fe80::/10)
            if ip.lower().startswith('fe80:'):
                return True
            # Check for unique local (fc00::/7)
            if ip.lower().startswith('fc00:') or ip.lower().startswith('fd00:'):
                return True
            # Check for loopback (::1)
            if ip == '::1':
                return True
        
        return False
    
    def _get_ip_geolocation(self, ip: str, ip_api_url: str = None) -> Dict:
        """Get IP geolocation info with caching and timeout"""
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
            response = requests.get(
                f'https://opendata.baidu.com/api.php?query={ip}&co=&resource_id=6006&oe=utf8',
                timeout=IP_API_TIMEOUT
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '0' and data.get('data'):
                    location_info = data['data'][0]
                    location_str = location_info.get('location', '')
                    locations['country'] = location_str if location_str else 'Unknown'
                    locations['city'] = location_info.get('city', 'Unknown')
        except requests.Timeout:
            self.logger.warning(f"IP geolocation timeout for {ip}")
        except Exception as e:
            self.logger.error(f"IP geolocation query failed: {e}")
        
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
            
            # 使用正确的whois模块API
            try:
                # python-whois 库的正确用法
                w = whois.query(domain)
            except Exception:
                # 备用：使用whois.whois()函数
                try:
                    w = whois.whois(domain)
                except Exception:
                    w = None
            
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
        """
        Query single DNSBL server with timeout
        
        修复：使用socket.create_connection超时而非全局设置
        """
        query = f"{reversed_ip}.{server}"
        try:
            # 使用线程超时而非全局socket超时
            import concurrent.futures
            
            def dns_query():
                return socket.gethostbyname(query)
            
            with concurrent.futures.ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(dns_query)
                try:
                    future.result(timeout=BLACKLIST_TIMEOUT)
                    return True, name
                except concurrent.futures.TimeoutError:
                    return False, name
                except socket.gaierror:
                    return False, name
        except Exception:
            return False, name
