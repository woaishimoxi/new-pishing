"""
Traceback Service
Email source tracing and analysis with correlation analysis
"""
import re
import time
import requests
import socket
import json
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple, Set
import whois
from datetime import datetime
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config


# 全局配置
TRUSTED_DOMAINS: Set[str] = set()
KNOWN_MALICIOUS_IOCS: Dict = {
    'ips': set(),
    'domains': set(),
    'urls': set(),
    'hashes': set(),
    'domain_patterns': [],
    'url_patterns': [],
    'ip_patterns': []
}
DOMAIN_AGE_CACHE: Dict = {}
_CONFIG_LOADED = False


def _load_config():
    """Load whitelist and IOC config"""
    global TRUSTED_DOMAINS, KNOWN_MALICIOUS_IOCS, _CONFIG_LOADED
    
    if _CONFIG_LOADED:
        return
    
    # 加载白名单
    whitelist_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        'config', 'whitelist.json'
    )
    
    if os.path.exists(whitelist_file):
        try:
            with open(whitelist_file, 'r', encoding='utf-8') as f:
                whitelist = json.load(f)
                TRUSTED_DOMAINS = set(whitelist.get('trusted_domains', []))
        except Exception as e:
            print(f"Failed to load whitelist: {e}")
    
    # 加载IOC数据库
    ioc_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        'config', 'ioc_database.json'
    )
    
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


class TracebackService:
    """
    Traceback service
    Email source tracing and analysis with correlation analysis
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        _load_config()
    
    def _load_ioc_database(self):
        """Load IOC database from config directory"""
        ioc_file = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            'config', 'ioc_database.json'
        )
        
        if os.path.exists(ioc_file):
            try:
                with open(ioc_file, 'r', encoding='utf-8') as f:
                    ioc_data = json.load(f)
                    KNOWN_MALICIOUS_IOCS['ips'].update(ioc_data.get('malicious_ips', []))
                    KNOWN_MALICIOUS_IOCS['domains'].update(ioc_data.get('malicious_domains', []))
                    KNOWN_MALICIOUS_IOCS['urls'].update(ioc_data.get('malicious_urls', []))
                    KNOWN_MALICIOUS_IOCS['hashes'].update(ioc_data.get('malicious_hashes', []))
                self.logger.info(f"Loaded {len(KNOWN_MALICIOUS_IOCS['ips'])} malicious IPs, "
                               f"{len(KNOWN_MALICIOUS_IOCS['domains'])} malicious domains")
            except Exception as e:
                self.logger.warning(f"Failed to load IOC database: {e}")
        else:
            self.logger.info("IOC database file not found, using empty database")
    
    def generate_report(
        self,
        parsed_email: Dict,
        vt_api_key: str = "",
        ip_api_url: str = 'http://ip-api.com/json/'
    ) -> Dict:
        """
        Generate complete traceback report with correlation analysis
        
        Args:
            parsed_email: Parsed email data
            vt_api_key: VirusTotal API key
            ip_api_url: IP geolocation API URL
            
        Returns:
            Complete traceback report with correlation analysis
        """
        report = {
            'email_source': {},
            'url_analysis': [],
            'risk_indicators': [],
            'correlation_analysis': {  # 新增：关联分析
                'attack_chain': [],
                'ioc_matches': [],
                'related_campaigns': [],
                'threat_score': 0
            },
            'ioc_matches': {  # 新增：IOC匹配结果
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
                geo_info = self._get_ip_geolocation(source_info['source_ip'], ip_api_url)
                report['email_source']['geolocation'] = geo_info
                
                blacklist_info = self._check_blacklist(source_info['source_ip'])
                report['email_source']['blacklist_check'] = blacklist_info
                
                if blacklist_info['is_blacklisted']:
                    report['risk_indicators'].append({
                        'type': 'BLACKLISTED_IP',
                        'description': f"源 IP {source_info['source_ip']} 被以下黑名单标记：{', '.join(blacklist_info['blacklists'])}",
                        'severity': 'high'
                    })
                    report['correlation_analysis']['ioc_matches'].append({
                        'type': 'ip',
                        'value': source_info['source_ip'],
                        'reason': 'Blacklisted IP'
                    })
                
                # IOC匹配：检查IP
                if source_info['source_ip'] in KNOWN_MALICIOUS_IOCS['ips']:
                    report['ioc_matches']['malicious_ips'].append(source_info['source_ip'])
                    report['correlation_analysis']['threat_score'] += 50
        
        # 分析URL
        urls = parsed_email.get('urls', [])
        for url in urls:
            url_analysis = {
                'url': url,
                'redirect_chain': [],
                'domain_info': {},
                'risks': []
            }
            
            redirect_chain = self._trace_url_redirects(url)
            if len(redirect_chain) > 1:
                url_analysis['redirect_chain'] = redirect_chain
                url_analysis['risks'].append({
                    'type': 'MULTIPLE_REDIRECTS',
                    'description': f"URL 经过 {len(redirect_chain)-1} 次跳转",
                    'severity': 'medium'
                })
            
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            domain = parsed.netloc.split(':')[0]
            if domain:
                domain_info = self._analyze_domain_info(domain)
                url_analysis['domain_info'] = domain_info
                
                if domain_info.get('age_days') and domain_info['age_days'] < 30:
                    url_analysis['risks'].append({
                        'type': 'NEW_DOMAIN',
                        'description': f"域名注册仅 {domain_info['age_days']} 天",
                        'severity': 'high'
                    })
                
                if '-' in domain or any(c.isdigit() for c in domain.split('.')[0]):
                    url_analysis['risks'].append({
                        'type': 'SUSPICIOUS_DOMAIN_PATTERN',
                        'description': "域名包含连字符或数字，可能存在仿冒嫌疑",
                        'severity': 'medium'
                    })
                
                # IOC匹配：检查域名
                if domain in KNOWN_MALICIOUS_IOCS['domains']:
                    report['ioc_matches']['malicious_domains'].append(domain)
                    report['correlation_analysis']['threat_score'] += 40
                
                # IOC匹配：检查域名模式
                for pattern in KNOWN_MALICIOUS_IOCS.get('domain_patterns', []):
                    try:
                        if re.match(pattern, domain, re.IGNORECASE):
                            report['ioc_matches']['suspicious_patterns'].append(f'域名匹配模式: {pattern}')
                            report['correlation_analysis']['threat_score'] += 25
                            break
                    except re.error:
                        pass
                
                # IOC匹配：检查URL
                if url in KNOWN_MALICIOUS_IOCS['urls']:
                    report['ioc_matches']['malicious_urls'].append(url)
                    report['correlation_analysis']['threat_score'] += 50
                
                # IOC匹配：检查URL模式
                for pattern in KNOWN_MALICIOUS_IOCS.get('url_patterns', []):
                    try:
                        if re.match(pattern, url, re.IGNORECASE):
                            report['ioc_matches']['suspicious_patterns'].append(f'URL匹配模式: {pattern}')
                            report['correlation_analysis']['threat_score'] += 20
                            break
                    except re.error:
                        pass
            
            report['url_analysis'].append(url_analysis)
        
        # 关联分析：构建攻击链
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
    
    def _build_attack_chain(self, email_source: Dict, url_analysis: List, parsed_email: Dict) -> List[Dict]:
        """
        Build attack chain from collected evidence
        
        Returns:
            List of attack chain steps
        """
        chain = []
        
        # Step 1: 邮件来源
        if email_source.get('source_ip'):
            chain.append({
                'step': 1,
                'type': 'email_source',
                'description': f'邮件来自 IP: {email_source["source_ip"]}',
                'details': {
                    'ip': email_source['source_ip'],
                    'geolocation': email_source.get('geolocation', {}),
                    'path': email_source.get('full_path', '')
                }
            })
        
        # Step 2: 发件人
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
        
        # Step 3: 恶意URL
        malicious_urls = [ua for ua in url_analysis if ua.get('risks')]
        if malicious_urls:
            chain.append({
                'step': 3,
                'type': 'malicious_urls',
                'description': f'发现 {len(malicious_urls)} 个可疑URL',
                'details': {
                    'urls': [ua['url'] for ua in malicious_urls[:5]]
                }
            })
        
        # Step 4: 攻击目标
        to_email = parsed_email.get('to', '')
        if to_email:
            chain.append({
                'step': 4,
                'type': 'target',
                'description': f'攻击目标: {to_email}',
                'details': {
                    'target': to_email
                }
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
        """Get IP geolocation info"""
        locations = {
            'ip': ip,
            'country': 'Unknown',
            'region': 'Unknown',
            'city': 'Unknown',
            'isp': 'Unknown'
        }
        
        try:
            response = requests.get(f'{ip_api_url}{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == 'success':
                    locations['country'] = data.get('country', 'Unknown')
                    locations['regionName'] = data.get('regionName', 'Unknown')
                    locations['city'] = data.get('city', 'Unknown')
                    locations['isp'] = data.get('isp', 'Unknown')
        except Exception as e:
            self.logger.error(f"IP geolocation query failed: {e}")
        
        return locations
    
    def _trace_url_redirects(self, initial_url: str, max_hops: int = 5) -> List[str]:
        """Trace URL redirect chain"""
        redirects = [initial_url]
        current_url = initial_url
        visited = {initial_url.lower()}
        
        for _ in range(max_hops):
            try:
                resp = requests.head(
                    current_url,
                    allow_redirects=False,
                    timeout=3,
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
            except requests.RequestException:
                break
        
        return redirects
    
    def _analyze_domain_info(self, domain: str) -> Dict:
        """Analyze domain info"""
        global DOMAIN_AGE_CACHE
        
        info = {
            'domain': domain,
            'is_valid': False,
            'has_mx_record': False,
            'registrar': 'Unknown',
            'creation_date': None,
            'expiry_date': None,
            'age_days': 0
        }
        
        if domain in DOMAIN_AGE_CACHE:
            cached_info = DOMAIN_AGE_CACHE[domain]
            info.update(cached_info)
            return info
        
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            registered_domain = '.'.join(domain_parts[-2:])
            if registered_domain in TRUSTED_DOMAINS:
                info['is_valid'] = True
                info['registrar'] = 'Trusted Domain'
                info['age_days'] = 3650
                DOMAIN_AGE_CACHE[domain] = info
                return info
        
        try:
            w = whois.get(domain)
            if not w or not hasattr(w, 'creation_date'):
                info['is_valid'] = True
                info['age_days'] = 3650
                DOMAIN_AGE_CACHE[domain] = info
                return info
            
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
                    info['creation_date'] = creation_date
                    info['age_days'] = int(age_seconds / 86400)
                except Exception:
                    info['age_days'] = 3650
            else:
                info['age_days'] = 3650
            
            expiry_date = w.expiration_date
            if isinstance(expiry_date, list):
                expiry_date = expiry_date[0]
            info['expiry_date'] = expiry_date
            
        except Exception:
            info['is_valid'] = True
            info['age_days'] = 3650
        
        DOMAIN_AGE_CACHE[domain] = info
        return info
    
    def _check_blacklist(self, ip: str) -> Dict:
        """Check if IP is blacklisted"""
        result = {
            'ip': ip,
            'is_blacklisted': False,
            'blacklists': []
        }
        
        dnsbl_servers = [
            ('zen.spamhaus.org', 'Spamhaus'),
            ('b.barracudacentral.org', 'Barracuda'),
            ('ubl.unsubscore.com', 'Unsubscribe'),
        ]
        
        try:
            reversed_ip = '.'.join(ip.split('.')[::-1])
            
            for server, name in dnsbl_servers:
                query = f"{reversed_ip}.{server}"
                try:
                    socket.gethostbyname(query)
                    result['is_blacklisted'] = True
                    result['blacklists'].append(name)
                except socket.gaierror:
                    pass
        except Exception as e:
            self.logger.error(f"Blacklist check failed: {e}")
        
        return result
