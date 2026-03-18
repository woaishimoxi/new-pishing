"""
Traceback Service
Email source tracing and analysis
"""
import re
import time
import requests
import socket
from urllib.parse import urljoin, urlparse
from typing import Dict, List, Optional, Tuple
import whois
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config


TRUSTED_DOMAINS = {
    'qq.com', 'qlogo.cn', 'mail.qq.com', 'weixin.qq.com',
    'steampowered.com', 'steamcommunity.com', 'steamstatic.com',
    'valvesoftware.com', 'google.com', 'microsoft.com',
    'facebook.com', 'baidu.com', 'taobao.com', 'jd.com'
}

DOMAIN_AGE_CACHE: Dict = {}


class TracebackService:
    """
    Traceback service
    Email source tracing and analysis
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
    
    def generate_report(
        self,
        parsed_email: Dict,
        vt_api_key: str = "",
        ip_api_url: str = 'http://ip-api.com/json/'
    ) -> Dict:
        """
        Generate complete traceback report
        
        Args:
            parsed_email: Parsed email data
            vt_api_key: VirusTotal API key
            ip_api_url: IP geolocation API URL
            
        Returns:
            Complete traceback report
        """
        report = {
            'email_source': {},
            'url_analysis': [],
            'risk_indicators': []
        }
        
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
                
                if domain_info['age_days'] < 30:
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
            
            report['url_analysis'].append(url_analysis)
        
        return report
    
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
