"""
URL Analyzer Service
Analyze URL security risks with VirusTotal integration
"""
import re
import time
import whois
import requests
import hashlib
import json
from urllib.parse import urlparse
from typing import Dict, List, Tuple, Optional, Set
from datetime import datetime
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config


# 全局缓存
TRUSTED_DOMAINS: Set[str] = set()
SUSPICIOUS_DOMAIN_KEYWORDS: List[str] = []
BRAND_NAMES: List[str] = []
DOMAIN_AGE_CACHE: Dict = {}
_IOC_CACHE: Dict = {}
_CONFIG_LOADED = False


def _load_config():
    """Load whitelist and IOC config"""
    global TRUSTED_DOMAINS, SUSPICIOUS_DOMAIN_KEYWORDS, BRAND_NAMES, _CONFIG_LOADED, _IOC_CACHE
    
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
                SUSPICIOUS_DOMAIN_KEYWORDS = whitelist.get('suspicious_domain_keywords', [])
        except Exception as e:
            print(f"Failed to load whitelist: {e}")
    
    # 加载品牌名称
    BRAND_NAMES = [
        'paypal', 'google', 'microsoft', 'amazon', 'facebook', 'apple',
        'linkedin', 'twitter', 'instagram', 'netflix', 'dropbox',
        'alipay', 'wechat', 'taobao', 'jd', 'icbc', 'ccb', 'bank',
        'steam', 'epic', 'playstation', 'xbox', 'nintendo',
        'hsbc', 'citibank', 'jpmorgan', 'goldmansachs',
        'visa', 'mastercard', 'unionpay',
        'baidu', 'tencent', 'alibaba', 'bytedance', 'douyin', 'tiktok'
    ]
    
    # 加载IOC数据库
    ioc_file = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
        'config', 'ioc_database.json'
    )
    
    if os.path.exists(ioc_file):
        try:
            with open(ioc_file, 'r', encoding='utf-8') as f:
                _IOC_CACHE = json.load(f)
        except Exception as e:
            print(f"Failed to load IOC database: {e}")
    
    _CONFIG_LOADED = True


class URLAnalyzerService:
    """
    URL Analyzer Service
    Analyze URL security risks with VirusTotal integration
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.vt_api_key = self.config.api.virustotal_api_key
        self.vt_api_url = self.config.api.virustotal_api_url
        self.vt_cache: Dict[str, Dict] = {}
        
        # 加载配置
        _load_config()
    
    def check_virustotal(self, url: str) -> Dict:
        """
        Check URL against VirusTotal API
        
        Args:
            url: URL to check
            
        Returns:
            Dict with VT results
        """
        result = {
            'checked': False,
            'positives': 0,
            'total': 0,
            'detection_ratio': 0.0,
            'permalink': '',
            'error': None
        }
        
        if not self.vt_api_key:
            return result
        
        # 使用URL的MD5作为缓存键
        url_hash = hashlib.md5(url.encode()).hexdigest()
        if url_hash in self.vt_cache:
            return self.vt_cache[url_hash]
        
        try:
            params = {
                'apikey': self.vt_api_key,
                'resource': url
            }
            
            response = requests.get(self.vt_api_url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                response_code = data.get('response_code', 0)
                
                if response_code == 1:
                    result['checked'] = True
                    result['positives'] = data.get('positives', 0)
                    result['total'] = data.get('total', 0)
                    result['permalink'] = data.get('permalink', '')
                    
                    if result['total'] > 0:
                        result['detection_ratio'] = result['positives'] / result['total']
                else:
                    result['error'] = 'URL not found in VT database'
            else:
                result['error'] = f'VT API error: {response.status_code}'
                
        except requests.exceptions.Timeout:
            result['error'] = 'VT API timeout'
        except Exception as e:
            result['error'] = f'VT API error: {str(e)}'
        
        # 缓存结果
        self.vt_cache[url_hash] = result
        return result
    
    def is_valid_http_url(self, url: str) -> bool:
        """Check if URL is valid HTTP/HTTPS URL"""
        if not url or not isinstance(url, str):
            return False
        
        try:
            if not url.startswith(('http://', 'https://')):
                if '.' in url and not url.startswith(('cid:', 'mailto:', 'javascript:', 'data:')):
                    url = 'http://' + url
                else:
                    return False
            
            parsed = urlparse(url)
            
            if parsed.scheme not in ['http', 'https']:
                return False
            
            if not parsed.netloc:
                return False
            
            return True
        except Exception:
            return False
    
    def filter_urls(self, urls: List[str]) -> Tuple[List[str], List[Dict]]:
        """Filter URL list, separating valid HTTP URLs from non-HTTP URLs"""
        valid_urls = []
        skipped_urls = []
        
        for url in urls:
            if self.is_valid_http_url(url):
                valid_urls.append(url)
            else:
                skipped_info = {
                    'url': url[:100] if len(url) > 100 else url,
                    'reason': '非HTTP/HTTPS协议或无效URL'
                }
                
                if ':' in url:
                    scheme = url.split(':')[0].lower()
                    if scheme in ['cid', 'mailto', 'javascript', 'data', 'file']:
                        skipped_info['scheme'] = scheme
                        skipped_info['reason'] = f'{scheme}协议，跳过分析'
                
                skipped_urls.append(skipped_info)
        
        return valid_urls, skipped_urls
    
    def get_registered_domain(self, domain: str) -> str:
        """Extract registered domain (last two parts, e.g., example.com)"""
        parts = domain.lower().split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain.lower()
    
    def is_trusted_domain(self, domain: str) -> bool:
        """Check if domain is in whitelist"""
        registered = self.get_registered_domain(domain)
        return registered in TRUSTED_DOMAINS
    
    def check_domain_keywords(self, domain: str) -> List[str]:
        """Check if domain contains suspicious keywords"""
        domain_lower = domain.lower()
        found_keywords = []
        
        for keyword in SUSPICIOUS_DOMAIN_KEYWORDS:
            if keyword in domain_lower:
                found_keywords.append(keyword)
        
        return found_keywords
    
    def check_brand_abuse(self, domain: str) -> List[str]:
        """Check if domain abuses brand names"""
        domain_lower = domain.lower()
        abused_brands = []
        
        for brand in BRAND_NAMES:
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
    
    def check_ioc_patterns(self, domain: str, url: str = "") -> List[str]:
        """
        Check domain/URL against IOC patterns
        
        Returns:
            List of matched IOC patterns
        """
        matches = []
        
        # 检查域名模式
        domain_patterns = _IOC_CACHE.get('malicious_domain_patterns', [])
        for pattern in domain_patterns:
            try:
                if re.match(pattern, domain, re.IGNORECASE):
                    matches.append(f'域名匹配恶意模式: {pattern}')
            except re.error:
                pass
        
        # 检查URL模式
        if url:
            url_patterns = _IOC_CACHE.get('malicious_url_patterns', [])
            for pattern in url_patterns:
                try:
                    if re.match(pattern, url, re.IGNORECASE):
                        matches.append(f'URL匹配恶意模式: {pattern}')
                except re.error:
                    pass
        
        return matches
    
    def check_phishing_keywords(self, text: str) -> List[str]:
        """
        Check text for phishing keywords
        
        Returns:
            List of matched phishing keywords
        """
        matches = []
        text_lower = text.lower()
        
        keywords = _IOC_CACHE.get('known_phishing_keywords', [])
        for keyword in keywords:
            if keyword.lower() in text_lower:
                matches.append(keyword)
        
        return matches
    
    def get_domain_age(self, domain: str) -> Optional[float]:
        """Get domain age in days"""
        if domain in DOMAIN_AGE_CACHE:
            cached_value = DOMAIN_AGE_CACHE[domain]
            return cached_value
        
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
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            
            if isinstance(creation_date, datetime):
                age_days = (datetime.now() - creation_date).days
                if 0 <= age_days <= 10950:
                    DOMAIN_AGE_CACHE[domain] = float(age_days)
                    return float(age_days)
            
            DOMAIN_AGE_CACHE[domain] = None
            return None
            
        except Exception:
            DOMAIN_AGE_CACHE[domain] = None
            return None
    
    def analyze_single_url(self, url: str, check_whitelist: bool = True, use_vt: bool = True) -> Dict:
        """
        Analyze single URL for security risks
        
        Args:
            url: URL to analyze
            check_whitelist: Whether to check whitelist
            use_vt: Whether to use VirusTotal API
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
            'reasons': [],
            'virustotal': None  # 新增VirusTotal结果
        }
        
        if not self.is_valid_http_url(url):
            result['reasons'].append('无效的HTTP/HTTPS URL')
            result['risk_level'] = 'SKIP'
            return result
        
        result['is_valid'] = True
        
        try:
            parsed = urlparse(url if url.startswith(('http://', 'https://')) else 'http://' + url)
            domain = parsed.netloc.split(':')[0]
            result['domain'] = domain
            result['registered_domain'] = self.get_registered_domain(domain)
            result['has_https'] = parsed.scheme == 'https'
        except Exception as e:
            result['reasons'].append(f'URL解析失败: {str(e)}')
            result['risk_level'] = 'ERROR'
            return result
        
        if check_whitelist and self.is_trusted_domain(domain):
            result['is_whitelisted'] = True
            result['risk_level'] = 'SAFE'
            result['risk_score'] = 0
            result['reasons'].append(f'可信域名: {result["registered_domain"]}')
            
            age = self.get_domain_age(result['registered_domain'])
            if age is not None:
                result['domain_age_days'] = age
            
            return result
        
        risk_score = 0
        reasons = []
        
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        if re.match(ip_pattern, domain):
            result['is_ip_address'] = True
            risk_score += 40
            reasons.append('使用IP地址而非域名')
        
        domain_age = self.get_domain_age(result['registered_domain'])
        if domain_age is not None:
            result['domain_age_days'] = domain_age
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
            risk_score += 5
            reasons.append('无法查询域名年龄')
        
        suspicious_keywords = self.check_domain_keywords(domain)
        if suspicious_keywords:
            result['suspicious_keywords'] = suspicious_keywords
            risk_score += 50
            reasons.append(f'域名包含可疑关键词: {", ".join(suspicious_keywords)}')
        
        brand_abuse = self.check_brand_abuse(domain)
        if brand_abuse:
            result['brand_abuse'] = brand_abuse
            risk_score += 45
            reasons.append(f'疑似品牌滥用: {", ".join(brand_abuse)}')
        
        # IOC模式匹配检查
        ioc_matches = self.check_ioc_patterns(domain, url)
        if ioc_matches:
            risk_score += 40
            reasons.extend(ioc_matches[:3])  # 最多显示3个匹配
        
        if not result['has_https']:
            risk_score += 10
            reasons.append('未使用HTTPS加密')
        
        if len(url) > 200:
            risk_score += 5
            reasons.append('URL过长')
        
        # VirusTotal检查
        if use_vt and self.vt_api_key:
            vt_result = self.check_virustotal(url)
            result['virustotal'] = vt_result
            
            if vt_result['checked'] and vt_result['positives'] > 0:
                # 根据VT检测结果增加风险分数
                vt_ratio = vt_result['detection_ratio']
                if vt_ratio > 0.5:
                    risk_score += 50
                    reasons.append(f'VirusTotal检测到高风险（{vt_result["positives"]}/{vt_result["total"]}）')
                elif vt_ratio > 0.2:
                    risk_score += 30
                    reasons.append(f'VirusTotal检测到中风险（{vt_result["positives"]}/{vt_result["total"]}）')
                elif vt_ratio > 0:
                    risk_score += 15
                    reasons.append(f'VirusTotal检测到低风险（{vt_result["positives"]}/{vt_result["total"]}）')
        
        result['risk_score'] = min(risk_score, 100)
        
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
    
    def analyze_urls(self, urls: List[str], check_whitelist: bool = True, use_vt: bool = False) -> Dict:
        """
        Batch analyze URLs
        
        Args:
            urls: List of URLs to analyze
            check_whitelist: Whether to check whitelist
            use_vt: Whether to use VirusTotal API (default False for performance)
        """
        valid_urls, skipped_urls = self.filter_urls(urls)
        
        analysis_results = []
        high_risk_count = 0
        medium_risk_count = 0
        low_risk_count = 0
        safe_count = 0
        
        for url in valid_urls:
            result = self.analyze_single_url(url, check_whitelist, use_vt=use_vt)
            analysis_results.append(result)
            
            if result['risk_level'] == 'HIGH':
                high_risk_count += 1
            elif result['risk_level'] == 'MEDIUM':
                medium_risk_count += 1
            elif result['risk_level'] == 'LOW':
                low_risk_count += 1
            elif result['risk_level'] == 'SAFE':
                safe_count += 1
        
        max_risk_score = max([r['risk_score'] for r in analysis_results], default=0)
        
        risk_levels_priority = ['HIGH', 'MEDIUM', 'LOW', 'SAFE', 'UNKNOWN', 'SKIP']
        max_risk_level = 'UNKNOWN'
        for level in risk_levels_priority:
            if any(r['risk_level'] == level for r in analysis_results):
                max_risk_level = level
                break
        
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
    
    def quick_check_url(self, url: str) -> Tuple[str, int, List[str]]:
        """Quick check URL"""
        result = self.analyze_single_url(url)
        return result['risk_level'], result['risk_score'], result['reasons']
