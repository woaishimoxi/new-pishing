"""
Feature Extraction Service
Extract features from parsed email data
"""
import re
import time
import json
import os
import whois
import requests
from urllib.parse import urlparse, parse_qs
from typing import Dict, List, Optional, Set
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config, FeatureExtractionError


URGENT_KEYWORDS = [
    '紧急', '立即', '24小时', '尽快', '马上', 'urgent', 'immediately',
    'activate', 'verify', 'confirm', 'suspended', 'frozen', '限', '过期',
    '警告', '危险', '风险', 'alert', 'warning', 'action required'
]

FINANCIAL_KEYWORDS = [
    '转账', '汇款', '账户', '密码', '银行卡', '付款', '支付', '充值', '提现',
    'transfer', 'payment', 'bank account', 'wire', 'refund', 'invoice',
    'credit card', 'debit card', 'paypal', 'bitcoin', 'cryptocurrency'
]

SHORT_URL_SERVICES = [
    'bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tiny.cc'
]

BRAND_NAMES = [
    'paypal', 'microsoft', 'google', 'apple', 'amazon', 'facebook',
    'netflix', 'dropbox', 'linkedin', 'twitter', 'instagram',
    'icbc', 'ccb', 'abc', 'boc', 'bank of china', 'alipay', 'wechat'
]

DOMAIN_AGE_CACHE: Dict[str, float] = {}


class FeatureExtractionService:
    """
    Feature extraction service
    Extract features from parsed email data
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
    
    def extract_features(
        self,
        parsed_email: Dict,
        vt_api_key: str = "",
        vt_api_url: str = "https://www.virustotal.com/vtapi/v2/url/report"
    ) -> Dict:
        """
        Extract all features from parsed email
        
        Args:
            parsed_email: Parsed email data
            vt_api_key: VirusTotal API key
            vt_api_url: VirusTotal API URL
            
        Returns:
            Feature vector dictionary
        """
        header_features = self._extract_header_features(parsed_email)
        
        urls = parsed_email.get('urls', [])
        url_features_list = [self._extract_url_features(url, vt_api_key, vt_api_url) for url in urls]
        aggregated_url_features = self._aggregate_url_features(url_features_list)
        
        body = parsed_email.get('body', '')
        html_body = parsed_email.get('html_body', '')
        subject = parsed_email.get('subject', '')
        text_features = self._extract_text_features(body + html_body, subject)
        
        attachment_features = self._extract_attachment_features(parsed_email, vt_api_key)
        
        html_features = self._extract_html_features(parsed_email)
        
        feature_vector = {
            **header_features,
            **aggregated_url_features,
            **text_features,
            **attachment_features,
            **html_features,
            'url_count': len(urls),
        }
        
        return feature_vector
    
    def _extract_header_features(self, parsed_email: Dict) -> Dict:
        """Extract email header features"""
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
        
        from_email = parsed_email.get('from_email', '')
        from_domain = from_email.split('@')[-1].lower() if '@' in from_email else ''
        
        if from_domain:
            domain_parts = from_domain.split('.')
            if len(domain_parts) >= 2:
                top_level_domain = '.'.join(domain_parts[-2:])
            else:
                top_level_domain = from_domain
        else:
            top_level_domain = from_domain
        
        trusted_senders = set(self.config.whitelist.trusted_senders)
        trusted_domains = set(self.config.whitelist.trusted_domains)
        
        is_trusted = from_email.lower() in trusted_senders or top_level_domain in trusted_domains
        
        if is_trusted:
            features['is_suspicious_from_domain'] = 0
        else:
            for keyword in self.config.whitelist.suspicious_keywords:
                if keyword in top_level_domain:
                    features['is_suspicious_from_domain'] = 1
                    break
            
            high_risk_patterns = ['suspicious', 'phish', 'scam', 'fraud', 'hack']
            for pattern in high_risk_patterns:
                if pattern in top_level_domain.lower():
                    features['is_suspicious_from_domain'] = 1
                    break
        
        received_chain = parsed_email.get('received_chain', [])
        features['received_hops_count'] = len(received_chain)
        
        headers = parsed_email.get('headers', {})
        if headers.get('spf_result') == 'fail':
            features['spf_fail'] = 1
        if headers.get('dkim_result') == 'fail':
            features['dkim_fail'] = 1
        if headers.get('dmarc_result') == 'fail':
            features['dmarc_fail'] = 1
        
        from_display_name = parsed_email.get('from_display_name', '')
        if from_display_name:
            for brand in BRAND_NAMES:
                if brand.lower() in from_display_name.lower():
                    if brand.lower() not in from_domain.lower():
                        features['from_display_name_mismatch'] = 1
                        break
        
        subject = parsed_email.get('subject', '').lower()
        if from_domain and from_domain in subject:
            features['from_domain_in_subject'] = 1
        
        return features
    
    def _extract_url_features(
        self,
        url: str,
        vt_api_key: str = "",
        vt_api_url: str = "https://www.virustotal.com/vtapi/v2/url/report"
    ) -> Dict:
        """Extract features for a single URL"""
        features = {
            'domain_age_days': 3650,
            'has_https': int(url.startswith('https')),
            'is_short_url': self._is_short_url(url),
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
            
            domain_clean = domain.split(':')[0]
            
            ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
            if re.match(ip_pattern, domain_clean):
                features['is_ip_address'] = 1
            
            if ':' in domain:
                port = domain.split(':')[-1]
                if port not in ['80', '443', '8080']:
                    features['has_port'] = 1
            
            domain_parts = domain_clean.split('.')
            if len(domain_parts) >= 2:
                top_level_domain = '.'.join(domain_parts[-2:])
            else:
                top_level_domain = domain_clean
            
            features['domain_age_days'] = self._get_domain_age(top_level_domain)
            
            sld = domain_clean.split('.')[0]
            if any(c.isdigit() for c in sld) or '-' in sld:
                features['has_mixed_sld'] = 1
            else:
                features['has_mixed_sld'] = 0
            
            features['domain_length'] = len(domain_clean)
            
            if '@' in url:
                features['has_at_symbol'] = 1
            
            suspicious_params = ['redirect', 'url', 'link', 'goto', 'return', 'next', 'auth', 'token']
            query_lower = query.lower()
            if any(param in query_lower for param in suspicious_params):
                features['has_suspicious_params'] = 1
            
            parts = domain_clean.split('.')
            if len(parts) > 3:
                features['has_subdomain'] = 1
            
            features['path_depth'] = path.count('/')
            features['query_length'] = len(query)
            
            if vt_api_key:
                features['vt_detection_ratio'] = self._query_virustotal(url, vt_api_key, vt_api_url)
            
        except Exception:
            pass
        
        return features
    
    def _is_short_url(self, url: str) -> bool:
        """Check if URL is a short URL"""
        for service in SHORT_URL_SERVICES:
            if service in url.lower():
                return True
        return False
    
    def _get_domain_age(self, domain: str) -> float:
        """Get domain age in days"""
        global DOMAIN_AGE_CACHE
        
        if domain in DOMAIN_AGE_CACHE:
            return DOMAIN_AGE_CACHE[domain]
        
        domain_parts = domain.split('.')
        if len(domain_parts) >= 2:
            registered_domain = '.'.join(domain_parts[-2:])
            if registered_domain in set(self.config.whitelist.trusted_domains):
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
                except Exception:
                    pass
        except Exception:
            pass
        
        return 3650.0
    
    def _query_virustotal(
        self,
        url: str,
        vt_api_key: str,
        vt_api_url: str
    ) -> float:
        """Query VirusTotal for URL detection ratio"""
        if not vt_api_key or vt_api_key in ['test_key', 'test', 'your_api_key', '']:
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
            self.logger.debug(f"VirusTotal query skipped for {url[:50]}: {type(e).__name__}")
        
        return 0.0
    
    def _aggregate_url_features(self, url_features_list: List[Dict]) -> Dict:
        """Aggregate URL features from multiple URLs"""
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
    
    def _extract_text_features(self, body: str, subject: str = "") -> Dict:
        """Extract text features - improved version"""
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
        
        # 移除HTML标签和CSS样式，只保留纯文本
        clean_text = re.sub(r'<style[^>]*>.*?</style>', '', body, flags=re.DOTALL | re.IGNORECASE)
        clean_text = re.sub(r'<script[^>]*>.*?</script>', '', clean_text, flags=re.DOTALL | re.IGNORECASE)
        clean_text = re.sub(r'<[^>]+>', ' ', clean_text)
        clean_text = re.sub(r'\s+', ' ', clean_text).strip()
        
        # 移除CSS中的 !important 和注释
        text_for_analysis = re.sub(r'!important', '', clean_text, flags=re.IGNORECASE)
        text_for_analysis = re.sub(r'/\*.*?\*/', '', text_for_analysis, flags=re.DOTALL)
        
        text = text_for_analysis + " " + subject
        
        urgent_count = sum(1 for kw in URGENT_KEYWORDS if kw.lower() in text.lower())
        features['urgent_keywords_count'] = urgent_count
        
        financial_count = sum(1 for kw in FINANCIAL_KEYWORDS if kw.lower() in text.lower())
        features['financial_keywords_count'] = financial_count
        
        features['text_length'] = len(text)
        # 只计算纯文本中的感叹号，排除CSS !important
        features['exclamation_count'] = text.count('!')
        
        letters = ''.join(c for c in text if c.isalpha())
        if letters:
            features['caps_ratio'] = sum(1 for c in letters if c.isupper()) / len(letters)
        
        urgency_factors = [
            min(urgent_count / 5, 1),
            min(financial_count / 3, 1),
            min(features['exclamation_count'] / 5, 1),
            min(features['caps_ratio'], 1)
        ]
        features['urgency_score'] = sum(urgency_factors) / len(urgency_factors)
        
        return features
    
    def _extract_attachment_features(
        self,
        parsed_email: Dict,
        vt_api_key: str = ""
    ) -> Dict:
        """Extract attachment features"""
        features = {
            'attachment_count': 0,
            'has_suspicious_attachment': 0,
            'has_executable_attachment': 0,
            'total_attachment_size': 0,
            'has_double_extension': 0,
            'sandbox_detected': 0,
            'max_sandbox_detection_ratio': 0.0,
            'has_sandbox_analysis': 0,
            'attachment_risk_score': 0.0,
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
            
            ext = '.' + filename.rsplit('.', 1)[-1] if '.' in filename else ''
            if ext in ['.exe', '.bat', '.cmd', '.com', '.scr', '.vbs', '.js', '.ps1', '.msi', '.hta']:
                features['has_executable_attachment'] = 1
                attachment_risk += 10.0
            elif ext in ['.zip', '.rar', '.7z', '.tar', '.gz']:
                attachment_risk += 3.0
            elif ext in ['.pdf', '.doc', '.docx', '.xls', '.xlsx']:
                attachment_risk += 1.0
            
            parts = filename.split('.')
            if len(parts) > 2:
                if parts[-2] in ['.pdf', '.doc', '.xls', '.jpg', '.png', '.txt', '.zip']:
                    features['has_double_extension'] = 1
                    attachment_risk += 7.0
        
        features['total_attachment_size'] = total_size
        features['sandbox_detected'] = 1 if sandbox_detected else 0
        features['max_sandbox_detection_ratio'] = max_detection_ratio
        features['has_sandbox_analysis'] = 1 if sandbox_analyzed else 0
        features['attachment_risk_score'] = min(10.0, max(0.0, attachment_risk))
        
        return features
    
    def _extract_html_features(self, parsed_email: Dict) -> Dict:
        """Extract HTML features"""
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
        
        for link in html_links:
            if link.get('type') == 'link' and 'risk' in link:
                features['has_hidden_links'] = 1
                break
        
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
