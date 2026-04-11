#!/usr/bin/env python3
"""
溯源分析模块 - 增强版
按照5个维度进行完整的溯源分析：
1. 攻击目标 (收信人)
2. IP来源与传播链
3. 攻击特性 (社会工程学)
4. 攻击载体
5. 攻击动机与目标
"""
import re
import json
import requests
from typing import Dict, List, Optional
from urllib.parse import urlparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config


# 社会工程学关键词
SOCIAL_ENGINEERING_KEYWORDS = {
    'urgency': {
        'en': ['urgent', 'immediate', 'asap', 'expires', 'deadline', 'limited time',
               'act now', 'right away', 'within 24 hours', 'last chance'],
        'zh': ['紧急', '立即', '马上', '尽快', '过期', '截止', '限时', '马上处理', '24小时内', '最后机会']
    },
    'fear': {
        'en': ['suspended', 'blocked', 'compromised', 'hacked', 'unauthorized', 'fraud',
               'suspicious activity', 'security alert', 'account locked', 'virus'],
        'zh': ['冻结', '封禁', '泄露', '被盗', '异常', '警告', '风险', '锁定', '病毒', '感染']
    },
    'reward': {
        'en': ['congratulations', 'winner', 'prize', 'gift', 'bonus', 'free',
               'refund', 'reward', 'lottery', 'selected'],
        'zh': ['恭喜', '中奖', '奖励', '礼品', '免费', '退款', '抽奖', '选中', '补贴', '红包']
    },
    'authority': {
        'en': ['administrator', 'support team', 'security team', 'hr department',
               'it department', 'management', 'ceo', 'director'],
        'zh': ['管理员', '客服', '安全团队', '人事部', '技术部', '管理层', 'CEO', '总监', '财务部']
    },
    'generic': {
        'en': ['dear user', 'dear customer', 'dear sir', 'dear madam',
               'valued customer', 'dear colleague'],
        'zh': ['尊敬的用户', '亲爱的客户', '尊敬的先生', '尊敬的女士', '尊敬的同事', '各位同事']
    }
}

# 危险文件扩展名
DANGEROUS_EXTENSIONS = [
    '.exe', '.scr', '.bat', '.cmd', '.com', '.pif', '.vbs', '.vbe',
    '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.hta', '.cpl',
    '.docm', '.xlsm', '.pptm', '.dotm', '.zip', '.rar', '.7z'
]

# 短链接域名
SHORT_URL_DOMAINS = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd',
    'buff.ly', 'adf.ly', 'bl.ink', 'lnkd.in', 't.cn', 'url.cn'
]


class TracebackAnalyzer:
    """
    增强版溯源分析器
    提供5个维度的深度分析
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
    
    def _check_url_threatbook(self, url: str, api_key: str, api_url: str) -> Dict:
        """
        调用微步在线API检测URL
        """
        result = {
            'checked': False,
            'positives': 0,
            'total': 0,
            'detection_ratio': 0.0,
            'threat_level': 'unknown',
            'threat_types': []
        }
        
        if not api_key:
            return result
        
        try:
            parsed = urlparse(url if url.startswith('http') else 'http://' + url)
            domain = parsed.netloc.split(':')[0]
            
            if not domain:
                return result
            
            tb_api_url = 'https://api.threatbook.cn/v3/domain/query'
            
            params = {
                'apikey': api_key,
                'resource': domain
            }
            
            response = requests.get(
                tb_api_url,
                params=params,
                timeout=15
            )
            
            if response.status_code == 200:
                data = response.json()
                
                if data.get('response_code') == 0:
                    detail = data.get('data', {}).get('detail', {})
                    threat_info = detail.get('threat_tags', {})
                    threat_types = threat_info.get('threat_types', [])
                    
                    result['checked'] = True
                    result['threat_types'] = threat_types
                    
                    if threat_types:
                        result['positives'] = len(threat_types)
                        result['threat_level'] = 'malicious'
                        result['detection_ratio'] = 1.0
                    else:
                        result['threat_level'] = 'clean'
                        result['detection_ratio'] = 0.0
                    
                    tags = detail.get('tags', [])
                    if tags:
                        result['total'] = len(tags)
                        
                    severity = detail.get('severity', '')
                    if severity in ['critical', 'high']:
                        result['threat_level'] = 'malicious'
                    elif severity == 'medium':
                        result['threat_level'] = 'suspicious'
                        
        except requests.exceptions.Timeout:
            self.logger.debug(f"ThreatBook API timeout for {url}")
        except Exception as e:
            self.logger.debug(f"ThreatBook API error: {e}")
        
        return result
    
    def analyze(self, parsed_email: Dict, saved_traceback: Dict = None) -> Dict:
        """
        执行完整的溯源分析
        """
        report = {
            'dimensions': {},
            'risk_score': 0,
            'summary': ''
        }
        
        # 维度1: 攻击目标
        report['dimensions']['targets'] = self._analyze_targets(parsed_email)
        
        # 维度2: IP来源与传播链
        report['dimensions']['source_chain'] = self._analyze_source_chain(parsed_email, saved_traceback)
        
        # 维度3: 攻击特性（社会工程学）
        report['dimensions']['social_engineering'] = self._analyze_social_engineering(parsed_email)
        
        # 维度4: 攻击载体
        report['dimensions']['attack_vectors'] = self._analyze_attack_vectors(parsed_email)
        
        # 维度5: 攻击动机
        report['dimensions']['motivation'] = self._analyze_motivation(report['dimensions'])
        
        # 计算风险评分
        report['risk_score'] = self._calculate_risk_score(report['dimensions'])
        
        # 生成摘要
        report['summary'] = self._generate_summary(report['dimensions'])
        
        return report
    
    def _analyze_targets(self, parsed_email: Dict) -> Dict:
        """分析攻击目标（收信人）"""
        targets = {
            'recipients': [],
            'total_count': 0,
            'analysis': '',
            'risk_level': 'low'
        }
        
        to_field = parsed_email.get('to', '')
        cc_field = parsed_email.get('cc', '')
        
        to_emails = self._extract_emails(to_field)
        cc_emails = self._extract_emails(cc_field)
        
        targets['recipients'] = to_emails + cc_emails
        targets['total_count'] = len(targets['recipients'])
        
        if targets['total_count'] == 1:
            targets['analysis'] = '定向攻击：单个目标，可能是针对性钓鱼'
            targets['risk_level'] = 'medium'
        elif targets['total_count'] <= 5:
            targets['analysis'] = '小范围攻击：少量目标，可能是部门级钓鱼'
            targets['risk_level'] = 'medium'
        elif targets['total_count'] > 5:
            targets['analysis'] = '广撒网攻击：大量目标，可能是批量钓鱼'
            targets['risk_level'] = 'low'
        
        for email in targets['recipients']:
            local_part = email.split('@')[0].lower() if '@' in email else ''
            if any(role in local_part for role in ['admin', 'finance', 'hr', 'ceo', 'director']):
                targets['analysis'] += ' [针对高管/关键岗位]'
                targets['risk_level'] = 'high'
                break
        
        return targets
    
    def _analyze_source_chain(self, parsed_email: Dict, saved_traceback: Dict = None) -> Dict:
        """分析IP来源与传播链"""
        chain = {
            'source_ip': 'Unknown',
            'geolocation': {},
            'hops': [],
            'full_path': '',
            'analysis': '',
            'risk_level': 'low'
        }
        
        if saved_traceback:
            email_source = saved_traceback.get('email_source', {})
            
            if email_source.get('source_ip') and email_source['source_ip'] != 'Unknown':
                chain['source_ip'] = email_source['source_ip']
                
                if email_source.get('geolocation'):
                    chain['geolocation'] = email_source['geolocation']
                
                if email_source.get('hops'):
                    chain['hops'] = [
                        {'ip': hop, 'server': None, 'time': None}
                        for hop in email_source['hops']
                    ]
                
                if email_source.get('full_path'):
                    chain['full_path'] = email_source['full_path']
                
                if email_source.get('blacklist_check', {}).get('is_blacklisted'):
                    chain['risk_level'] = 'high'
                    blacklists = email_source['blacklist_check'].get('blacklists', [])
                    chain['analysis'] = f'源IP被以下黑名单标记：{", ".join(blacklists)}'
                else:
                    country = chain['geolocation'].get('country', '')
                    if country and country not in ['China', 'United States', 'Japan', '']:
                        chain['risk_level'] = 'medium'
                        chain['analysis'] = f'源IP位于{country}，需注意跨境风险'
                    else:
                        chain['analysis'] = f'源IP: {chain["source_ip"]}，地理位置: {country or "未知"}'
                
                return chain
        
        received_chain = parsed_email.get('received_chain', [])
        
        if not received_chain:
            headers = parsed_email.get('headers', {})
            received_header = headers.get('received', '')
            if received_header:
                received_chain = [received_header]
        
        if not received_chain:
            chain['analysis'] = '无法提取传播链信息'
            return chain
        
        hops = []
        ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
        
        for i, received in enumerate(reversed(received_chain)):
            hop = {
                'step': i + 1,
                'raw': received[:200],
                'ip': None,
                'server': None,
                'time': None
            }
            
            ip_match = re.search(ip_pattern, received)
            if ip_match:
                ip = ip_match.group(1)
                if not self._is_private_ip(ip):
                    hop['ip'] = ip
            
            from_match = re.search(r'from\s+(\S+)', received, re.IGNORECASE)
            if from_match:
                hop['server'] = from_match.group(1).rstrip(';')
            
            time_match = re.search(r';\s*(.+)$', received)
            if time_match:
                hop['time'] = time_match.group(1).strip()
            
            hops.append(hop)
        
        chain['hops'] = hops
        
        for hop in hops:
            if hop['ip']:
                chain['source_ip'] = hop['ip']
                break
        
        if chain['source_ip'] != 'Unknown':
            chain['geolocation'] = self._get_ip_geolocation(chain['source_ip'])
            
            country = chain['geolocation'].get('country', '')
            if country and country not in ['China', 'United States', 'Japan', '']:
                chain['risk_level'] = 'medium'
                chain['analysis'] = f'源IP位于{country}，需注意跨境风险'
        
        chain['full_path'] = ' -> '.join([
            hop.get('server') or hop.get('ip') or '?'
            for hop in hops if hop.get('server') or hop.get('ip')
        ])
        
        return chain
    
    def _analyze_social_engineering(self, parsed_email: Dict) -> Dict:
        """分析社会工程学特征"""
        se = {
            'detected_keywords': [],
            'categories': [],
            'risk_level': 'low',
            'analysis': ''
        }
        
        subject = (parsed_email.get('subject') or '').lower()
        body = (parsed_email.get('body') or '').lower()
        full_text = subject + ' ' + body
        
        for category, keywords_dict in SOCIAL_ENGINEERING_KEYWORDS.items():
            all_keywords = keywords_dict.get('en', []) + keywords_dict.get('zh', [])
            
            for keyword in all_keywords:
                if keyword in full_text:
                    se['detected_keywords'].append({
                        'keyword': keyword,
                        'category': category
                    })
            
            if any(kw['category'] == category for kw in se['detected_keywords']):
                se['categories'].append(category)
        
        se['categories'] = list(set(se['categories']))
        
        if len(se['categories']) >= 3:
            se['risk_level'] = 'high'
            se['analysis'] = '检测到多种社会工程学手段，高度可疑'
        elif len(se['categories']) >= 1:
            se['risk_level'] = 'medium'
            se['analysis'] = f'检测到{", ".join(se["categories"])}特征'
        else:
            se['analysis'] = '未检测到明显的社会工程学特征'
        
        return se
    
    def _analyze_attack_vectors(self, parsed_email: Dict) -> Dict:
        """分析攻击载体"""
        vectors = {
            'malicious_links': [],
            'suspicious_attachments': [],
            'qr_codes': 0,
            'info_theft_request': False,
            'risk_level': 'low',
            'analysis': '',
            'threatbook_results': []
        }
        
        body = parsed_email.get('body', '') + parsed_email.get('html_body', '')
        urls = parsed_email.get('urls', [])
        attachments = parsed_email.get('attachments', [])
        
        tb_api_key = self.config.api.threatbook_api_key
        tb_api_url = self.config.api.threatbook_api_url
        
        for url in urls:
            link_info = {
                'url': url,
                'is_short_url': False,
                'is_ip_url': False,
                'domain': '',
                'threatbook_checked': False,
                'threatbook_malicious': False
            }
            
            try:
                parsed_url = urlparse(url if url.startswith('http') else 'http://' + url)
                domain = parsed_url.netloc.split(':')[0]
                link_info['domain'] = domain
                
                if any(short in domain for short in SHORT_URL_DOMAINS):
                    link_info['is_short_url'] = True
                
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                    link_info['is_ip_url'] = True
                
                if tb_api_key and url.startswith(('http://', 'https://')):
                    try:
                        tb_result = self._check_url_threatbook(url, tb_api_key, tb_api_url)
                        link_info['threatbook_checked'] = tb_result.get('checked', False)
                        link_info['threatbook_malicious'] = tb_result.get('positives', 0) > 0
                        link_info['threatbook_ratio'] = tb_result.get('detection_ratio', 0)
                        if tb_result.get('checked'):
                            vectors['threatbook_results'].append({
                                'url': url,
                                'positives': tb_result.get('positives', 0),
                                'total': tb_result.get('total', 0),
                                'threat_level': tb_result.get('threat_level', 'unknown')
                            })
                    except Exception as e:
                        self.logger.debug(f"ThreatBook check failed for {url}: {e}")
                
                if link_info['is_short_url'] or link_info['is_ip_url'] or link_info['threatbook_malicious']:
                    vectors['malicious_links'].append(link_info)
                    
            except:
                pass
        
        for att in attachments:
            filename = att.get('filename') or ''
            if filename and any(filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                vectors['suspicious_attachments'].append({
                    'filename': filename,
                    'risk': 'high' if filename.endswith(('.exe', '.scr', '.bat', '.ps1')) else 'medium'
                })
        
        if 'qr' in body.lower() or '二维码' in body:
            vectors['qr_codes'] = 1
        
        theft_patterns = [
            r'password.*enter|输入.*密码',
            r'credit card|信用卡',
            r'bank account|银行账户',
            r'social security|身份证',
            r'reply.*code|回复.*验证码'
        ]
        for pattern in theft_patterns:
            if re.search(pattern, body, re.IGNORECASE):
                vectors['info_theft_request'] = True
                break
        
        risk_factors = [
            len(vectors['malicious_links']),
            len(vectors['suspicious_attachments']),
            vectors['qr_codes'],
            1 if vectors['info_theft_request'] else 0
        ]
        
        if sum(risk_factors) >= 2:
            vectors['risk_level'] = 'high'
            vectors['analysis'] = '检测到多个攻击载体'
        elif sum(risk_factors) >= 1:
            vectors['risk_level'] = 'medium'
            if vectors['malicious_links']:
                vectors['analysis'] = '包含可疑链接'
            elif vectors['suspicious_attachments']:
                vectors['analysis'] = '包含可疑附件'
        else:
            vectors['analysis'] = '未检测到明显的攻击载体'
        
        return vectors
    
    def _analyze_motivation(self, dimensions: Dict) -> Dict:
        """分析攻击动机"""
        motivation = {
            'primary': 'unknown',
            'secondary': [],
            'confidence': 0,
            'analysis': ''
        }
        
        vectors = dimensions.get('attack_vectors', {})
        se = dimensions.get('social_engineering', {})
        
        if vectors.get('malicious_links'):
            for link in vectors['malicious_links']:
                domain = link.get('domain', '')
                if any(kw in domain for kw in ['login', 'signin', 'verify', 'account']):
                    motivation['primary'] = 'credential_theft'
                    motivation['confidence'] = 0.8
                    motivation['analysis'] = '链接指向登录页面，动机为窃取凭证'
                    break
            
            if motivation['primary'] == 'unknown':
                motivation['primary'] = 'malware_delivery'
                motivation['confidence'] = 0.6
                motivation['analysis'] = '包含外部链接，可能用于恶意跳转'
        
        if vectors.get('suspicious_attachments'):
            motivation['primary'] = 'malware_delivery'
            motivation['confidence'] = 0.7
            motivation['analysis'] = '包含可疑附件，动机为植入恶意软件'
        
        if 'fear' in se.get('categories', []):
            if motivation['primary'] == 'unknown':
                motivation['primary'] = 'credential_theft'
                motivation['confidence'] = 0.6
                motivation['analysis'] = '利用恐惧心理诱导用户操作'
        
        if 'reward' in se.get('categories', []):
            if motivation['primary'] == 'unknown':
                motivation['primary'] = 'financial_fraud'
                motivation['confidence'] = 0.5
                motivation['analysis'] = '利用利诱手段诱导用户'
        
        if 'authority' in se.get('categories', []):
            motivation['secondary'].append('authority_abuse')
            motivation['confidence'] = min(1.0, motivation['confidence'] + 0.2)
        
        motivation_map = {
            'credential_theft': '窃取凭证',
            'malware_delivery': '植入恶意软件',
            'financial_fraud': '财务诈骗',
            'data_exfiltration': '数据窃取',
            'unknown': '未知'
        }
        
        motivation['primary_label'] = motivation_map.get(motivation['primary'], '未知')
        
        return motivation
    
    def _extract_emails(self, field: str) -> List[str]:
        if not field:
            return []
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        return re.findall(email_pattern, (field or '').lower())
    
    def _is_private_ip(self, ip: str) -> bool:
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
        except ValueError:
            pass
        return False
    
    def _get_ip_geolocation(self, ip: str) -> Dict:
        try:
            response = requests.get(
                f'https://opendata.baidu.com/api.php?query={ip}&co=&resource_id=6006&oe=utf8',
                timeout=5
            )
            if response.status_code == 200:
                data = response.json()
                if data.get('status') == '0' and data.get('data'):
                    location_info = data['data'][0]
                    location_str = location_info.get('location', '')
                    return {
                        'ip': ip,
                        'country': location_str if location_str else 'Unknown',
                        'city': location_info.get('city', 'Unknown'),
                        'isp': location_info.get('isp', 'Unknown'),
                        'lat': None,
                        'lon': None
                    }
        except Exception as e:
            self.logger.warning(f"IP地理位置查询失败: {e}")
        return {'ip': ip, 'country': 'Unknown'}
    
    def _calculate_risk_score(self, dimensions: Dict) -> float:
        score = 0.0
        weights = {
            'targets': 0.1,
            'source_chain': 0.2,
            'social_engineering': 0.25,
            'attack_vectors': 0.35,
            'motivation': 0.1
        }
        risk_map = {'low': 0.2, 'medium': 0.5, 'high': 0.8}
        
        for dim_name, weight in weights.items():
            dim = dimensions.get(dim_name, {})
            risk_level = dim.get('risk_level', 'low')
            score += risk_map.get(risk_level, 0.2) * weight
        
        return round(score, 2)
    
    def _generate_summary(self, dimensions: Dict) -> str:
        parts = []
        
        targets = dimensions.get('targets', {})
        chain = dimensions.get('source_chain', {})
        se = dimensions.get('social_engineering', {})
        vectors = dimensions.get('attack_vectors', {})
        motivation = dimensions.get('motivation', {})
        
        if targets.get('analysis'):
            parts.append(f"攻击类型：{targets['analysis']}")
        
        if chain.get('source_ip') and chain['source_ip'] != 'Unknown':
            geo = chain.get('geolocation', {})
            country = geo.get('country', '未知')
            parts.append(f"来源：{chain['source_ip']} ({country})")
        
        if se.get('analysis'):
            parts.append(f"诱骗手段：{se['analysis']}")
        
        if vectors.get('analysis'):
            parts.append(f"攻击载体：{vectors['analysis']}")
        
        if motivation.get('primary_label'):
            parts.append(f"攻击动机：{motivation['primary_label']}")
        
        return '；'.join(parts) if parts else '未发现明显风险'


traceback_analyzer = TracebackAnalyzer()
