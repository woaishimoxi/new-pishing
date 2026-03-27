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
    
    def analyze(self, parsed_email: Dict) -> Dict:
        """
        执行完整的溯源分析
        
        Args:
            parsed_email: 解析后的邮件数据
            
        Returns:
            完整的溯源报告
        """
        report = {
            'dimensions': {},
            'risk_score': 0,
            'summary': ''
        }
        
        # 维度1: 攻击目标
        report['dimensions']['targets'] = self._analyze_targets(parsed_email)
        
        # 维度2: IP来源与传播链
        report['dimensions']['source_chain'] = self._analyze_source_chain(parsed_email)
        
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
    
    # ==================== 维度1: 攻击目标 ====================
    def _analyze_targets(self, parsed_email: Dict) -> Dict:
        """分析攻击目标（收信人）"""
        targets = {
            'recipients': [],
            'total_count': 0,
            'analysis': '',
            'risk_level': 'low'
        }
        
        # 提取收件人
        to_field = parsed_email.get('to', '')
        cc_field = parsed_email.get('cc', '')
        
        # 解析收件人邮箱
        to_emails = self._extract_emails(to_field)
        cc_emails = self._extract_emails(cc_field)
        
        targets['recipients'] = to_emails + cc_emails
        targets['total_count'] = len(targets['recipients'])
        
        # 分析攻击类型
        if targets['total_count'] == 1:
            targets['analysis'] = '定向攻击：单个目标，可能是针对性钓鱼'
            targets['risk_level'] = 'medium'
        elif targets['total_count'] <= 5:
            targets['analysis'] = '小范围攻击：少量目标，可能是部门级钓鱼'
            targets['risk_level'] = 'medium'
        elif targets['total_count'] > 5:
            targets['analysis'] = '广撒网攻击：大量目标，可能是批量钓鱼'
            targets['risk_level'] = 'low'
        
        # 检查是否针对特定角色
        for email in targets['recipients']:
            local_part = email.split('@')[0].lower() if '@' in email else ''
            if any(role in local_part for role in ['admin', 'finance', 'hr', 'ceo', 'director']):
                targets['analysis'] += ' [针对高管/关键岗位]'
                targets['risk_level'] = 'high'
                break
        
        return targets
    
    # ==================== 维度2: IP来源与传播链 ====================
    def _analyze_source_chain(self, parsed_email: Dict) -> Dict:
        """分析IP来源与传播链"""
        chain = {
            'source_ip': 'Unknown',
            'geolocation': {},
            'hops': [],
            'full_path': '',
            'analysis': '',
            'risk_level': 'low'
        }
        
        # 提取Received链
        received_chain = parsed_email.get('received_chain', [])
        
        if not received_chain:
            # 尝试从原始邮件头提取
            headers = parsed_email.get('headers', {})
            received_header = headers.get('received', '')
            if received_header:
                received_chain = [received_header]
        
        if not received_chain:
            chain['analysis'] = '无法提取传播链信息'
            return chain
        
        # 解析每条Received记录
        hops = []
        ip_pattern = r'\[(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\]'
        
        for i, received in enumerate(reversed(received_chain)):
            hop = {
                'step': i + 1,
                'raw': received[:200],  # 截取前200字符
                'ip': None,
                'server': None,
                'time': None
            }
            
            # 提取IP
            ip_match = re.search(ip_pattern, received)
            if ip_match:
                ip = ip_match.group(1)
                if not self._is_private_ip(ip):
                    hop['ip'] = ip
            
            # 提取服务器名
            from_match = re.search(r'from\s+(\S+)', received, re.IGNORECASE)
            if from_match:
                hop['server'] = from_match.group(1).rstrip(';')
            
            # 提取时间
            time_match = re.search(r';\s*(.+)$', received)
            if time_match:
                hop['time'] = time_match.group(1).strip()
            
            hops.append(hop)
        
        chain['hops'] = hops
        
        # 提取源IP（最早的非私有IP）
        for hop in hops:
            if hop['ip']:
                chain['source_ip'] = hop['ip']
                break
        
        # 查询源IP地理位置
        if chain['source_ip'] != 'Unknown':
            chain['geolocation'] = self._get_ip_geolocation(chain['source_ip'])
            
            # 分析风险
            country = chain['geolocation'].get('country', '')
            if country and country not in ['China', 'United States', 'Japan', '']:
                chain['risk_level'] = 'medium'
                chain['analysis'] = f'源IP位于{country}，需注意跨境风险'
        
        # 构建传播链路径
        chain['full_path'] = ' → '.join([
            hop.get('server') or hop.get('ip') or '?'
            for hop in hops if hop.get('server') or hop.get('ip')
        ])
        
        return chain
    
    # ==================== 维度3: 攻击特性（社会工程学）====================
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
        
        # 检测各类关键词
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
        
        # 去重
        se['categories'] = list(set(se['categories']))
        
        # 评估风险
        if len(se['categories']) >= 3:
            se['risk_level'] = 'high'
            se['analysis'] = '检测到多种社会工程学手段，高度可疑'
        elif len(se['categories']) >= 1:
            se['risk_level'] = 'medium'
            se['analysis'] = f'检测到{", ".join(se["categories"])}特征'
        else:
            se['analysis'] = '未检测到明显的社会工程学特征'
        
        return se
    
    # ==================== 维度4: 攻击载体 ====================
    def _analyze_attack_vectors(self, parsed_email: Dict) -> Dict:
        """分析攻击载体"""
        vectors = {
            'malicious_links': [],
            'suspicious_attachments': [],
            'qr_codes': 0,
            'info_theft_request': False,
            'risk_level': 'low',
            'analysis': ''
        }
        
        body = parsed_email.get('body', '') + parsed_email.get('html_body', '')
        urls = parsed_email.get('urls', [])
        attachments = parsed_email.get('attachments', [])
        
        # 分析链接
        for url in urls:
            link_info = {
                'url': url,
                'is_short_url': False,
                'is_ip_url': False,
                'domain': ''
            }
            
            try:
                parsed = urlparse(url if url.startswith('http') else 'http://' + url)
                domain = parsed.netloc.split(':')[0]
                link_info['domain'] = domain
                
                # 检查短链接
                if any(short in domain for short in SHORT_URL_DOMAINS):
                    link_info['is_short_url'] = True
                
                # 检查IP地址URL
                if re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', domain):
                    link_info['is_ip_url'] = True
                
                # 标记可疑链接
                if link_info['is_short_url'] or link_info['is_ip_url']:
                    vectors['malicious_links'].append(link_info)
                    
            except:
                pass
        
        # 分析附件
        for att in attachments:
            filename = att.get('filename') or ''
            if filename and any(filename.lower().endswith(ext) for ext in DANGEROUS_EXTENSIONS):
                vectors['suspicious_attachments'].append({
                    'filename': filename,
                    'risk': 'high' if filename.endswith(('.exe', '.scr', '.bat', '.ps1')) else 'medium'
                })
        
        # 检测二维码（简化检测）
        if 'qr' in body.lower() or '二维码' in body:
            vectors['qr_codes'] = 1
        
        # 检测信息窃取请求
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
        
        # 评估风险
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
    
    # ==================== 维度5: 攻击动机 ====================
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
        
        # 根据攻击载体推断动机
        if vectors.get('malicious_links'):
            # 检查链接是否指向登录页面
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
        
        # 根据社会工程学特征修正
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
        
        # 动机中文说明
        motivation_map = {
            'credential_theft': '窃取凭证',
            'malware_delivery': '植入恶意软件',
            'financial_fraud': '财务诈骗',
            'data_exfiltration': '数据窃取',
            'unknown': '未知'
        }
        
        motivation['primary_label'] = motivation_map.get(motivation['primary'], '未知')
        
        return motivation
    
    # ==================== 工具函数 ====================
    def _extract_emails(self, field: str) -> List[str]:
        """从邮件头字段提取邮箱地址"""
        if not field:
            return []
        
        email_pattern = r'[\w\.-]+@[\w\.-]+\.\w+'
        return re.findall(email_pattern, (field or '').lower())
    
    def _is_private_ip(self, ip: str) -> bool:
        """检查是否为私有IP"""
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
        """查询IP地理位置"""
        try:
            response = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
            if response.status_code == 200:
                data = response.json()
                return {
                    'ip': ip,
                    'country': data.get('country', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'isp': data.get('isp', 'Unknown'),
                    'lat': data.get('lat'),
                    'lon': data.get('lon')
                }
        except Exception as e:
            self.logger.warning(f"IP geolocation query failed: {e}")
        
        return {'ip': ip, 'country': 'Unknown'}
    
    def _calculate_risk_score(self, dimensions: Dict) -> float:
        """计算综合风险评分"""
        score = 0.0
        
        # 各维度权重
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
        """生成溯源摘要"""
        parts = []
        
        targets = dimensions.get('targets', {})
        chain = dimensions.get('source_chain', {})
        se = dimensions.get('social_engineering', {})
        vectors = dimensions.get('attack_vectors', {})
        motivation = dimensions.get('motivation', {})
        
        # 攻击目标
        if targets.get('analysis'):
            parts.append(f"攻击类型：{targets['analysis']}")
        
        # 来源
        if chain.get('source_ip') and chain['source_ip'] != 'Unknown':
            geo = chain.get('geolocation', {})
            country = geo.get('country', '未知')
            parts.append(f"来源：{chain['source_ip']} ({country})")
        
        # 社会工程学
        if se.get('analysis'):
            parts.append(f"诱骗手段：{se['analysis']}")
        
        # 攻击载体
        if vectors.get('analysis'):
            parts.append(f"攻击载体：{vectors['analysis']}")
        
        # 动机
        if motivation.get('primary_label'):
            parts.append(f"攻击动机：{motivation['primary_label']}")
        
        return '；'.join(parts) if parts else '未发现明显风险'


# 创建全局实例
traceback_analyzer = TracebackAnalyzer()
