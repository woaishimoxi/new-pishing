"""
URL分析服务
借鉴LLMphish项目的URL检测逻辑
提供域名分析、可疑URL识别、品牌仿冒检测
"""
import re
from typing import Dict, List, Optional
from urllib.parse import urlparse
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config

logger = get_logger(__name__)

# 高风险顶级域名
HIGH_RISK_TLDS = [
    '.top', '.xyz', '.club', '.work', '.click', '.link',
    '.info', '.biz', '.site', '.online', '.website'
]

# 短链接服务
SHORT_URL_SERVICES = [
    'bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly',
    'is.gd', 'buff.ly', 'adf.ly', 'j.mp', 'tiny.cc'
]

# 品牌关键词及其官方域名
BRAND_DOMAINS = {
    'paypal': ['paypal.com', 'paypal.cn'],
    'apple': ['apple.com', 'icloud.com'],
    'microsoft': ['microsoft.com', 'office.com', 'outlook.com', 'live.com'],
    'google': ['google.com', 'gmail.com', 'google.cn'],
    'amazon': ['amazon.com', 'amazon.cn'],
    'facebook': ['facebook.com'],
    'netflix': ['netflix.com'],
    'dropbox': ['dropbox.com'],
    'linkedin': ['linkedin.com'],
    'twitter': ['twitter.com', 'x.com'],
    'instagram': ['instagram.com'],
    'alipay': ['alipay.com'],
    'wechat': ['wechat.com', 'weixin.qq.com'],
    'taobao': ['taobao.com'],
    'jd': ['jd.com', 'jd.hk'],
    'baidu': ['baidu.com'],
    'qq': ['qq.com', 'tencent.com'],
    '163': ['163.com', 'netease.com'],
    'sina': ['sina.com', 'weibo.com'],
    'wps': ['wps.cn', 'wps.com', 'kingsoft.com'],
    'douban': ['douban.com'],
    'zhihu': ['zhihu.com'],
    'bilibili': ['bilibili.com'],
    'bankofchina': ['boc.cn', 'bankofchina.com'],
    'icbc': ['icbc.com.cn'],
    'ccb': ['ccb.com'],
    'abc': ['abchina.com'],
    'cmb': ['cmbchina.com'],
}

# 可疑参数
SUSPICIOUS_PARAMS = [
    'redirect', 'url', 'link', 'goto', 'next', 'return', 'target'
]


class URLAnalyzerService:
    """URL分析服务"""
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.whitelist = self._load_whitelist()
    
    def _load_whitelist(self) -> set:
        """加载白名单"""
        whitelist = set()
        try:
            import json
            whitelist_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))),
                'config', 'whitelist.json'
            )
            if os.path.exists(whitelist_file):
                with open(whitelist_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    whitelist = set(data.get('trusted_domains', []))
        except Exception as e:
            self.logger.warning(f"加载白名单失败: {e}")
        return whitelist
    
    def analyze_url(self, url: str) -> Dict:
        """
        分析单个URL
        
        Returns:
            {
                'url': 原始URL,
                'domain': 域名,
                'is_valid': 是否有效,
                'is_trusted': 是否在白名单,
                'risk_level': 风险等级 (SAFE/LOW/MEDIUM/HIGH),
                'risk_score': 风险分数 (0-100),
                'risks': 风险列表,
                'domain_info': 域名信息
            }
        """
        result = {
            'url': url,
            'domain': '',
            'is_valid': False,
            'is_trusted': False,
            'risk_level': 'UNKNOWN',
            'risk_score': 0,
            'risks': [],
            'domain_info': {}
        }
        
        # 解析URL
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            
            parsed = urlparse(url)
            domain = parsed.netloc.split(':')[0]
            
            if not domain:
                return result
            
            result['domain'] = domain
            result['is_valid'] = True
            
            # 检查白名单
            base_domain = self._get_base_domain(domain)
            if base_domain in self.whitelist:
                result['is_trusted'] = True
                result['risk_level'] = 'SAFE'
                result['risk_score'] = 0
                return result
            
            # 计算风险
            risks = []
            risk_score = 0
            
            # 1. IP地址URL
            if self._is_ip_address(domain):
                risks.append('使用IP地址而非域名')
                risk_score += 30
            
            # 2. 高风险TLD
            if self._has_high_risk_tld(domain):
                risks.append('使用高风险顶级域名')
                risk_score += 20
            
            # 3. 短链接
            if self._is_short_url(url):
                risks.append('使用短链接服务')
                risk_score += 15
            
            # 4. 域名长度异常
            if len(domain) > 30:
                risks.append('域名过长')
                risk_score += 10
            
            # 5. 连字符过多
            if domain.count('-') > 2:
                risks.append('域名包含过多连字符')
                risk_score += 15
            
            # 6. 子域名过多
            if domain.count('.') > 3:
                risks.append('子域名层级过深')
                risk_score += 10
            
            # 7. 可疑参数
            if self._has_suspicious_params(parsed.query):
                risks.append('URL包含可疑重定向参数')
                risk_score += 20
            
            # 8. 品牌仿冒检测
            brand_risk = self._check_brand_impersonation(domain)
            if brand_risk:
                risks.append(brand_risk)
                risk_score += 25
            
            # 9. 域名包含数字
            if self._has_numbers_in_domain(domain):
                risks.append('域名包含数字（可能为仿冒）')
                risk_score += 10
            
            # 确定风险等级
            risk_score = min(100, risk_score)
            if risk_score >= 50:
                risk_level = 'HIGH'
            elif risk_score >= 30:
                risk_level = 'MEDIUM'
            elif risk_score >= 10:
                risk_level = 'LOW'
            else:
                risk_level = 'SAFE'
            
            result['risk_level'] = risk_level
            result['risk_score'] = risk_score
            result['risks'] = risks
            result['domain_info'] = {
                'domain': domain,
                'base_domain': base_domain,
                'tld': domain.split('.')[-1] if '.' in domain else '',
                'subdomain_count': max(0, domain.count('.') - 1)
            }
            
        except Exception as e:
            self.logger.error(f"URL分析失败: {e}")
        
        return result
    
    def analyze_urls(self, urls: List[str]) -> Dict:
        """
        批量分析URL
        
        Returns:
            {
                'total_urls': URL总数,
                'valid_urls': 有效URL数,
                'trusted_urls': 白名单URL数,
                'high_risk_count': 高风险URL数,
                'max_risk_level': 最高风险等级,
                'max_risk_score': 最高风险分数,
                'url_results': 各URL分析结果
            }
        """
        if not urls:
            return {
                'total_urls': 0,
                'valid_urls': 0,
                'trusted_urls': 0,
                'high_risk_count': 0,
                'max_risk_level': 'UNKNOWN',
                'max_risk_score': 0,
                'url_results': []
            }
        
        url_results = []
        trusted_count = 0
        high_risk_count = 0
        max_risk_score = 0
        
        for url in urls[:10]:  # 最多分析10个URL
            result = self.analyze_url(url)
            url_results.append(result)
            
            if result['is_trusted']:
                trusted_count += 1
            if result['risk_level'] == 'HIGH':
                high_risk_count += 1
            max_risk_score = max(max_risk_score, result['risk_score'])
        
        # 确定最高风险等级
        if max_risk_score >= 50:
            max_risk_level = 'HIGH'
        elif max_risk_score >= 30:
            max_risk_level = 'MEDIUM'
        elif max_risk_score >= 10:
            max_risk_level = 'LOW'
        else:
            max_risk_level = 'SAFE'
        
        return {
            'total_urls': len(urls),
            'valid_urls': len([r for r in url_results if r['is_valid']]),
            'trusted_urls': trusted_count,
            'high_risk_count': high_risk_count,
            'max_risk_level': max_risk_level,
            'max_risk_score': max_risk_score,
            'url_results': url_results
        }
    
    def _get_base_domain(self, domain: str) -> str:
        """获取基础域名"""
        parts = domain.split('.')
        if len(parts) >= 2:
            return '.'.join(parts[-2:])
        return domain
    
    def _is_ip_address(self, domain: str) -> bool:
        """检查是否为IP地址"""
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        return bool(re.match(ip_pattern, domain))
    
    def _has_high_risk_tld(self, domain: str) -> bool:
        """检查是否使用高风险TLD"""
        domain_lower = domain.lower()
        return any(domain_lower.endswith(tld) for tld in HIGH_RISK_TLDS)
    
    def _is_short_url(self, url: str) -> bool:
        """检查是否为短链接"""
        url_lower = url.lower()
        return any(service in url_lower for service in SHORT_URL_SERVICES)
    
    def _has_suspicious_params(self, query: str) -> bool:
        """检查是否有可疑参数"""
        query_lower = query.lower()
        return any(param in query_lower for param in SUSPICIOUS_PARAMS)
    
    def _check_brand_impersonation(self, domain: str) -> Optional[str]:
        """
        检查品牌仿冒（增强版）
        
        检测方法：
        1. 域名包含品牌名但不是官方域名
        2. 视觉相似度检测（编辑距离）
        3. 拼写变体检测
        """
        domain_lower = domain.lower()
        base_domain = self._get_base_domain(domain)
        
        for brand, official_domains in BRAND_DOMAINS.items():
            # 1. 直接包含品牌名但不是官方域名
            if brand in domain_lower:
                if base_domain not in official_domains:
                    # 检查是否是官方域名的子域名
                    is_subdomain = any(
                        domain_lower.endswith('.' + od) or domain_lower == od
                        for od in official_domains
                    )
                    if not is_subdomain:
                        return f'仿冒品牌: {brand} (非官方域名)'
            
            # 2. 视觉相似度检测（编辑距离）
            # 提取域名的主体部分（不含TLD）
            domain_main = base_domain.split('.')[0]
            
            # 计算与品牌名的编辑距离
            similarity = self._calculate_similarity(domain_main, brand)
            
            if similarity > 0.7 and similarity < 1.0:  # 高相似度但不完全相同
                if base_domain not in official_domains:
                    return f'疑似仿冒品牌: {brand} (相似度{similarity:.0%})'
            
            # 3. 常见拼写变体检测
            typos = self._generate_typos(brand)
            if domain_main in typos:
                if base_domain not in official_domains:
                    return f'拼写变体仿冒: {brand} → {domain_main}'
        
        return None
    
    def _calculate_similarity(self, s1: str, s2: str) -> float:
        """
        计算两个字符串的相似度（基于编辑距离）
        
        Returns:
            相似度 0.0-1.0
        """
        if not s1 or not s2:
            return 0.0
        
        # 计算编辑距离
        m, n = len(s1), len(s2)
        dp = [[0] * (n + 1) for _ in range(m + 1)]
        
        for i in range(m + 1):
            dp[i][0] = i
        for j in range(n + 1):
            dp[0][j] = j
        
        for i in range(1, m + 1):
            for j in range(1, n + 1):
                if s1[i-1] == s2[j-1]:
                    dp[i][j] = dp[i-1][j-1]
                else:
                    dp[i][j] = min(
                        dp[i-1][j] + 1,    # 删除
                        dp[i][j-1] + 1,    # 插入
                        dp[i-1][j-1] + 1   # 替换
                    )
        
        edit_distance = dp[m][n]
        max_len = max(m, n)
        similarity = 1 - (edit_distance / max_len)
        
        return similarity
    
    def _generate_typos(self, brand: str) -> List[str]:
        """
        生成常见拼写变体
        
        包括：
        - 字母替换（o→0, l→1, i→1）
        - 字母交换
        - 重复字母
        """
        typos = set()
        brand_lower = brand.lower()
        
        # 常见替换规则
        replacements = {
            'o': ['0', 'a', 'e'],
            'l': ['1', 'i'],
            'i': ['1', 'l'],
            'e': ['3', 'a'],
            'a': ['4', 'e', 'o'],
            's': ['5', 'z'],
            'z': ['s'],
            'g': ['q', '9'],
            'q': ['g'],
            'b': ['d', '8'],
            'd': ['b'],
            'p': ['q'],
            'w': ['vv', 'm'],
            'm': ['w', 'n'],
            'n': ['m'],
        }
        
        # 单字符替换
        for i, char in enumerate(brand_lower):
            if char in replacements:
                for replacement in replacements[char]:
                    typo = brand_lower[:i] + replacement + brand_lower[i+1:]
                    typos.add(typo)
        
        # 相邻字符交换
        for i in range(len(brand_lower) - 1):
            typo = brand_lower[:i] + brand_lower[i+1] + brand_lower[i] + brand_lower[i+2:]
            typos.add(typo)
        
        # 添加/删除字符
        for i in range(len(brand_lower) + 1):
            for c in 'aeiouns':
                typo = brand_lower[:i] + c + brand_lower[i:]
                typos.add(typo)
        
        if len(brand_lower) > 3:
            for i in range(len(brand_lower)):
                typo = brand_lower[:i] + brand_lower[i+1:]
                typos.add(typo)
        
        return list(typos)
    
    def _has_numbers_in_domain(self, domain: str) -> bool:
        """检查域名是否包含数字"""
        # 排除IP地址
        if self._is_ip_address(domain):
            return False
        # 检查主域名部分
        main_part = domain.split('.')[0]
        return bool(re.search(r'\d', main_part))


# 单例实例
url_analyzer = URLAnalyzerService()
