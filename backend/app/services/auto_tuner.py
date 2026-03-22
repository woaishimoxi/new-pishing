#!/usr/bin/env python3
"""
智能配置模块 - 参数推荐算法
根据企业邮件数据特征自动推荐最优检测参数
"""
import os
import json
import statistics
from typing import Dict, List, Tuple
from datetime import datetime
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import get_logger, get_config


class AutoTuner:
    """
    智能参数调优器
    基于企业邮件特征自动推荐最优检测参数
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
    
    def analyze_email_patterns(self, emails: List[Dict]) -> Dict:
        """
        分析企业邮件模式
        
        Args:
            emails: 邮件数据列表
            
        Returns:
            邮件模式分析结果
        """
        if not emails:
            return self._get_default_patterns()
        
        patterns = {
            'total_count': len(emails),
            'avg_text_length': 0,
            'avg_url_count': 0,
            'has_attachment_ratio': 0,
            'has_html_ratio': 0,
            'common_senders': [],
            'common_domains': [],
            'peak_hours': [],
        }
        
        text_lengths = []
        url_counts = []
        has_attachment = 0
        has_html = 0
        sender_freq = {}
        domain_freq = {}
        hour_freq = {}
        
        for email in emails:
            # 文本长度
            body = email.get('body', '') or ''
            text_lengths.append(len(body))
            
            # URL数量
            urls = email.get('urls', []) or []
            url_counts.append(len(urls))
            
            # 附件
            if email.get('attachments'):
                has_attachment += 1
            
            # HTML
            if email.get('html_body') or email.get('has_html_body'):
                has_html += 1
            
            # 发件人统计
            sender = email.get('from_email', '') or ''
            if sender:
                sender_freq[sender] = sender_freq.get(sender, 0) + 1
                domain = sender.split('@')[-1] if '@' in sender else ''
                if domain:
                    domain_freq[domain] = domain_freq.get(domain, 0) + 1
            
            # 时间分布
            time_str = email.get('date', '') or email.get('detection_time', '')
            if time_str:
                try:
                    dt = datetime.fromisoformat(time_str.replace('Z', '+00:00'))
                    hour = dt.hour
                    hour_freq[hour] = hour_freq.get(hour, 0) + 1
                except:
                    pass
        
        # 计算统计值
        if text_lengths:
            patterns['avg_text_length'] = statistics.mean(text_lengths)
        if url_counts:
            patterns['avg_url_count'] = statistics.mean(url_counts)
        
        patterns['has_attachment_ratio'] = has_attachment / len(emails) if emails else 0
        patterns['has_html_ratio'] = has_html / len(emails) if emails else 0
        
        # 常见发件人
        sorted_senders = sorted(sender_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        patterns['common_senders'] = [s[0] for s in sorted_senders]
        
        # 常见域名
        sorted_domains = sorted(domain_freq.items(), key=lambda x: x[1], reverse=True)[:10]
        patterns['common_domains'] = [d[0] for d in sorted_domains]
        
        # 高峰时段
        sorted_hours = sorted(hour_freq.items(), key=lambda x: x[1], reverse=True)[:3]
        patterns['peak_hours'] = [h[0] for h in sorted_hours]
        
        return patterns
    
    def recommend_parameters(self, patterns: Dict) -> Dict:
        """
        根据邮件模式推荐检测参数
        
        Args:
            patterns: 邮件模式分析结果
            
        Returns:
            推荐的参数配置
        """
        recommendations = {
            'phishing_threshold': 0.70,
            'suspicious_threshold': 0.40,
            'url_risk_weight': 0.4,
            'text_risk_weight': 0.3,
            'header_risk_weight': 0.3,
            'auto_monitor_interval': 300,  # 秒
            'max_attachment_size': 10 * 1024 * 1024,  # 10MB
            'enable_sandbox': False,
            'trusted_domains': [],
            'reasons': []
        }
        
        # 根据平均URL数量调整权重
        avg_url_count = patterns.get('avg_url_count', 0)
        if avg_url_count > 5:
            recommendations['url_risk_weight'] = 0.5
            recommendations['reasons'].append('邮件中URL较多，提高URL风险权重')
        elif avg_url_count < 1:
            recommendations['url_risk_weight'] = 0.3
            recommendations['reasons'].append('邮件中URL较少，降低URL风险权重')
        
        # 根据附件比例调整
        attachment_ratio = patterns.get('has_attachment_ratio', 0)
        if attachment_ratio > 0.5:
            recommendations['enable_sandbox'] = True
            recommendations['reasons'].append('附件比例较高，建议启用沙箱分析')
        
        # 根据HTML比例调整
        html_ratio = patterns.get('has_html_ratio', 0)
        if html_ratio > 0.7:
            recommendations['reasons'].append('HTML邮件较多，注意检查隐藏链接')
        
        # 设置常用域名作为可信域名
        common_domains = patterns.get('common_domains', [])
        if common_domains:
            recommendations['trusted_domains'] = common_domains[:5]
            recommendations['reasons'].append(f'已将常用域名 {", ".join(common_domains[:3])} 添加到白名单')
        
        # 根据邮件量调整监控间隔
        total_count = patterns.get('total_count', 0)
        if total_count > 1000:
            recommendations['auto_monitor_interval'] = 60  # 1分钟
            recommendations['reasons'].append('邮件量大，建议缩短监控间隔')
        elif total_count < 100:
            recommendations['auto_monitor_interval'] = 600  # 10分钟
            recommendations['reasons'].append('邮件量小，可延长监控间隔')
        
        return recommendations
    
    def apply_recommendations(self, recommendations: Dict) -> bool:
        """
        应用推荐参数到配置文件
        
        Args:
            recommendations: 推荐的参数配置
            
        Returns:
            是否成功应用
        """
        try:
            config_file = os.path.join(
                os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                'config', 'api_config.json'
            )
            
            # 读取现有配置
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    current_config = json.load(f)
            else:
                current_config = {}
            
            # 更新配置
            current_config['detection'] = {
                'phishing_threshold': recommendations['phishing_threshold'],
                'suspicious_threshold': recommendations['suspicious_threshold'],
                'url_risk_weight': recommendations['url_risk_weight'],
                'text_risk_weight': recommendations['text_risk_weight'],
                'header_risk_weight': recommendations['header_risk_weight'],
            }
            
            current_config['monitor'] = {
                'interval': recommendations['auto_monitor_interval'],
                'max_attachment_size': recommendations['max_attachment_size'],
                'enable_sandbox': recommendations['enable_sandbox'],
            }
            
            current_config['last_tuned'] = datetime.now().isoformat()
            
            # 保存配置
            with open(config_file, 'w', encoding='utf-8') as f:
                json.dump(current_config, f, indent=2, ensure_ascii=False)
            
            self.logger.info(f"已应用推荐参数: {recommendations}")
            return True
            
        except Exception as e:
            self.logger.error(f"应用推荐参数失败: {e}")
            return False
    
    def auto_tune(self, emails: List[Dict] = None) -> Dict:
        """
        自动调优入口
        
        Args:
            emails: 邮件数据列表（可选）
            
        Returns:
            调优结果
        """
        self.logger.info("开始智能参数调优...")
        
        # 如果没有提供邮件数据，从数据库获取
        if not emails:
            emails = self._load_emails_from_db()
        
        # 分析邮件模式
        patterns = self.analyze_email_patterns(emails)
        self.logger.info(f"邮件模式分析完成: {patterns}")
        
        # 推荐参数
        recommendations = self.recommend_parameters(patterns)
        self.logger.info(f"参数推荐完成: {recommendations}")
        
        # 应用参数
        success = self.apply_recommendations(recommendations)
        
        result = {
            'success': success,
            'patterns': patterns,
            'recommendations': recommendations,
            'applied_at': datetime.now().isoformat() if success else None
        }
        
        return result
    
    def _load_emails_from_db(self) -> List[Dict]:
        """从数据库加载邮件数据"""
        try:
            from app.models.database import Database
            db = Database()
            alerts = db.get_alerts(limit=1000)
            return alerts
        except Exception as e:
            self.logger.warning(f"从数据库加载邮件失败: {e}")
            return []
    
    def _get_default_patterns(self) -> Dict:
        """获取默认邮件模式"""
        return {
            'total_count': 0,
            'avg_text_length': 1000,
            'avg_url_count': 2,
            'has_attachment_ratio': 0.2,
            'has_html_ratio': 0.5,
            'common_senders': [],
            'common_domains': [],
            'peak_hours': [9, 14, 16],
        }


# 创建全局实例
auto_tuner = AutoTuner()
