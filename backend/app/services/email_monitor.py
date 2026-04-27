#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Email Monitor Service
Automatic email monitoring with phishing detection
"""
import threading
import time
import json
from datetime import datetime
from typing import Dict, List, Optional
from pathlib import Path
import os

from app.core.logger import get_logger
from app.core.config import get_config
from app.services.email_fetcher import EmailFetcherService
from app.models.database import DatabaseRepository

logger = get_logger(__name__)


class EmailMonitorService:
    """邮件自动监控服务"""
    
    def __init__(self):
        self.config = get_config()
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.fetcher = EmailFetcherService()
        self.db = DatabaseRepository()
        
        self.stats = {
            'total_checked': 0,
            'phishing_detected': 0,
            'last_check_time': None,
            'last_error': None,
            'last_fetched_count': 0,
            'last_processed_count': 0,
            'last_failed_count': 0,
            'last_search_criteria': None,
            'start_time': None
        }
        
        self._lock = threading.Lock()
        self._reload_config()
    
    def _reload_config(self):
        """重新加载配置文件"""
        try:
            base_dir = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))
            config_file = os.path.join(base_dir, 'config', 'api_config.json')
            
            if os.path.exists(config_file):
                with open(config_file, 'r', encoding='utf-8') as f:
                    api_config = json.load(f)
                
                # 加载 AI 配置
                ai_config = api_config.get('ai', {})
                if ai_config:
                    if 'provider' in ai_config:
                        self.config.api.ai_provider = ai_config['provider']
                    if 'api_key' in ai_config:
                        self.config.api.ai_api_key = ai_config['api_key']
                    if 'api_url' in ai_config:
                        self.config.api.ai_api_url = ai_config['api_url']
                    if 'model' in ai_config:
                        self.config.api.ai_model = ai_config['model']
                    if 'enabled' in ai_config:
                        self.config.api.ai_enabled = ai_config['enabled']
                    logger.info(f"AI config reloaded: enabled={self.config.api.ai_enabled}, api_key={'已配置' if self.config.api.ai_api_key else '未配置'}")
                
                # 加载 threatbook 配置
                tb_config = api_config.get('threatbook', {})
                if tb_config:
                    if 'api_key' in tb_config:
                        self.config.api.threatbook_api_key = tb_config['api_key']
                    if 'api_url' in tb_config:
                        self.config.api.threatbook_api_url = tb_config['api_url']
                
                email_config = api_config.get('email', {})
                if email_config:
                    self.config.email.address = email_config.get('email', self.config.email.address)
                    self.config.email.password = email_config.get('password', self.config.email.password)
                    self.config.email.server = email_config.get('server', self.config.email.server)
                    self.config.email.protocol = email_config.get('protocol', self.config.email.protocol)
                    self.config.email.port = email_config.get('port', self.config.email.port)
                    self.config.email.enabled = email_config.get('enabled', self.config.email.enabled)

                mon = api_config.get('monitor') or {}
                if 'interval' in mon:
                    self.config.email.monitor_interval = int(mon['interval'])
                if 'max_attachment_size' in mon:
                    self.config.detection.max_file_size = int(mon['max_attachment_size'])
                self.config.email.only_unseen = mon.get('only_unseen', getattr(self.config.email, 'only_unseen', True))
                self.config.email.mark_seen_after_process = mon.get('mark_seen_after_process', getattr(self.config.email, 'mark_seen_after_process', False))
                self.config.email.monitor_fetch_limit = mon.get('fetch_limit', mon.get('monitor_fetch_limit', getattr(self.config.email, 'monitor_fetch_limit', 10)))

                det = api_config.get('detection') or {}
                if 'phishing_threshold' in det:
                    self.config.detection.phishing_threshold = float(det['phishing_threshold'])
                if 'suspicious_threshold' in det:
                    self.config.detection.suspicious_threshold = float(det['suspicious_threshold'])
                    
                logger.info(f"Email config reloaded: address={self.config.email.address[:10]}..., server={self.config.email.server}")
        except Exception as e:
            logger.error(f"Failed to reload config: {e}")
    
    @property
    def is_running(self) -> bool:
        """检查监控是否运行中"""
        return self.running and self.thread is not None and self.thread.is_alive()
    
    def start(self) -> Dict:
        """启动监控"""
        # 重新加载配置以确保获取最新配置
        self._reload_config()
        
        if self.is_running:
            return {
                'success': False,
                'message': 'Monitor is already running'
            }
        
        config_check = self._check_email_config()
        if not config_check['valid']:
            return {
                'success': False,
                'message': f'Email configuration is incomplete: {config_check["reason"]}'
            }
        
        self.running = True
        self.stats['start_time'] = datetime.now().isoformat()
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        
        logger.info("Email monitor started")
        return {
            'success': True,
            'message': 'Monitor started successfully'
        }
    
    def stop(self) -> Dict:
        """停止监控"""
        if not self.is_running:
            return {
                'success': False,
                'message': 'Monitor is not running'
            }
        
        self.running = False
        if self.thread:
            self.thread.join(timeout=5)
            self.thread = None
        
        logger.info("Email monitor stopped")
        return {
            'success': True,
            'message': 'Monitor stopped successfully'
        }
    
    def get_status(self) -> Dict:
        """获取监控状态"""
        with self._lock:
            stats_copy = self.stats.copy()
        
        config_check = self._check_email_config()
        
        return {
            'running': self.is_running,
            'interval': getattr(self.config.email, 'monitor_interval', 30),
            'stats': stats_copy,
            'email_configured': config_check['valid'],
            'config_details': config_check,
            'monitor_config': {
                'only_unseen': getattr(self.config.email, 'only_unseen', True),
                'mark_seen_after_process': getattr(self.config.email, 'mark_seen_after_process', False),
                'fetch_limit': getattr(self.config.email, 'monitor_fetch_limit', 10)
            }
        }
    
    def _check_email_config(self) -> Dict:
        """检查邮箱配置是否完整，返回详细信息"""
        # 每次都重新获取最新配置
        self.config = get_config()
        
        address = self.config.email.address
        password = self.config.email.password
        server = self.config.email.server
        
        details = {
            'valid': False,
            'reason': '',
            'address_set': bool(address),
            'password_set': bool(password),
            'server_set': bool(server)
        }
        
        if not address:
            details['reason'] = '邮箱地址未配置'
            return details
        
        if not password:
            details['reason'] = '邮箱密码/授权码未配置'
            return details
        
        if not server:
            details['reason'] = '邮箱服务器未配置'
            return details
        
        details['valid'] = True
        return details
    
    def _monitor_loop(self):
        """监控循环"""
        logger.info("Monitor loop started")
        
        while self.running:
            try:
                self._check_new_emails()
            except Exception as e:
                logger.error(f"Monitor loop error: {e}")
                with self._lock:
                    self.stats['last_error'] = str(e)
            
            interval = getattr(self.config.email, 'monitor_interval', 30)
            for _ in range(interval):
                if not self.running:
                    break
                time.sleep(1)
        
        logger.info("Monitor loop ended")
    
    def _check_new_emails(self):
        """检查新邮件"""
        config_check = self._check_email_config()
        if not config_check['valid']:
            logger.warning(f"Email not configured: {config_check['reason']}")
            return
        
        logger.info("Checking for new emails...")
        
        try:
            connected = self.fetcher.connect(
                self.config.email.address,
                self.config.email.password,
                self.config.email.server,
                self.config.email.protocol,
                self.config.email.port
            )
            
            if not connected:
                error_msg = '连接邮件服务器失败'
                logger.error(error_msg)
                with self._lock:
                    self.stats['last_error'] = error_msg
                return
            
            only_unseen = getattr(self.config.email, 'only_unseen', True)
            mark_seen_after_process = getattr(self.config.email, 'mark_seen_after_process', False)
            fetch_limit = getattr(self.config.email, 'monitor_fetch_limit', 10)
            emails = self.fetcher.fetch_emails(
                limit=fetch_limit,
                only_unseen=only_unseen,
                mark_seen_after_fetch=False
            )
            
            with self._lock:
                self.stats['last_fetched_count'] = len(emails)
                self.stats['last_search_criteria'] = 'UNSEEN' if only_unseen else 'ALL'
                self.stats['last_check_time'] = datetime.now().isoformat()
            
            if not emails:
                logger.debug("No new emails found")
                return
            
            logger.info(f"Found {len(emails)} emails to process")
            
            processed_count = 0
            failed_count = 0
            for email_data in emails:
                try:
                    result = self.fetcher.analyze_email(
                        email_data.get('raw', ''),
                        source='auto_monitor',
                        metadata={
                            'email_id': email_data.get('id'),
                            'email_uid': email_data.get('uid'),
                            'fingerprint': email_data.get('fingerprint')
                        }
                    )
                    
                    with self._lock:
                        self.stats['total_checked'] += 1
                        self.stats['last_check_time'] = datetime.now().isoformat()
                    
                    if result.get('label') == 'PHISHING':
                        with self._lock:
                            self.stats['phishing_detected'] += 1
                        
                        self._handle_phishing(email_data, result)
                    
                    if mark_seen_after_process and self.config.email.protocol == 'imap' and result.get('label') != 'ERROR':
                        self.fetcher.mark_as_seen(email_data.get('id', ''))
                    
                    processed_count += 1
                    
                except Exception as e:
                    failed_count += 1
                    logger.error(f"Failed to process email: {e}")
            
            with self._lock:
                self.stats['last_processed_count'] = processed_count
                self.stats['last_failed_count'] = failed_count
                    
        except Exception as e:
            logger.error(f"Failed to fetch emails: {e}")
            raise
        finally:
            self.fetcher.disconnect()
    
    def _handle_phishing(self, email_data: Dict, result: Dict):
        """处理检测到的钓鱼邮件"""
        parsed_email = result.get('parsed') or {}
        subject = parsed_email.get('subject') or email_data.get('subject', 'Unknown')
        from_addr = parsed_email.get('from') or email_data.get('from', 'Unknown')
        confidence = result.get('confidence', 0)
        
        logger.warning(
            f"Phishing detected! From: {from_addr}, "
            f"Subject: {subject}, Confidence: {confidence:.2%}"
        )
        
        self._save_alert(parsed_email or email_data, email_data, result)
    
    def _save_alert(self, parsed_email: Dict, email_data: Dict, result: Dict):
        """保存告警到数据库 - 与手动输入保持一致的分析流程"""
        try:
            # 获取完整的 parsed 数据（包含 body、html_body 等）
            full_parsed = result.get('parsed') or {}
            # 确保 body 和 html_body 被包含
            if not full_parsed.get('body') and result.get('features', {}).get('body'):
                full_parsed['body'] = result['features'].get('body', '')
            if not full_parsed.get('html_body') and result.get('features', {}).get('html_body'):
                full_parsed['html_body'] = result['features'].get('html_body', '')
            
            # 构建完整的 traceback 报告，包含所有分析模块的结果
            traceback_report = result.get('traceback') or {}
            traceback_report['module_scores'] = result.get('module_scores')  # 模块评分
            traceback_report['model_scores'] = result.get('model_scores')   # 模型评分
            traceback_report['features'] = result.get('features')           # 特征数据
            traceback_report['url_analysis'] = result.get('url_analysis')   # URL分析
            
            self.db.save_alert(
                parsed=full_parsed,
                label=result.get('label', 'PHISHING'),
                confidence=result.get('confidence', 0),
                traceback_report=traceback_report,
                source='auto_monitor',
                raw_email=email_data.get('raw', ''),
                email_uid=email_data.get('id'),
                ai_analysis=result.get('ai_analysis'),
                module_scores=result.get('module_scores'),
                model_scores=result.get('model_scores'),
                features=result.get('features'),
                url_analysis=result.get('url_analysis')
            )
        except Exception as e:
            logger.error(f"Failed to save alert: {e}")


email_monitor = EmailMonitorService()
