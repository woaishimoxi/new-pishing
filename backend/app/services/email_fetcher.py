"""
Email Fetcher Service
Fetch emails from mail servers via IMAP/POP3
"""
import imaplib
import poplib
import email
import re
import time
import json
import os
import hashlib
from datetime import datetime
from typing import List, Dict, Optional, Tuple
from concurrent.futures import ThreadPoolExecutor
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config
from app.services.analysis_pipeline import AnalysisPipeline


class EmailFetcherService:
    """
    Email Fetcher Service
    Fetch emails from mail servers via IMAP/POP3
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self._config = None
        self.pipeline = AnalysisPipeline()
        self.connection = None
    
    @property
    def config(self):
        """每次获取最新配置"""
        if self._config is None:
            self._config = get_config()
        return self._config
    
    def refresh_config(self):
        """手动刷新配置"""
        self._config = get_config()
        self.logger.info("Config refreshed")
    
    def connect(
        self,
        email_address: str,
        password: str,
        server: str,
        protocol: str = 'imap',
        port: Optional[int] = None
    ) -> bool:
        """Connect to mail server"""
        self.protocol = protocol.lower()
        self.port = port or self._get_default_port()
        
        try:
            if self.protocol == 'imap':
                self.connection = imaplib.IMAP4_SSL(server, self.port)
                self.connection.login(email_address, password)
                self.logger.info(f"Connected to IMAP server: {server}")
            elif self.protocol == 'pop3':
                self.connection = poplib.POP3_SSL(server, self.port)
                self.connection.user(email_address)
                self.connection.pass_(password)
                self.logger.info(f"Connected to POP3 server: {server}")
            return True
        except Exception as e:
            self.logger.error(f"Connection failed: {e}")
            self.connection = None
            return False
    
    def _get_default_port(self) -> int:
        """Get default port for protocol"""
        if self.protocol == 'imap':
            return 993
        elif self.protocol == 'pop3':
            return 995
        raise ValueError(f"Unsupported protocol: {self.protocol}")
    
    def disconnect(self) -> None:
        """Disconnect from mail server"""
        if self.connection:
            try:
                if self.protocol == 'imap':
                    self.connection.logout()
                elif self.protocol == 'pop3':
                    self.connection.quit()
                self.logger.info("Disconnected from server")
            except Exception as e:
                self.logger.error(f"Disconnect failed: {e}")
            finally:
                self.connection = None
    
    def mark_as_seen(self, msg_id: str) -> None:
        """Mark email as seen (IMAP only)"""
        if not self.connection or self.protocol != 'imap':
            return
        
        try:
            self.connection.store(msg_id, '+FLAGS', '\\Seen')
            self.logger.debug(f"Email {msg_id} marked as seen")
        except Exception as e:
            self.logger.error(f"Failed to mark email as seen: {e}")
    
    def fetch_emails(
        self,
        limit: int = 10,
        only_unseen: bool = True,
        mark_seen_after_fetch: bool = False
    ) -> List[Dict]:
        """Fetch emails from server"""
        if not self.connection:
            self.logger.error("Not connected to server")
            return []
        
        emails = []
        try:
            if self.protocol == 'imap':
                self.connection.select('INBOX')
                search_criteria = 'UNSEEN' if only_unseen else 'ALL'
                status, messages = self.connection.search(None, search_criteria)
                if status != 'OK' or not messages or not messages[0]:
                    self.logger.info("No messages matched search criteria")
                    return []

                message_ids = messages[0].split()[-limit:]
                
                for msg_id in message_ids:
                    status, data = self.connection.fetch(msg_id, '(RFC822 UID)')
                    uid = None
                    raw_email = None
                    
                    if status != 'OK' or not data:
                        self.logger.warning(f"Failed to fetch message {msg_id!r}")
                        continue

                    for response_part in data:
                        if isinstance(response_part, tuple):
                            if b'RFC822' in response_part[0]:
                                raw_email = response_part[1].decode('utf-8', errors='ignore')
                            uid_str = response_part[0].decode('utf-8', errors='ignore')
                            uid_match = re.search(r'UID\s+(\d+)', uid_str)
                            if uid_match:
                                uid = uid_match.group(1)
                            elif re.search(r'(\d+)\s+\(UID', uid_str):
                                qq_match = re.search(r'(\d+)\s+\(UID', uid_str)
                                if qq_match:
                                    uid = qq_match.group(1)
                            elif b'UID' in response_part[0]:
                                num_match = re.search(r'(\d+)', uid_str)
                                if num_match:
                                    uid = num_match.group(1)
                    
                    if not uid:
                        uid = msg_id.decode('utf-8')
                        self.logger.warning(f"No standard UID found, using message sequence number {uid}")
                    
                    if raw_email:
                        message_id = msg_id.decode('utf-8')
                        fingerprint = hashlib.sha1(raw_email.encode('utf-8', errors='ignore')).hexdigest()
                        emails.append({
                            'raw': raw_email,
                            'id': message_id,
                            'uid': uid,
                            'message_id': message_id,
                            'fingerprint': fingerprint
                        })
                        if mark_seen_after_fetch:
                            self.mark_as_seen(message_id)
                
                self.logger.info(f"IMAP search criteria={search_criteria}, matched={len(message_ids)}, fetched={len(emails)}")
            
            elif self.protocol == 'pop3':
                num_messages = len(self.connection.list()[1])
                start = max(1, num_messages - limit + 1)

                for i in range(start, num_messages + 1):
                    response, lines, octets = self.connection.retr(i)
                    raw_email = b'\n'.join(lines).decode('utf-8', errors='ignore')
                    fingerprint = hashlib.sha1(raw_email.encode('utf-8', errors='ignore')).hexdigest()
                    emails.append({
                        'raw': raw_email,
                        'id': str(i),
                        'message_id': str(i),
                        'fingerprint': fingerprint
                    })

            self.logger.info(f"Fetched {len(emails)} emails")
        except Exception as e:
            self.logger.error(f"Failed to fetch emails: {e}")
        
        return emails
    
    def process_email(self, raw_email: str) -> Dict:
        """Process single email - 统一走 AnalysisPipeline"""
        try:
            return self.pipeline.analyze(raw_email, source='IMAP自动拉取')
        except Exception as e:
            self.logger.error(f"Failed to process email: {e}")
            return {
                'label': 'ERROR',
                'confidence': 0.0,
                'reason': f'处理失败: {str(e)}',
                'parsed': {},
                'model_scores': {}
            }

    def analyze_email(self, raw_email: str, source: str = 'manual', metadata: Optional[Dict] = None) -> Dict:
        """统一分析入口：所有来源邮件都调用这里"""
        return self.pipeline.analyze(raw_email, source=source)

    def process_emails(
        self,
        emails: List[Dict],
        max_workers: int = 4,
        mark_seen_after_process: bool = False
    ) -> List[Dict]:
        """Process multiple emails in parallel - 统一走 AnalysisPipeline"""
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_email = {
                executor.submit(self.pipeline.analyze, email['raw'], source='IMAP自动拉取'): email
                for email in emails
            }

            for future in future_to_email:
                try:
                    result = future.result()
                    email = future_to_email[future]
                    result['email_id'] = email['id']
                    if mark_seen_after_process and self.protocol == 'imap' and result.get('label') != 'ERROR':
                        self.mark_as_seen(email['id'])
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Exception processing email: {e}")

        return results
