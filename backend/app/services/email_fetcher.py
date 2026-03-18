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
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor
import sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, get_config
from app.services.email_parser import EmailParserService
from app.services.detector import DetectionService
from app.services.traceback import TracebackService
from app.services.feature_extractor import FeatureExtractionService
from app.services.url_analyzer import URLAnalyzerService


class EmailFetcherService:
    """
    Email Fetcher Service
    Fetch emails from mail servers via IMAP/POP3
    """
    
    def __init__(self):
        self.logger = get_logger(__name__)
        self.config = get_config()
        self.parser = EmailParserService()
        self.detector = DetectionService()
        self.traceback = TracebackService()
        self.feature_extractor = FeatureExtractionService()
        self.connection = None
    
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
        only_unseen: bool = True
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
                message_ids = messages[0].split()[-limit:]
                
                for msg_id in message_ids:
                    status, data = self.connection.fetch(msg_id, '(RFC822 UID)')
                    uid = None
                    raw_email = None
                    
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
                        emails.append({
                            'raw': raw_email,
                            'id': msg_id.decode('utf-8'),
                            'uid': uid
                        })
            
            elif self.protocol == 'pop3':
                num_messages = len(self.connection.list()[1])
                start = max(1, num_messages - limit + 1)
                
                for i in range(start, num_messages + 1):
                    response, lines, octets = self.connection.retr(i)
                    raw_email = b'\n'.join(lines).decode('utf-8', errors='ignore')
                    emails.append({
                        'raw': raw_email,
                        'id': str(i)
                    })
            
            self.logger.info(f"Fetched {len(emails)} emails")
        except Exception as e:
            self.logger.error(f"Failed to fetch emails: {e}")
        
        return emails
    
    def process_email(self, raw_email: str, vt_api_key: str = "") -> Dict:
        """Process single email"""
        try:
            parsed = self.parser.parse(raw_email)
            features = self.feature_extractor.extract_features(parsed, vt_api_key)
            traceback_report = self.traceback.generate_report(parsed, vt_api_key)
            
            url_analyzer = URLAnalyzerService()
            url_analysis = url_analyzer.analyze_urls(parsed.get('urls', []))
            
            label, confidence, reason = self.detector.analyze(
                parsed, features, 
                url_analysis['max_risk_level'],
                url_analysis['max_risk_score']
            )
            
            return {
                'label': label,
                'confidence': round(confidence, 4),
                'reason': reason,
                'parsed': {
                    'from': parsed.get('from'),
                    'from_display_name': parsed.get('from_display_name'),
                    'from_email': parsed.get('from_email'),
                    'to': parsed.get('to'),
                    'subject': parsed.get('subject'),
                    'body': parsed.get('body', ''),
                    'html_body': parsed.get('html_body', ''),
                    'urls': parsed.get('urls', []),
                    'url_count': len(parsed.get('urls', [])),
                    'attachment_count': len(parsed.get('attachments', [])),
                    'has_html_body': 1 if parsed.get('html_body') else 0
                },
                'features': features,
                'traceback': traceback_report,
                'url_analysis': url_analysis
            }
            
        except Exception as e:
            self.logger.error(f"Failed to process email: {e}")
            return {
                'label': 'ERROR',
                'confidence': 0.0,
                'reason': f'处理失败: {str(e)}',
                'parsed': {}
            }
    
    def process_emails(
        self,
        emails: List[Dict],
        vt_api_key: str = "",
        max_workers: int = 4
    ) -> List[Dict]:
        """Process multiple emails in parallel"""
        results = []
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_email = {
                executor.submit(self.process_email, email['raw'], vt_api_key): email 
                for email in emails
            }
            
            for future in future_to_email:
                try:
                    result = future.result()
                    email = future_to_email[future]
                    result['email_id'] = email['id']
                    results.append(result)
                except Exception as e:
                    self.logger.error(f"Exception processing email: {e}")
        
        return results
