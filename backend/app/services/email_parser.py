"""
Email Parser Service
Parse raw email content into structured data
"""
import email
import re
import hashlib
from email.header import decode_header
from email.message import Message
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple, Any
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from app.core import get_logger, FeatureExtractionError


class LinkExtractor(HTMLParser):
    """Extract links from HTML content"""
    
    def __init__(self):
        super().__init__()
        self.links: List[Dict] = []
        self.forms: List[Dict] = []
        self.hidden_links: List[str] = []
        self.current_link: Optional[str] = None
        self.link_text: str = ""
    
    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]) -> None:
        attrs_dict = dict(attrs)
        
        if tag == 'a':
            href = attrs_dict.get('href', '')
            if href:
                self.links.append({'url': href, 'type': 'link'})
                style = attrs_dict.get('style', '')
                if 'display:none' in style.lower() or 'visibility:hidden' in style.lower():
                    self.hidden_links.append(href)
                self.current_link = href
                self.link_text = ""
        
        elif tag == 'form':
            action = attrs_dict.get('action', '')
            method = attrs_dict.get('method', 'GET')
            if action:
                self.forms.append({'action': action, 'method': method})
        
        elif tag == 'img':
            src = attrs_dict.get('src', '')
            if src:
                self.links.append({'url': src, 'type': 'image'})
        
        elif tag == 'iframe':
            src = attrs_dict.get('src', '')
            if src:
                self.links.append({'url': src, 'type': 'iframe', 'risk': 'high'})
        
        elif tag == 'script':
            src = attrs_dict.get('src', '')
            if src:
                self.links.append({'url': src, 'type': 'script', 'risk': 'medium'})


class EmailParserService:
    """
    Email parsing service
    Parses raw email content into structured data
    """
    
    HIGH_RISK_EXTENSIONS = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbe',
        '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.hta',
        '.cpl', '.msc', '.jar', '.dll', '.reg', '.lnk'
    }
    
    MEDIUM_RISK_EXTENSIONS = {
        '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', '.dot', '.dotm',
        '.xlt', '.xltm', '.pot', '.potm', '.ppa', '.ppam', '.sldm',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'
    }
    
    def __init__(self):
        self.logger = get_logger(__name__)
    
    def parse(self, raw_email: str) -> Dict[str, Any]:
        """
        Parse raw email string into structured data
        
        Args:
            raw_email: Raw email string
            
        Returns:
            Dict with parsed email data
        """
        try:
            msg = email.message_from_string(raw_email)
            
            from_raw = msg.get("From", "").strip()
            from_display_name, from_email = self._parse_email_address(from_raw)
            
            received_list = msg.get_all("Received", [])
            
            body = ""
            html_body = ""
            subject = self._decode_mime_header(msg.get("Subject", ""))
            to_addr = self._decode_mime_header(msg.get("To", ""))
            
            attachments: List[Dict] = []
            
            if msg.is_multipart():
                for part in msg.walk():
                    content_type = part.get_content_type()
                    content_disposition = part.get("Content-Disposition", "")
                    
                    if content_disposition and 'attachment' in content_disposition.lower():
                        attachment_info = self._parse_attachment(part)
                        if attachment_info:
                            attachments.append(attachment_info)
                        continue
                    
                    if content_type == "text/plain":
                        decoded = self._decode_payload(part)
                        if decoded:
                            body += decoded
                    
                    elif content_type == "text/html":
                        decoded = self._decode_payload(part)
                        if decoded:
                            html_body += decoded
            else:
                content_type = msg.get_content_type()
                decoded = self._decode_payload(msg)
                if decoded:
                    if content_type == "text/plain":
                        body = decoded
                    elif content_type == "text/html":
                        html_body = decoded
                    elif content_type.startswith('application/') or content_type.startswith('image/'):
                        attachment_info = self._parse_attachment(msg)
                        if attachment_info:
                            attachments.append(attachment_info)
            
            urls = self._extract_urls(body)
            
            html_links: List[Dict] = []
            html_forms: List[Dict] = []
            if html_body:
                extractor = LinkExtractor()
                try:
                    extractor.feed(html_body)
                    html_links = extractor.links
                    html_forms = extractor.forms
                    for link in html_links:
                        if isinstance(link, dict):
                            url = link.get('url')
                            if url and url not in urls:
                                urls.append(url)
                except Exception as e:
                    self.logger.warning(f"HTML parsing failed: {e}")
            
            for attachment in attachments:
                content = attachment.get('content')
                if content:
                    try:
                        if isinstance(content, bytes):
                            attachment_text = content.decode('utf-8', errors='ignore')
                        else:
                            attachment_text = str(content)
                        
                        attachment_urls = self._extract_urls(attachment_text)
                        for url in attachment_urls:
                            if url not in urls:
                                urls.append(url)
                    except Exception as e:
                        self.logger.warning(f"Attachment URL extraction failed: {e}")
            
            headers = self._extract_headers(msg)
            
            return {
                "from": from_raw,
                "from_display_name": from_display_name,
                "from_email": from_email,
                "received_chain": received_list,
                "body": body,
                "html_body": html_body,
                "urls": urls,
                "subject": subject,
                "to": to_addr,
                "attachments": attachments,
                "html_links": html_links,
                "html_forms": html_forms,
                "headers": headers
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse email: {e}")
            raise FeatureExtractionError(f"Failed to parse email: {str(e)}")
    
    def _parse_email_address(self, email_addr: str) -> Tuple[str, str]:
        """Parse email address, separating display name and email"""
        if not email_addr:
            return ("", "")
        
        email_addr = self._decode_mime_header(email_addr)
        
        match = re.match(r'["\']?([^"<>]*)["\']?\s*<([^<>]+)>', email_addr)
        if match:
            return (match.group(1).strip(), match.group(2).strip())
        
        if '@' in email_addr:
            email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email_addr)
            if email_match:
                return ("", email_match.group(0))
        
        return (email_addr.strip(), "")
    

    def _decode_payload(self, part) -> str:
        """
        Decode email payload with proper encoding handling
        
        Supports:
        - Base64
        - Quoted-printable  
        - Multiple charsets
        """
        try:
            # 方法1: 使用get_payload(decode=True)自动解码
            payload = part.get_payload(decode=True)
            if payload:
                # 尝试多种编码
                for encoding in ['utf-8', 'gb2312', 'gbk', 'big5', 'latin-1']:
                    try:
                        return payload.decode(encoding, errors='strict')
                    except (UnicodeDecodeError, AttributeError):
                        continue
                # 如果都失败，使用ignore
                return payload.decode('utf-8', errors='ignore')
        except Exception as e:
            self.logger.warning(f"Failed to decode payload: {e}")
        
        return ""

    def _decode_mime_header(self, header: str) -> str:
        """Decode MIME encoded header"""
        if not header:
            return ""
        
        decoded_parts = []
        for part, encoding in decode_header(header):
            if isinstance(part, bytes):
                try:
                    decoded_parts.append(part.decode(encoding or 'utf-8', errors='ignore'))
                except (LookupError, UnicodeDecodeError):
                    decoded_parts.append(part.decode('utf-8', errors='ignore'))
            else:
                decoded_parts.append(part)
        
        return ''.join(decoded_parts)
    
    def _parse_attachment(self, part: Message) -> Optional[Dict]:
        """Parse attachment from email part"""
        try:
            filename = part.get_filename()
            if not filename:
                content_type = part.get('Content-Type', '')
                name_match = re.search(r'name=["\']?([^"\';]+)', content_type)
                if name_match:
                    filename = name_match.group(1).strip()
            
            if not filename:
                filename = "unnamed"
            
            filename = self._decode_mime_header(filename)
            content_type = part.get_content_type()
            payload = part.get_payload(decode=True)
            size = len(payload) if payload else 0
            
            md5_hash = ""
            sha256_hash = ""
            if payload:
                md5_hash = hashlib.md5(payload).hexdigest()
                sha256_hash = hashlib.sha256(payload).hexdigest()
            
            is_suspicious = self._check_suspicious_file_type(filename, content_type)
            
            # Check attachment content for dangerous patterns
            content_risk = self._check_attachment_content(payload)
            if content_risk:
                is_suspicious = True
            
            return {
                'filename': filename,
                'content_type': content_type,
                'size': size,
                'md5': md5_hash,
                'sha256': sha256_hash,
                'is_suspicious_type': is_suspicious,
                'content': payload
            }
            
        except Exception as e:
            self.logger.error(f"Failed to parse attachment: {e}")
            return None
    
    def _check_suspicious_file_type(self, filename: str, content_type: str) -> bool:
        """Check if file type is suspicious"""
        filename_lower = filename.lower()
        
        # Check for dangerous extensions anywhere in the filename
        dangerous_extensions = ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.sh', '.py', '.pl', '.cgi']
        for ext in dangerous_extensions:
            if ext in filename_lower:
                return True
        
        # Check standard high-risk extensions
        ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''
        if ext in self.HIGH_RISK_EXTENSIONS:
            return True
        
        # Check for double extensions that mask dangerous files
        parts = filename_lower.split('.')
        if len(parts) > 2:
            # Check if the second-to-last part is a common safe extension
            # but the last part might be hiding something dangerous
            second_last = '.' + parts[-2]
            last = '.' + parts[-1]
            
            # Common safe extensions that attackers might use to mask dangerous files
            safe_extensions = ['.txt', '.jpg', '.jpeg', '.png', '.gif', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.zip']
            
            if second_last in safe_extensions:
                # Check if the actual extension (last part) is dangerous
                if last in ['.php', '.php3', '.php4', '.php5', '.phtml', '.jsp', '.asp', '.aspx', '.sh', '.py', '.pl', '.cgi']:
                    return True
                # Also check if it's in our standard high-risk list
                if last in self.HIGH_RISK_EXTENSIONS:
                    return True
        
        # Check content type for PHP files
        if 'php' in content_type.lower() or 'application/x-php' in content_type.lower():
            return True
            
        return False

    def _check_attachment_content(self, payload) -> bool:
        """Check attachment content for dangerous patterns"""
        if not payload:
            return False
            
        try:
            # Decode payload if it's bytes
            if isinstance(payload, bytes):
                content = payload.decode('utf-8', errors='ignore')
            else:
                content = str(payload)
            
            content_lower = content.lower()
            
            # Check for dangerous PHP patterns
            dangerous_patterns = [
                'eval(', 'base64_decode', 'system(', 'exec(', 'shell_exec(',
                'passthru(', 'assert(', 'create_function', 'iframe',
                'document.write', 'window.location', '<script>',
                '<?php', '<?=', '?>'
            ]
            
            for pattern in dangerous_patterns:
                if pattern in content_lower:
                    return True
                    
            # Check for suspicious variable names that might indicate obfuscated code
            suspicious_vars = ['_', '$a', '$b', '$c', '$d', '$e', '$f']
            for var in suspicious_vars:
                if var + '=' in content_lower:
                    # If we see multiple suspicious variable assignments, likely obfuscated
                    if content_lower.count(var + '=') > 2:
                        return True
                        
        except Exception:
            # If we can't decode the content, we can't check it
            pass
            
        return False
    
    def _extract_urls(self, body: str) -> List[str]:
        """Extract URLs from text body"""
        if not body:
            return []
        
        url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(?:/[^\s<>"]*)?'
        urls = list(set(re.findall(url_pattern, body)))
        
        processed_urls = []
        for url in urls:
            if isinstance(url, str) and not url.startswith(('http://', 'https://', 'www.')):
                processed_urls.append('http://' + url)
            elif isinstance(url, str):
                processed_urls.append(url)
        
        return processed_urls
    
    def _extract_headers(self, msg: Message) -> Dict[str, str]:
        """Extract email headers"""
        headers = {
            'return_path': msg.get("Return-Path", ""),
            'x_mailer': msg.get("X-Mailer", ""),
            'x_originating_ip': msg.get("X-Originating-IP", ""),
            'authentication_results': msg.get("Authentication-Results", ""),
            'received_spf': msg.get("Received-SPF", ""),
            'dkim_signature': msg.get("DKIM-Signature", ""),
            'x_spam_status': msg.get("X-Spam-Status", ""),
            'x_spam_score': msg.get("X-Spam-Score", ""),
        }
        
        auth_results = headers.get('authentication_results', '')
        headers['spf_result'] = self._parse_auth_result(auth_results, 'spf')
        headers['dkim_result'] = self._parse_auth_result(auth_results, 'dkim')
        headers['dmarc_result'] = self._parse_auth_result(auth_results, 'dmarc')
        
        return headers
    
    def _parse_auth_result(self, auth_results: str, auth_type: str) -> str:
        """Parse authentication result (SPF/DKIM/DMARC)"""
        if not auth_results:
            return "none"
        
        auth_results = auth_results.lower()
        
        patterns = {
            'spf': r'spf[=:]?\s*(\w+)',
            'dkim': r'dkim[=:]?\s*(\w+)',
            'dmarc': r'dmarc[=:]?\s*(\w+)'
        }
        
        pattern = patterns.get(auth_type, '')
        if pattern:
            match = re.search(pattern, auth_results)
            if match:
                result = match.group(1)
                if result in ['pass', 'fail']:
                    return result
                elif result in ['softfail', 'neutral']:
                    return 'fail'
                elif result == 'none':
                    return 'none'
                elif result in ['temperror', 'permerror']:
                    return 'unknown'
        
        return "unknown"
