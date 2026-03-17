"""
邮件解析与特征提取模块
该模块是整个数据处理流水线的入口。其核心任务是将原始的、非结构化的邮件字符串，
转化为结构化的、可供后续分析的特征字典。

增强功能：
- 附件解析：提取附件名、类型、大小、内容
- HTML 内容解析：提取隐藏链接、表单动作
- 发件人详细信息：显示名、邮箱地址分离
"""
import email
from email.message import Message
from email.header import decode_header
import re
import hashlib
from typing import Dict, List, Optional
from html.parser import HTMLParser


class LinkExtractor(HTMLParser):
    """提取 HTML 中的链接"""
    def __init__(self):
        super().__init__()
        self.links = []
        self.forms = []
        self.hidden_links = []
        self.current_link = None
        self.link_text = ""

    def handle_starttag(self, tag, attrs):
        attrs_dict = dict(attrs)

        if tag == 'a':
            href = attrs_dict.get('href', '')
            if href:
                self.links.append({'url': href, 'type': 'link'})
                # 检查是否为隐藏链接（空文本或 display:none）
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


def decode_mime_header(header: str) -> str:
    """解码 MIME 编码的邮件头"""
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


def parse_email(raw_email: str) -> Dict:
    """
    解析原始邮件字符串，提取结构化信息。

    增强功能：
    - 附件列表：包含文件名、类型、大小、哈希值
    - HTML 正文：单独提取 HTML 内容
    - 显示名欺骗检测信息

    Args:
        raw_email (str): 原始邮件字符串

    Returns:
        Dict: 包含以下键的字典：
            - 'from': 发件人地址 (str)
            - 'from_display_name': 发件人显示名 (str)
            - 'from_email': 发件人纯邮箱地址 (str)
            - 'received_chain': 邮件传输路径链 (List[str])
            - 'body': 邮件纯文本正文 (str)
            - 'html_body': 邮件 HTML 正文 (str)
            - 'urls': 正文中提取的所有 URL (List[str])
            - 'subject': 邮件主题 (str)
            - 'to': 收件人地址 (str)
            - 'attachments': 附件列表 (List[Dict])
            - 'html_links': HTML 中提取的链接 (List[Dict])
            - 'html_forms': HTML 中的表单 (List[Dict])
            - 'headers': 原始邮件头信息 (Dict)
    """
    msg = email.message_from_string(raw_email)

    # 提取发件人信息
    from_raw = msg.get("From", "").strip()
    from_display_name, from_email = parse_email_address(from_raw)

    # 提取所有 Received 头部
    received_list = msg.get_all("Received", [])

    # 初始化正文
    body = ""
    html_body = ""
    subject = decode_mime_header(msg.get("Subject", ""))
    to_addr = decode_mime_header(msg.get("To", ""))

    # 附件列表
    attachments = []

    # 处理多部分邮件（multipart）
    if msg.is_multipart():
        for part in msg.walk():
            content_type = part.get_content_type()
            content_disposition = part.get("Content-Disposition", "")

            # 检查是否为附件
            if content_disposition and 'attachment' in content_disposition.lower():
                attachment_info = parse_attachment(part)
                if attachment_info:
                    attachments.append(attachment_info)
                continue

            # 处理纯文本部分
            if content_type == "text/plain":
                payload = part.get_payload(decode=True)
                if payload:
                    body += payload.decode('utf-8', errors='ignore')

            # 处理 HTML 部分
            elif content_type == "text/html":
                payload = part.get_payload(decode=True)
                if payload:
                    html_body += payload.decode('utf-8', errors='ignore')
    else:
        # 处理单部分邮件
        content_type = msg.get_content_type()
        payload = msg.get_payload(decode=True)
        if payload:
            if content_type == "text/plain":
                body = payload.decode('utf-8', errors='ignore')
            elif content_type == "text/html":
                html_body = payload.decode('utf-8', errors='ignore')
            elif content_type.startswith('application/') or content_type.startswith('image/'):
                # 单部分附件
                attachment_info = parse_attachment(msg)
                if attachment_info:
                    attachments.append(attachment_info)

    # 从纯文本正文提取 URL
    urls = extract_urls_from_body(body)

    # 从 HTML 正文提取额外链接
    html_links = []
    html_forms = []
    if html_body:
        extractor = LinkExtractor()
        try:
            extractor.feed(html_body)
            html_links = extractor.links
            html_forms = extractor.forms
            # 添加 HTML 中的链接到总 URL 列表
            for link in html_links:
                if isinstance(link, dict):
                    url = link.get('url')
                    if url and url not in urls:
                        urls.append(url)
                elif isinstance(link, str):
                    if link not in urls:
                        urls.append(link)
        except Exception:
            pass

    # 从文本类型附件中提取 URL
    for attachment in attachments:
        content = attachment.get('content')
        if content:
            try:
                # 尝试将附件内容解码为文本
                if isinstance(content, bytes):
                    attachment_text = content.decode('utf-8', errors='ignore')
                else:
                    attachment_text = str(content)
                
                # 提取 URL
                attachment_urls = extract_urls_from_body(attachment_text)
                # 添加到总 URL 列表
                for url in attachment_urls:
                    if url not in urls:
                        urls.append(url)
            except Exception:
                pass

    # 提取邮件头信息
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

    # 解析 SPF/DKIM/DMARC 状态
    auth_results = headers.get('authentication_results', '')
    headers['spf_result'] = parse_auth_result(auth_results, 'spf')
    headers['dkim_result'] = parse_auth_result(auth_results, 'dkim')
    headers['dmarc_result'] = parse_auth_result(auth_results, 'dmarc')

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


def parse_email_address(email_addr: str) -> tuple:
    """
    解析邮箱地址，分离显示名和纯邮箱地址。

    Args:
        email_addr: 原始邮箱地址字符串，如 "John Doe <john@example.com>"

    Returns:
        tuple: (display_name, email_address)
    """
    if not email_addr:
        return ("", "")

    # 解码 MIME 编码
    email_addr = decode_mime_header(email_addr)

    # 匹配 "Display Name" <email@example.com> 格式
    match = re.match(r'["\']?([^"<>]*)["\']?\s*<([^<>]+)>', email_addr)
    if match:
        return (match.group(1).strip(), match.group(2).strip())

    # 只有邮箱地址
    if '@' in email_addr:
        email_match = re.search(r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}', email_addr)
        if email_match:
            return ("", email_match.group(0))

    return (email_addr.strip(), "")


def parse_attachment(part) -> Optional[Dict]:
    """
    解析邮件附件。

    Args:
        part: 邮件部件

    Returns:
        Dict: 包含附件信息的字典，失败返回 None
    """
    try:
        filename = part.get_filename()
        if not filename:
            # 尝试从 Content-Type 的 name 参数获取
            content_type = part.get('Content-Type', '')
            name_match = re.search(r'name=["\']?([^"\';]+)', content_type)
            if name_match:
                filename = name_match.group(1).strip()

        if not filename:
            filename = "unnamed"

        # 解码文件名（处理 MIME 编码）
        filename = decode_mime_header(filename)

        # 获取内容类型
        content_type = part.get_content_type()

        # 获取 payload 数据
        payload = part.get_payload(decode=True)
        size = len(payload) if payload else 0

        # 计算哈希值
        md5_hash = ""
        sha256_hash = ""
        if payload:
            md5_hash = hashlib.md5(payload).hexdigest()
            sha256_hash = hashlib.sha256(payload).hexdigest()

        # 检查是否为可疑文件类型
        is_suspicious_type = check_suspicious_file_type(filename, content_type)

        return {
            'filename': filename,
            'content_type': content_type,
            'size': size,
            'md5': md5_hash,
            'sha256': sha256_hash,
            'is_suspicious_type': is_suspicious_type,
            'content': payload  # 保留文件内容用于沙箱分析
        }

    except Exception as e:
        print(f"解析附件失败：{e}")
        return None


def check_suspicious_file_type(filename: str, content_type: str) -> bool:
    """
    检查文件类型是否可疑。

    Args:
        filename: 文件名
        content_type: 内容类型

    Returns:
        bool: 是否可疑
    """
    # 高风险扩展名（可执行文件、脚本等）
    high_risk_extensions = {
        '.exe', '.bat', '.cmd', '.com', '.pif', '.scr', '.vbs', '.vbe',
        '.js', '.jse', '.wsf', '.wsh', '.ps1', '.msi', '.msp', '.hta',
        '.cpl', '.msc', '.jar', '.dll', '.reg', '.lnk'
    }

    # 中等风险扩展名（文档宏、压缩包等）
    medium_risk_extensions = {
        '.doc', '.docm', '.xls', '.xlsm', '.ppt', '.pptm', '.dot', '.dotm',
        '.xlt', '.xltm', '.pot', '.potm', '.ppa', '.ppam', '.sldm',
        '.zip', '.rar', '.7z', '.tar', '.gz', '.iso', '.img'
    }

    # 获取文件扩展名
    ext = '.' + filename.rsplit('.', 1)[-1].lower() if '.' in filename else ''

    if ext in high_risk_extensions:
        return True

    # 检查双重扩展名（如：file.pdf.exe）
    parts = filename.lower().split('.')
    if len(parts) > 2:
        # 检查是否为伪装文件
        if parts[-2] in ['.pdf', '.doc', '.xls', '.jpg', '.png', '.txt']:
            return True

    return False


def parse_email_headers(msg: Message) -> Dict:
    """
    专门解析邮件头部的详细信息。

    Args:
        msg: email.Message 对象

    Returns:
        Dict: 包含头部详细信息的字典
    """
    headers = {
        "from": msg.get("From", ""),
        "to": msg.get("To", ""),
        "subject": msg.get("Subject", ""),
        "date": msg.get("Date", ""),
        "message_id": msg.get("Message-ID", ""),
        "mime_version": msg.get("MIME-Version", ""),
        "content_type": msg.get("Content-Type", ""),
        "received_chain": msg.get_all("Received", []),
        "return_path": msg.get("Return-Path", ""),
        "x_mailer": msg.get("X-Mailer", ""),
    }

    # 提取 SPF/DKIM/DMARC 相关头部
    headers["spf"] = msg.get("Authentication-Results", "")
    headers["dkim_signatures"] = msg.get("DKIM-Signature", "")

    return headers


def extract_urls_from_body(body: str) -> List[str]:
    """
    从邮件正文中提取所有 URL。

    Args:
        body: 邮件正文

    Returns:
        List[str]: URL 列表
    """
    if not body:
        return []
    
    # 匹配三种类型的URL：
    # 1. 以 http:// 或 https:// 开头的URL
    # 2. 以 www. 开头的URL
    # 3. 没有协议前缀但包含域名和路径的URL（如 zxcve.zncb.work/dingding）
    # 使用非捕获组 (?:...) 避免返回元组
    url_pattern = r'https?://[^\s<>"]+|www\.[^\s<>"]+|[a-zA-Z0-9][-a-zA-Z0-9]{0,62}(?:\.[a-zA-Z0-9][-a-zA-Z0-9]{0,62})+(?:/[^\s<>"]*)?'
    urls = list(set(re.findall(url_pattern, body)))
    
    # 为没有协议前缀的URL添加 http://
    processed_urls = []
    for url in urls:
        if isinstance(url, str) and not url.startswith(('http://', 'https://', 'www.')):
            processed_urls.append('http://' + url)
        elif isinstance(url, str):
            processed_urls.append(url)
    
    return processed_urls


def extract_emails_from_text(text: str) -> List[str]:
    """
    从文本中提取所有邮箱地址。

    Args:
        text: 文本内容

    Returns:
        List[str]: 邮箱地址列表
    """
    email_pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
    return list(set(re.findall(email_pattern, text)))


def parse_auth_result(auth_results: str, auth_type: str) -> str:
    """
    解析认证结果（SPF/DKIM/DMARC）。

    Args:
        auth_results: Authentication-Results 头部内容
        auth_type: 认证类型 ('spf', 'dkim', 'dmarc')

    Returns:
        str: 认证结果 ('pass', 'fail', 'none', 'unknown')
    """
    if not auth_results:
        return "none"

    auth_results = auth_results.lower()

    # 查找对应认证类型的结果
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


if __name__ == "__main__":
    # 测试示例
    test_email = """From: "Bank Security" <security@suspicious-bank.com>
To: user@example.com
Subject: 【紧急】您的账户存在异常登录！
Content-Type: multipart/mixed; boundary="boundary123"

--boundary123
Content-Type: text/plain; charset="utf-8"

尊敬的客户，

我们检测到您的账户有异常活动。请立即点击以下链接验证您的身份：
http://secure-login-verify.com/account/check

如果不立即处理，您的账户将在 24 小时内被冻结！

此致
银行安全团队

--boundary123
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"

[malicious payload]

--boundary123--
"""

    parsed = parse_email(test_email)

    print("=" * 60)
    print("邮件解析结果")
    print("=" * 60)
    print(f"发件人显示名：{parsed.get('from_display_name')}")
    print(f"发件人邮箱：{parsed.get('from_email')}")
    print(f"主题：{parsed.get('subject')}")
    print(f"URL 数量：{len(parsed.get('urls', []))}")
    print(f"附件数量：{len(parsed.get('attachments', []))}")

    for att in parsed.get('attachments', []):
        print(f"\n附件信息:")
        print(f"  文件名：{att.get('filename')}")
        print(f"  类型：{att.get('content_type')}")
        print(f"  大小：{att.get('size')} 字节")
        print(f"  MD5: {att.get('md5')}")
        print(f"  可疑类型：{att.get('is_suspicious_type')}")

    print("=" * 60)
