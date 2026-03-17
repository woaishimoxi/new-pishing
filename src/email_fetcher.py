"""
邮件收取模块
该模块负责连接到邮箱服务器，收取邮件，解析邮件，提取特征，检测邮件是否为钓鱼邮件，并存储结果。
"""
import imaplib
import poplib
import email
import time
import json
import os
from datetime import datetime
from typing import List, Dict, Optional
from concurrent.futures import ThreadPoolExecutor

from parse_email import parse_email
from features import build_feature_vector
from detector import PhishingDetector, analyze_phishing_risk
from email_traceback import generate_traceback_report


class EmailFetcher:
    """
    邮件收取器类
    支持 POP3 和 IMAP 协议
    """

    def __init__(self, email_address: str, password: str, server: str, protocol: str = 'imap', port: Optional[int] = None):
        """
        初始化邮件收取器

        Args:
            email_address: 邮箱地址
            password: 邮箱密码（或授权码）
            server: 邮件服务器地址
            protocol: 协议，可选 'imap' 或 'pop3'
            port: 端口号，如果为 None，则使用默认端口
        """
        self.email_address = email_address
        self.password = password
        self.server = server
        self.protocol = protocol.lower()
        self.port = port or self._get_default_port()
        self.connection = None
        self.detector = PhishingDetector()

    def _get_default_port(self) -> int:
        """获取默认端口"""
        if self.protocol == 'imap':
            return 993  # IMAP SSL
        elif self.protocol == 'pop3':
            return 995  # POP3 SSL
        else:
            raise ValueError(f"不支持的协议: {self.protocol}")

    def connect(self) -> bool:
        """
        连接到邮件服务器

        Returns:
            bool: 是否连接成功
        """
        try:
            if self.protocol == 'imap':
                self.connection = imaplib.IMAP4_SSL(self.server, self.port)
                self.connection.login(self.email_address, self.password)
                print(f"成功连接到 IMAP 服务器: {self.server}")
            elif self.protocol == 'pop3':
                self.connection = poplib.POP3_SSL(self.server, self.port)
                self.connection.user(self.email_address)
                self.connection.pass_(self.password)
                print(f"成功连接到 POP3 服务器: {self.server}")
            return True
        except Exception as e:
            print(f"连接失败: {e}")
            self.connection = None
            return False

    def disconnect(self):
        """断开连接"""
        if self.connection:
            try:
                if self.protocol == 'imap':
                    self.connection.logout()
                elif self.protocol == 'pop3':
                    self.connection.quit()
                print("已断开连接")
            except Exception as e:
                print(f"断开连接失败: {e}")
            finally:
                self.connection = None

    def mark_as_seen(self, msg_id: str):
        """
        标记邮件为已读

        Args:
            msg_id: 邮件ID
        """
        if not self.connection or self.protocol != 'imap':
            return
        
        try:
            self.connection.store(msg_id, '+FLAGS', '\\Seen')
            print(f"邮件 {msg_id} 已标记为已读")
        except Exception as e:
            print(f"标记邮件为已读失败: {e}")

    def fetch_emails(self, limit: int = 10, only_unseen: bool = True) -> List[Dict]:
        """
        收取邮件

        Args:
            limit: 限制收取邮件数量
            only_unseen: 是否只收取未读邮件

        Returns:
            List[Dict]: 邮件列表
        """
        if not self.connection:
            print("未连接到服务器")
            return []

        emails = []
        try:
            if self.protocol == 'imap':
                self.connection.select('INBOX')
                # 只收取未读邮件
                search_criteria = 'UNSEEN' if only_unseen else 'ALL'
                status, messages = self.connection.search(None, search_criteria)
                message_ids = messages[0].split()[-limit:]

                for msg_id in message_ids:
                    # 获取邮件内容和UID
                    status, data = self.connection.fetch(msg_id, '(RFC822 UID)')
                    uid = None
                    raw_email = None
                    
                    for response_part in data:
                        if isinstance(response_part, tuple):
                            # 解析邮件内容
                            if b'RFC822' in response_part[0]:
                                raw_email = response_part[1].decode('utf-8', errors='ignore')
                            # 解析UID - 尝试多种格式
                            uid_str = response_part[0].decode('utf-8', errors='ignore')
                            import re
                            # 标准格式: UID 123
                            uid_match = re.search(r'UID\s+(\d+)', uid_str)
                            if uid_match:
                                uid = uid_match.group(1)
                            # QQ邮箱可能的格式
                            elif re.search(r'\d+\s+\(UID', uid_str):
                                qq_match = re.search(r'(\d+)\s+\(UID', uid_str)
                                if qq_match:
                                    uid = qq_match.group(1)
                            # 其他可能的格式
                            elif b'UID' in response_part[0]:
                                # 尝试提取数字部分
                                num_match = re.search(r'(\d+)', uid_str)
                                if num_match:
                                    uid = num_match.group(1)
                    
                    # 如果实在拿不到UID，用msg_id临时替代
                    if not uid:
                        uid = msg_id.decode('utf-8')
                        print(f"警告：未获取到标准 UID，使用消息序列号 {uid}")
                    
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

            print(f"成功收取 {len(emails)} 封邮件")
        except Exception as e:
            print(f"收取邮件失败: {e}")

        return emails

    def process_email(self, raw_email: str) -> Dict:
        """
        处理邮件

        Args:
            raw_email: 原始邮件字符串

        Returns:
            Dict: 处理结果
        """
        try:
            # 解析邮件
            parsed = parse_email(raw_email)

            # 提取特征
            features = build_feature_vector(parsed)

            # 分析（二分类）
            label, confidence, reason = analyze_phishing_risk(parsed, features)

            # 生成溯源报告
            traceback_report = generate_traceback_report(parsed)

            # 构建结果
            result = {
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
                'traceback': traceback_report,
                'processed_at': datetime.now().isoformat()
            }

            return result
        except Exception as e:
            print(f"处理邮件失败: {e}")
            return {
                'label': 'ERROR',
                'confidence': 0.0,
                'reason': f'处理失败: {str(e)}',
                'processed_at': datetime.now().isoformat()
            }

    def process_emails(self, emails: List[Dict], max_workers: int = 4) -> List[Dict]:
        """
        批量处理邮件

        Args:
            emails: 邮件列表
            max_workers: 最大工作线程数

        Returns:
            List[Dict]: 处理结果列表
        """
        results = []

        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_to_email = {executor.submit(self.process_email, email['raw']): email for email in emails}
            for future in future_to_email:
                try:
                    result = future.result()
                    email = future_to_email[future]
                    result['email_id'] = email['id']
                    results.append(result)
                except Exception as e:
                    print(f"处理邮件时发生异常: {e}")

        return results

    def save_results(self, results: List[Dict], output_dir: str = 'data/processed_emails'):
        """
        保存处理结果

        Args:
            results: 处理结果列表
            output_dir: 输出目录
        """
        os.makedirs(output_dir, exist_ok=True)

        for result in results:
            # 生成文件名
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            email_id = result.get('email_id', 'unknown')
            filename = f"{timestamp}_{email_id}.json"
            filepath = os.path.join(output_dir, filename)

            # 保存结果
            try:
                with open(filepath, 'w', encoding='utf-8') as f:
                    json.dump(result, f, indent=2, ensure_ascii=False)
                print(f"结果已保存到: {filepath}")
            except Exception as e:
                print(f"保存结果失败: {e}")

    def run(self, limit: int = 10, output_dir: str = 'data/processed_emails') -> List[Dict]:
        """
        运行完整流程

        Args:
            limit: 限制收取邮件数量
            output_dir: 输出目录

        Returns:
            List[Dict]: 处理结果列表
        """
        print("开始收取邮件...")
        
        # 连接服务器
        if not self.connect():
            return []

        try:
            # 收取邮件
            emails = self.fetch_emails(limit)

            if not emails:
                print("没有收到邮件")
                return []

            # 处理邮件
            print("开始处理邮件...")
            results = self.process_emails(emails)

            # 保存结果
            print("保存处理结果...")
            self.save_results(results, output_dir)

            # 统计结果
            phishing_count = sum(1 for r in results if r.get('label') == 'PHISHING')
            safe_count = sum(1 for r in results if r.get('label') == 'SAFE')
            error_count = sum(1 for r in results if r.get('label') == 'ERROR')

            print(f"\n处理完成!")
            print(f"总邮件数: {len(results)}")
            print(f"钓鱼邮件数: {phishing_count}")
            print(f"正常邮件数: {safe_count}")
            print(f"处理失败数: {error_count}")

            return results
        finally:
            # 断开连接
            self.disconnect()


def main():
    """主函数"""
    import argparse

    parser = argparse.ArgumentParser(description='邮件收取和分析工具')
    parser.add_argument('--email', required=True, help='邮箱地址')
    parser.add_argument('--password', required=True, help='邮箱密码或授权码')
    parser.add_argument('--server', required=True, help='邮件服务器地址')
    parser.add_argument('--protocol', choices=['imap', 'pop3'], default='imap', help='邮件协议')
    parser.add_argument('--port', type=int, help='端口号')
    parser.add_argument('--limit', type=int, default=10, help='限制收取邮件数量')
    parser.add_argument('--output', default='data/processed_emails', help='输出目录')

    args = parser.parse_args()

    # 创建邮件收取器
    fetcher = EmailFetcher(
        email_address=args.email,
        password=args.password,
        server=args.server,
        protocol=args.protocol,
        port=args.port
    )

    # 运行
    fetcher.run(limit=args.limit, output_dir=args.output)


if __name__ == '__main__':
    main()
