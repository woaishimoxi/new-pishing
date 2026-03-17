#!/usr/bin/env python3
"""
邮件收取示例脚本

此脚本演示如何使用 EmailFetcher 类收取邮件并进行分析。

使用方法：
1. 配置邮箱信息（地址、密码/授权码、服务器地址）
2. 运行脚本：python fetch_emails.py

注意：
- 对于 Gmail、QQ 邮箱等，需要使用授权码而不是密码
- 确保邮箱开启了 IMAP 或 POP3 服务
"""

from src.email_fetcher import EmailFetcher


def main():
    # 配置邮箱信息
    # 注意：使用授权码而不是密码（特别是 QQ 邮箱、Gmail 等）
    email_config = {
        'email': 'your_email@example.com',  # 替换为你的邮箱
        'password': 'your_password_or_app_password',  # 替换为你的密码或授权码
        'server': 'imap.example.com',  # 替换为你的邮件服务器地址
        'protocol': 'imap',  # 可选 'imap' 或 'pop3'
        'port': None  # 默认为 993 (IMAP) 或 995 (POP3)
    }

    # 其他配置
    limit = 10  # 限制收取邮件数量
    output_dir = 'data/processed_emails'  # 输出目录

    print("=" * 60)
    print("邮件收取与分析系统")
    print("=" * 60)
    print(f"邮箱: {email_config['email']}")
    print(f"服务器: {email_config['server']}")
    print(f"协议: {email_config['protocol']}")
    print(f"限制: {limit} 封邮件")
    print(f"输出目录: {output_dir}")
    print("=" * 60)

    # 创建邮件收取器
    fetcher = EmailFetcher(
        email_address=email_config['email'],
        password=email_config['password'],
        server=email_config['server'],
        protocol=email_config['protocol'],
        port=email_config['port']
    )

    # 运行
    results = fetcher.run(limit=limit, output_dir=output_dir)

    print("=" * 60)
    print("运行完成!")
    print("=" * 60)


if __name__ == '__main__':
    main()
