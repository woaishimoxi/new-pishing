#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
创建使用.zip附件的测试邮件
.zip文件会触发沙箱分析，但不会触发可执行文件检测
"""
import sys
import os
import base64
import zipfile
import io

sys.stdout.reconfigure(encoding='utf-8')

print("=" * 60)
print("创建使用.zip附件的测试邮件")
print("=" * 60)

# 创建一个包含可疑内容的zip文件
zip_buffer = io.BytesIO()
with zipfile.ZipFile(zip_buffer, 'w', zipfile.ZIP_DEFLATED) as zf:
    # 添加一个包含恶意URL的文本文件
    zf.writestr('malicious_content.txt', """
IMPORTANT: Your account has been compromised!

Please verify your credentials immediately:
http://phishing-site.com/verify?token=abc123

Download the security patch:
http://malware-download.com/security_update.exe

Contact our C2 server:
malicious-c2-server.com
""")
    
    # 添加一个包含敏感信息的文件
    zf.writestr('credentials.txt', """
Username: admin
Password: P@ssw0rd123
Bank Account: 1234-5678-9012-3456
""")

zip_content = zip_buffer.getvalue()
zip_b64 = base64.b64encode(zip_content).decode()

print(f"ZIP文件大小: {len(zip_content)} bytes")

# 创建EML邮件
eml_content = f"""From: security@company-alert.xyz
To: user@company.com
Subject: Urgent Security Update Required
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary789"
X-Priority: 1

--boundary789
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64

PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6QXJpYWwsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweCI+
PHA+RGVhciBVc2VyLDwvcD4KPHA+V2UgaGF2ZSBkZXRlY3RlZCB1bnVzdWFsIGFjdGl2aXR5IG9uIH
lvdXIgYWNjb3VudC4gUGxlYXNlIHJldmlldyB0aGUgYXR0YWNoZWQgc2VjdXJpdHkgdXBkYXRlIGlt
bWVkaWF0ZWx5LjwvcD4KPHA+VGhhbmsgeW91LTwvcD4KPHA+SVQgU2VjdXJpdHkgVGVhbTwvcD4KPC9k
aXY+

--boundary789
Content-Type: application/zip; name="security_update.zip"
Content-Disposition: attachment; filename="security_update.zip"
Content-Transfer-Encoding: base64

{zip_b64}

--boundary789--
"""

# 保存EML文件
output_path = os.path.join(os.getcwd(), 'test_zip_attachment.eml')
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(eml_content)

print(f"\n测试邮件已生成: {output_path}")
print(f"\n邮件特征:")
print(f"  发件人: security@company-alert.xyz")
print(f"  主题: Urgent Security Update Required")
print(f"  附件: security_update.zip")

print(f"\nKill Switch分析:")
print(f"  - .zip文件不是可执行文件类型 ✓")
print(f"  - 不会触发'包含可执行文件附件'规则 ✓")
print(f"  - 会被沙箱分析器接受分析 ✓")

print("\n" + "=" * 60)
print("生成完成")
print("=" * 60)
