# 白名单配置说明

## 配置文件位置

`config/whitelist.json` - 白名单配置文件

## 配置项说明

### 1. trusted_domains - 可信域名列表

这些域名不会被标记为可疑，系统会降低对这些域名相关邮件的风险评分。

```json
"trusted_domains": [
    "qq.com",
    "deepphish.cn",
    "your-domain.com"
]
```

**添加自己的域名：**
- 如果你有自己的服务平台（如 `deepphish.cn`）
- 经常收到来自特定域名的正常邮件
- 将这些域名添加到此列表

### 2. trusted_senders - 可信发件人列表

特定邮箱地址的白名单。来自这些发件人的邮件风险评分会降低。

```json
"trusted_senders": [
    "noreply@deepphish.cn",
    "service@your-company.com"
]
```

### 3. verification_email_indicators - 验证码邮件识别词

用于识别正常的验证码邮件。邮件主题或正文中包含这些词汇时，系统会将其视为验证码邮件，降低风险评分。

```json
"verification_email_indicators": [
    "验证码",
    "verification",
    "verify",
    "code",
    "confirm",
    "激活码",
    "校验码",
    "动态密码"
]
```

**添加自定义识别词：**
- 如果你的平台使用特定的验证码描述词汇
- 将此词汇添加到列表中

### 4. suspicious_domain_keywords - 可疑域名关键词

已知的恶意域名（精确匹配）。这些域名会被标记为可疑。

```json
"suspicious_domain_keywords": [
    "paypa1.com",
    "g0ogle.com"
]
```

**注意：** 不要随意将包含正常词汇的域名添加到此列表，以免造成误报。

## 使用示例

### 场景1：避免自己平台被误报

如果你运营一个名为 `myplatform.cn` 的平台，发送验证码邮件：

1. 将 `myplatform.cn` 添加到 `trusted_domains`
2. 将发件人邮箱（如 `noreply@myplatform.cn`）添加到 `trusted_senders`
3. 如有特殊的验证码词汇，添加到 `verification_email_indicators`

### 场景2：添加合作伙伴域名

对于经常发送正常邮件的合作伙伴：

1. 将其域名添加到 `trusted_domains`
2. 系统会自动降低来自这些域名的邮件风险评分

## 修改后生效方式

配置文件修改后立即生效，无需重启系统。

## 验证配置

运行测试脚本验证配置是否正确加载：

```bash
python test_whitelist.py
```

预期输出：
- `[OK] your-domain.com 已在白名单中` - 表示配置正确
- 验证码邮件被识别为 `SAFE`
- 真正的钓鱼邮件仍被识别为 `PHISHING`
