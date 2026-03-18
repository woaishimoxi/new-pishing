# 钓鱼邮件检测与溯源系统 API 文档

## 概述

本文档描述了钓鱼邮件检测与溯源系统的RESTful API接口规范。

- **基础URL**: `http://localhost:5000`
- **版本**: v2.0.0
- **编码**: UTF-8
- **格式**: JSON

---

## 目录

1. [检测接口](#1-检测接口)
2. [告警管理接口](#2-告警管理接口)
3. [配置管理接口](#3-配置管理接口)
4. [统计接口](#4-统计接口)
5. [邮件收取接口](#5-邮件收取接口)
6. [错误码说明](#6-错误码说明)

---

## 1. 检测接口

### 1.1 健康检查

检查服务是否正常运行。

**请求**

```
GET /api/detection/health
```

**响应**

```json
{
    "status": "healthy",
    "service": "Phishing Detection System",
    "version": "2.0.0"
}
```

---

### 1.2 分析邮件

分析原始邮件内容，返回检测结果。

**请求**

```
POST /api/detection/analyze
Content-Type: application/json
```

**请求体**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| email | string | 是 | 原始邮件内容 |
| source | string | 否 | 来源标识，默认"手动输入" |
| email_uid | string | 否 | 邮件唯一标识（用于去重） |

**请求示例**

```json
{
    "email": "From: sender@example.com\nTo: recipient@example.com\nSubject: Test\n\nThis is a test email.",
    "source": "手动输入"
}
```

**响应参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| id | integer | 告警记录ID |
| label | string | 判定结果：PHISHING/SUSPICIOUS/SAFE |
| confidence | float | 置信度 (0-1) |
| reason | string | 判定原因说明 |
| module_scores | object | 各模块评分 |
| parsed | object | 解析后的邮件信息 |
| features | object | 特征向量 |
| attachments | array | 附件信息列表 |
| traceback | object | 溯源分析结果 |
| url_analysis | object | URL分析结果 |
| sandbox_analysis | object | 沙箱分析结果 |

**响应示例**

```json
{
    "id": 123,
    "label": "PHISHING",
    "confidence": 0.92,
    "reason": "邮件认证失败（SPF/DKIM/DMARC全部失败）；发件人显示名称与邮箱不匹配；包含可执行文件附件",
    "module_scores": {
        "header": 0.8,
        "url": 0.3,
        "text": 0.4,
        "attachment": 0.75,
        "html": 0.2
    },
    "parsed": {
        "from": "\"PayPal Security\" <security@paypa1.com>",
        "from_display_name": "PayPal Security",
        "from_email": "security@paypa1.com",
        "to": "victim@example.com",
        "subject": "Urgent: Verify Your Account",
        "body": "Please click the link below...",
        "url_count": 3,
        "attachment_count": 1
    },
    "features": {
        "is_suspicious_from_domain": 1,
        "spf_fail": 1,
        "dkim_fail": 1,
        "dmarc_fail": 1,
        "from_display_name_mismatch": 1
    },
    "traceback": {
        "email_source": {
            "source_ip": "192.168.1.100",
            "geolocation": {
                "country": "United States",
                "city": "Los Angeles"
            }
        },
        "risk_indicators": [
            {
                "type": "BLACKLISTED_IP",
                "description": "源 IP 被黑名单标记",
                "severity": "high"
            }
        ]
    },
    "url_analysis": {
        "max_risk_level": "HIGH",
        "max_risk_score": 85,
        "valid_urls": [
            {
                "url": "http://paypa1-verify.com/login",
                "risk_level": "HIGH",
                "risk_score": 85,
                "reasons": ["新域名（5天）", "疑似品牌滥用: paypal"]
            }
        ]
    },
    "sandbox_analysis": {
        "enabled": true,
        "has_sandbox_analysis": true,
        "sandbox_detected": false,
        "max_detection_ratio": 0.0
    }
}
```

---

### 1.3 上传邮件文件

上传邮件文件进行分析。

**请求**

```
POST /api/detection/upload
Content-Type: multipart/form-data
```

**请求参数**

| 参数 | 类型 | 必填 | 说明 |
|------|------|------|------|
| file | file | 是 | 邮件文件（支持.eml, .msg格式） |

**响应**

与 [1.2 分析邮件](#12-分析邮件) 响应格式相同。

---

## 2. 告警管理接口

### 2.1 获取告警列表

分页获取告警记录列表。

**请求**

```
GET /api/alerts?page=1&per_page=20&label=PHISHING
```

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| page | integer | 否 | 1 | 页码 |
| per_page | integer | 否 | 20 | 每页数量 |
| label | string | 否 | - | 筛选标签：PHISHING/SUSPICIOUS/SAFE |

**响应**

```json
{
    "alerts": [
        {
            "id": 123,
            "from_addr": "sender@example.com",
            "from_email": "sender@example.com",
            "to_addr": "recipient@example.com",
            "subject": "Test Email",
            "detection_time": "2024-01-15T10:30:00",
            "label": "PHISHING",
            "confidence": 0.92,
            "source_ip": "192.168.1.100",
            "source": "手动输入"
        }
    ],
    "total": 100,
    "page": 1,
    "per_page": 20,
    "total_pages": 5
}
```

---

### 2.2 获取告警详情

获取单个告警的详细信息。

**请求**

```
GET /api/alerts/{id}
```

**路径参数**

| 参数 | 类型 | 说明 |
|------|------|------|
| id | integer | 告警ID |

**响应**

```json
{
    "id": 123,
    "from_addr": "sender@example.com",
    "from_display_name": "Sender Name",
    "from_email": "sender@example.com",
    "to_addr": "recipient@example.com",
    "subject": "Test Email",
    "detection_time": "2024-01-15T10:30:00",
    "label": "PHISHING",
    "confidence": 0.92,
    "source_ip": "192.168.1.100",
    "risk_indicators": [
        {
            "type": "BLACKLISTED_IP",
            "description": "源 IP 被黑名单标记",
            "severity": "high"
        }
    ],
    "source": "手动输入",
    "parsed": {
        "from": "sender@example.com",
        "subject": "Test Email",
        "url_count": 3,
        "attachment_count": 1
    },
    "traceback": {},
    "attachments": [],
    "urls": ["https://example.com"],
    "headers": {}
}
```

---

### 2.3 删除告警

删除单个告警记录。

**请求**

```
DELETE /api/alerts/{id}
```

**响应**

```json
{
    "status": "success",
    "message": "报告已删除"
}
```

---

### 2.4 批量删除告警

批量删除多个告警记录。

**请求**

```
DELETE /api/alerts/batch
Content-Type: application/json
```

**请求体**

```json
{
    "ids": [1, 2, 3, 4, 5]
}
```

**响应**

```json
{
    "status": "success",
    "message": "成功删除 5 条报告",
    "deleted_count": 5
}
```

---

## 3. 配置管理接口

### 3.1 获取配置

获取当前系统配置。

**请求**

```
GET /api/config
```

**响应**

```json
{
    "virustotal": {
        "api_key": "your-api-key",
        "api_url": "https://www.virustotal.com/vtapi/v2/url/report"
    },
    "ipapi": {
        "api_url": "http://ip-api.com/json/"
    },
    "email": {
        "email": "your-email@example.com",
        "password": "your-password",
        "server": "imap.example.com",
        "protocol": "imap",
        "port": 993,
        "enabled": true
    }
}
```

---

### 3.2 更新配置

更新系统配置。

**请求**

```
POST /api/config
Content-Type: application/json
```

**请求体**

```json
{
    "virustotal": {
        "api_key": "new-api-key"
    },
    "email": {
        "email": "new-email@example.com",
        "password": "new-password",
        "server": "imap.new-server.com",
        "protocol": "imap",
        "port": 993,
        "enabled": true
    }
}
```

**响应**

```json
{
    "status": "success",
    "message": "配置已保存"
}
```

---

### 3.3 测试VirusTotal API连接

测试VirusTotal API是否可用。

**请求**

```
GET /api/config/test
```

**响应**

```json
{
    "status": "success",
    "message": "VirusTotal API 连接成功"
}
```

---

### 3.4 测试邮箱连接

测试邮箱服务器连接是否正常。

**请求**

```
GET /api/config/test-email
```

**响应**

```json
{
    "status": "success",
    "message": "邮箱连接成功"
}
```

---

## 4. 统计接口

### 4.1 获取概览统计

获取检测统计概览数据。

**请求**

```
GET /api/stats/overview
```

**响应**

```json
{
    "total": 1000,
    "phishing": 150,
    "suspicious": 250,
    "normal": 600,
    "today": 25,
    "trend": [
        {
            "day": "2024-01-15",
            "count": 25,
            "phish_count": 5,
            "suspicious_count": 8,
            "safe_count": 12
        }
    ]
}
```

---

### 4.2 获取每日统计

获取每日检测统计数据。

**请求**

```
GET /api/stats/daily?days=7
```

**查询参数**

| 参数 | 类型 | 必填 | 默认值 | 说明 |
|------|------|------|--------|------|
| days | integer | 否 | 7 | 统计天数 |

**响应**

```json
[
    {
        "day": "2024-01-15",
        "total": 25,
        "phishing": 5,
        "suspicious": 8,
        "normal": 12
    },
    {
        "day": "2024-01-14",
        "total": 30,
        "phishing": 7,
        "suspicious": 10,
        "normal": 13
    }
]
```

---

## 5. 邮件收取接口

### 5.1 收取邮件

从配置的邮箱服务器收取新邮件。

**请求**

```
POST /api/email/fetch
```

**响应**

```json
{
    "status": "success",
    "message": "成功获取 5 封新邮件",
    "emails": [
        {
            "id": "1",
            "uid": "ABC123",
            "hash": "md5hash...",
            "raw": "From: sender@example.com..."
        }
    ]
}
```

---

## 6. 错误码说明

### HTTP状态码

| 状态码 | 说明 |
|--------|------|
| 200 | 请求成功 |
| 400 | 请求参数错误 |
| 404 | 资源不存在 |
| 500 | 服务器内部错误 |

### 业务错误码

| 错误码 | 说明 |
|--------|------|
| EMAIL_PARSE_ERROR | 邮件解析失败 |
| FEATURE_EXTRACTION_ERROR | 特征提取失败 |
| DETECTION_ERROR | 检测过程失败 |
| CONFIGURATION_ERROR | 配置错误 |
| DATABASE_ERROR | 数据库操作失败 |
| API_ERROR | 外部API调用失败 |
| VALIDATION_ERROR | 参数验证失败 |
| FILE_UPLOAD_ERROR | 文件上传失败 |
| AUTHENTICATION_ERROR | 认证失败 |
| RATE_LIMIT_ERROR | 请求频率超限 |
| MODEL_NOT_FOUND | 模型文件未找到 |
| SERVICE_UNAVAILABLE | 服务不可用 |

### 错误响应格式

```json
{
    "error": "VALIDATION_ERROR",
    "message": "Invalid email format",
    "details": {
        "field": "email"
    }
}
```

---

## 附录

### A. 判定结果说明

| 结果 | 置信度范围 | 说明 |
|------|-----------|------|
| PHISHING | ≥ 70% | 高置信度钓鱼邮件，建议直接隔离 |
| SUSPICIOUS | 40% - 70% | 可疑邮件，建议人工复核 |
| SAFE | < 40% | 正常邮件 |

### B. 模块评分说明

| 模块 | 说明 | 评分范围 |
|------|------|---------|
| header | 邮件头分析 | 0-1 |
| url | URL风险分析 | 0-1 |
| text | 文本内容分析 | 0-1 |
| attachment | 附件风险分析 | 0-1 |
| html | HTML结构分析 | 0-1 |

### C. 风险等级说明

| 等级 | 分数范围 | 说明 |
|------|---------|------|
| HIGH | ≥ 60 | 高风险，建议拦截 |
| MEDIUM | 30 - 60 | 中等风险，建议警告 |
| LOW | 1 - 30 | 低风险，可放行 |
| SAFE | 0 | 安全 |

---

**文档版本**: v2.0.0  
**更新日期**: 2024-01-15
