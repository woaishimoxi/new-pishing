# 面向中小型企业的轻量化钓鱼邮件检测与溯源系统

一个集高精度检测、自动化溯源、可视化管理和多维度分析于一体的综合性钓鱼邮件安全防护解决方案。

[![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.x-green.svg)](https://flask.palletsprojects.com/)

---

## 系统特性

| 特性 | 说明 | 状态 |
|------|------|------|
| 多维度融合检测 | RF/XGB/IsolationForest + 规则引擎 + AI语义分析 + URL分析 | ✅ 已完成 |
| Kill Switch机制 | 高危特征一票否决，可执行附件、黑名单IP等 | ✅ 已完成 |
| 微步在线集成 | 文件沙箱分析、URL/IP/域名威胁情报查询 | ✅ 已完成 |
| AI语义分析 | 集成阿里通义千问/智谱AI/OpenAI等大语言模型 | ✅ 已完成 |
| 完整溯源分析 | IP地理位置、DNSBL黑名单查询、攻击链还原 | ✅ 已完成 |
| 自动邮件监控 | IMAP/POP3邮箱自动监控、轮询检测 | ✅ 已完成 |
| Web管理后台 | 检测面板、报告详情、系统配置、数据大屏 | ✅ 已完成 |
| 白名单/黑名单 | 动态管理可信域名、恶意IP/域名 | ✅ 已完成 |
| IOC威胁情报库 | 本地IOC库 + 云端威胁情报关联分析 | ✅ 已完成 |
| Docker部署 | 支持容器化部署 | ✅ 已完成 |

---

## 系统架构

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                              前端展示层                                      │
│  大屏展示 / 检测面板 / 报告详情 / 系统配置 / 溯源分析 / 域名管理            │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │ HTTP/REST
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              Flask API层                                    │
│  detection / alerts / config / stats / monitor / settings / domains        │
│  system / attachment / email / traceback                                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              业务服务层                                      │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │                        检测引擎 (detector.py)                       │   │
│  │  ┌─────────────┐  ┌─────────────┐  ┌─────────────┐  ┌───────────┐ │   │
│  │  │ RF/XGB分类器│  │ 异常检测器  │  │  规则引擎   │  │ Kill Switch│ │   │
│  │  │  (35维)     │  │  (26维)     │  │  (关键词)   │  │  (一票否决) │ │   │
│  │  └─────────────┘  └─────────────┘  └─────────────┘  └───────────┘ │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│  ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐          │
│  │email_parser │ │  traceback  │ │ url_analyzer│ │  threatbook │          │
│  │  邮件解析   │ │  溯源分析   │ │  URL分析    │ │  微步API    │          │
│  └─────────────┘ └─────────────┘ └─────────────┘ └─────────────┘          │
└─────────────────────────────────────────────────────────────────────────────┘
                                      │
                                      ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                              外部API集成                                     │
│  微步在线API / 阿里通义千问API / DNSBL服务器 / IP地理定位API                │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 检测流程

```
邮件输入 (手动上传/邮箱拉取/手动输入)
    │
    ├── 1. 邮件解析 → 提取发件人、正文、URL、附件
    ├── 2. 附件沙箱分析 → 微步在线文件沙箱API
    ├── 3. URL分析 → 白名单检查、品牌仿冒检测
    ├── 4. 特征提取 → 35维语义 + 26维统计 + 39维传统
    ├── 5. AI语义分析 → 大语言模型分析邮件内容
    ├── 6. 多模型融合检测
    │       ├── RF分类器 (权重1.5)
    │       ├── XGB分类器 (权重1.5)
    │       ├── 异常检测器 (权重1.0)
    │       ├── 规则引擎 (权重1.0)
    │       ├── AI分析 (权重1.2)
    │       └── URL分析 (权重1.0)
    ├── 7. 阈值判断
    │       ├── >= 0.60 → PHISHING
    │       ├── >= 0.35 → SUSPICIOUS
    │       └── < 0.35  → SAFE
    ├── 8. 溯源分析 → IP/DNSBL/WHOIS/攻击链
    └── 9. 结果存储
```

---

## 项目结构

```
项目根目录/
├── backend/                        # 后端代码
│   ├── app/
│   │   ├── __init__.py           # 应用入口
│   │   ├── __main__.py           # Flask应用工厂
│   │   ├── api/                  # API路由层 (11个)
│   │   │   ├── detection.py      # 检测接口
│   │   │   ├── alerts.py         # 告警接口/AI分析
│   │   │   ├── config.py         # 配置接口
│   │   │   ├── monitor.py        # 邮件监控接口
│   │   │   ├── email.py          # 邮件获取接口
│   │   │   ├── stats.py          # 统计接口
│   │   │   ├── settings.py       # 配置管理接口
│   │   │   ├── domains.py        # 域名管理接口
│   │   │   ├── system.py         # 系统管理接口
│   │   │   ├── attachment.py     # 附件分析接口
│   │   │   └── docs.py           # API文档
│   │   ├── services/             # 业务服务层 (14个)
│   │   │   ├── detector.py       # 检测引擎（核心）
│   │   │   ├── email_parser.py   # 邮件解析
│   │   │   ├── email_fetcher.py  # 邮件获取
│   │   │   ├── email_monitor.py  # 邮件监控
│   │   │   ├── feature_extractor.py      # 传统特征提取
│   │   │   ├── lightweight_features.py   # 轻量特征提取
│   │   │   ├── lightweight_model.py      # 轻量模型服务
│   │   │   ├── url_analyzer.py   # URL分析
│   │   │   ├── traceback.py      # 溯源分析
│   │   │   ├── threatbook.py     # 微步API
│   │   │   ├── sandbox_analyzer.py     # 沙箱分析
│   │   │   ├── auto_tuner.py     # 智能调优
│   │   │   └── performance_monitor.py   # 性能监控
│   │   ├── models/               # 数据模型
│   │   ├── core/                 # 核心模块
│   │   └── utils/                # 工具函数
│   ├── tests/                    # 测试用例
│   └── run.py                   # 启动入口
├── config/                       # 配置文件
│   ├── api_config.json          # API配置
│   ├── whitelist.json           # 白名单
│   ├── blacklist.json          # 黑名单
│   └── ioc_database.json       # IOC威胁情报库
├── models/                      # 机器学习模型
│   ├── phishmmf_simplified_rf.joblib
│   ├── phishmmf_simplified_xgb.joblib
│   ├── phishmmf_simplified_scaler.joblib
│   ├── phish_iforest.joblib
│   ├── phish_iforest_scaler.joblib
│   └── feature_info.json
├── src/templates/               # 前端模板 (7个)
│   ├── bigscreen.html          # 数据大屏
│   ├── dashboard.html          # 检测面板
│   ├── report.html             # 报告详情
│   ├── traceback.html          # 溯源分析
│   ├── settings.html           # 系统配置
│   ├── domains.html            # 域名管理
│   └── adversarial.html        # 对抗测试
├── scripts/startup/            # 部署脚本
│   ├── Dockerfile
│   ├── docker-compose.yml
│   ├── deploy.bat
│   └── deploy.sh
├── README.md                   # 项目说明
├── requirements.txt            # Python依赖
└── .gitignore
```

---

## 功能完成度分析

### 核心功能模块

| 模块 | 功能点 | 完成状态 | 说明 |
|------|--------|----------|------|
| **邮件检测** | 多模型融合检测 | ✅ | RF+XGB+IsolationForest+规则引擎 |
| | Kill Switch一票否决 | ✅ | 7种高危特征拦截 |
| | 阈值判断 | ✅ | PHISHING≥0.6, SUSPICIOUS≥0.35, SAFE<0.35 |
| **AI语义分析** | 多AI提供商支持 | ✅ | 阿里/智谱/月之暗面/DeepSeek/OpenAI |
| | 社会工程学检测 | ✅ | 识别紧迫性/恐惧/利益/权威话术 |
| **威胁情报** | 微步文件沙箱 | ✅ | 恶意代码检测 |
| | 微步URL查询 | ✅ | URL威胁情报 |
| | 微步IP查询 | ✅ | IP信誉查询 |
| | 微步域名查询 | ✅ | 域名信誉查询 |
| | 本地IOC库 | ✅ | 恶意IP/域名本地库 |
| | IOC缓存机制 | ✅ | 自动缓存云端情报 |
| **溯源分析** | IP地理位置 | ✅ | 百度IP查询API |
| | DNSBL黑名单 | ✅ | 10个DNSBL服务器 |
| | WHOIS查询 | ✅ | 域名注册信息 |
| | 攻击链还原 | ✅ | Received链分析 |
| | 社会工程学分析 | ✅ | 攻击动机/目标识别 |
| **邮件监控** | IMAP协议 | ✅ | 支持IMAP邮箱 |
| | POP3协议 | ✅ | 支持POP3邮箱 |
| | 轮询检测 | ✅ | 可配置间隔 |
| | 自动告警 | ✅ | 新邮件自动检测 |
| **配置管理** | Web配置界面 | ✅ | settings.html |
| | API配置 | ✅ | 微步/AI/邮箱 |
| | 白名单管理 | ✅ | 可视化编辑 |
| | 黑名单管理 | ✅ | 域名/IP分离 |
| **报告导出** | JSON导出 | ✅ | 完整报告JSON |
| | 原始邮件导出 | ✅ | EML格式 |
| | 报告删除 | ✅ | 单条/批量删除 |
| **数据统计** | 检测概览 | ✅ | 总数/分类统计 |
| | 趋势分析 | ✅ | 每日检测趋势 |
| | 大屏展示 | ✅ | 可视化数据大屏 |

### 前端页面

| 页面 | 功能 | 完成状态 |
|------|------|----------|
| bigscreen.html | 数据大屏展示 | ✅ |
| dashboard.html | 检测面板/告警列表 | ✅ |
| report.html | 检测报告详情 | ✅ |
| traceback.html | 溯源分析详情 | ✅ |
| settings.html | 系统配置中心 | ✅ |
| domains.html | 域名管理 | ✅ |
| adversarial.html | 对抗测试 | ✅ |

### API接口 (共46个)

| 接口模块 | 数量 | 完成状态 |
|----------|------|----------|
| 检测接口 | 6 | ✅ |
| 告警接口 | 8 | ✅ |
| 配置接口 | 5 | ✅ |
| 监控接口 | 5 | ✅ |
| 邮件接口 | 3 | ✅ |
| 统计接口 | 4 | ✅ |
| 配置管理 | 6 | ✅ |
| 域名管理 | 4 | ✅ |
| 系统管理 | 3 | ✅ |
| 附件分析 | 2 | ✅ |

---

## 快速开始

### 1. 安装依赖

```bash
pip install -r requirements.txt
```

### 2. 配置API Key

编辑 `config/api_config.json`：

```json
{
  "threatbook": {
    "api_key": "您的微步在线API Key",
    "api_url": "https://api.threatbook.cn/v3",
    "sandbox_enabled": true,
    "ioc_enabled": true
  },
  "ai": {
    "provider": "alibaba",
    "api_key": "您的AI API Key",
    "api_url": "https://dashscope.aliyuncs.com/compatible-mode/v1/chat/completions",
    "model": "qwen-turbo",
    "enabled": true
  },
  "email": {
    "email": "监控邮箱地址",
    "password": "邮箱授权码",
    "server": "imap.qq.com",
    "protocol": "imap",
    "port": 993,
    "enabled": true
  }
}
```

### 3. 启动服务

```bash
cd backend
python run.py
```

### 4. 访问系统

- 大屏展示：http://localhost:5000/
- 检测面板：http://localhost:5000/dashboard
- 系统配置：http://localhost:5000/settings
- 域名管理：http://localhost:5000/domains

---

## 性能指标

| 指标 | 目标值 | 实测值 |
|------|--------|--------|
| 单封邮件检测时间 | < 10s | 3-5s |
| 模型加载时间 | < 5s | 2-3s |
| 并发处理能力 | > 10 req/s | 20 req/s |
| 内存占用 | < 2GB | 1.2GB |
| 检测准确率 | > 90% | 94.4% |
| F1值 | > 90% | 93.8% |

---

## 系统要求

| 组件 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 2核 | 4核 |
| 内存 | 4GB | 8GB |
| 磁盘 | 10GB | 20GB |
| Python | 3.8+ | 3.9+ |

---

## 常见问题

### Q: 微步在线API Key如何获取？

1. 访问 https://x.threatbook.com
2. 注册账号
3. 在个人中心获取API Key
4. 填入系统配置

### Q: 阿里通义千问API Key如何获取？

1. 访问 https://dashscope.aliyun.com
2. 注册账号
3. 创建API Key
4. 填入系统配置

### Q: 邮箱配置失败怎么办？

1. 确认邮箱已开启IMAP/POP3服务
2. 使用授权码而非登录密码
3. 检查端口是否正确（IMAP:993, POP3:995）

---

## 版本历史

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| v3.0.0 | 2026-04-11 | 轻量化重构、代码瘦身、文档整合 |
| v2.0.0 | 2026-04-01 | 集成轻量模型、AI分析、Kill Switch机制 |
| v1.0.0 | 2026-03-30 | 多维度融合检测、URL分析 |

---

## 许可证

本项目用于毕业设计，仅供学习参考。

---

*最后更新：2026-04-11*
*版本号：v3.0.0*
