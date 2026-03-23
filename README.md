# 面向中小型企业的轻量化钓鱼邮件检测与溯源系统

一个集高精度检测、自动化溯源、可视化管理和一键式部署于一体的综合性钓鱼邮件安全防护解决方案。

[![Python](https://img.shields.io/badge/Python-3.9+-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Flask-2.3+-green.svg)](https://flask.palletsprojects.com/)
[![LightGBM](https://img.shields.io/badge/LightGBM-3.3+-orange.svg)](https://lightgbm.readthedocs.io/)
[![License](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 系统特性

- **轻量高效**：2核CPU、4GB内存即可流畅运行
- **高精度检测**：基于LightGBM机器学习模型，39维特征提取
- **多维度分析**：融合邮件头、URL、文本内容及威胁情报
- **自动溯源**：追踪邮件传输路径和URL跳转链路
- **智能配置**：基于企业邮件模式自动推荐最优参数
- **性能监控**：实时记录检测响应时间和系统资源占用
- **可视化界面**：直观的Web管理后台
- **一键部署**：3步操作，10分钟内完成部署

## 项目结构

```
项目根目录/
├── backend/                    # 后端核心代码
│   ├── app/
│   │   ├── api/               # API路由层
│   │   │   ├── detection.py   # 检测分析API
│   │   │   ├── alerts.py      # 告警管理API
│   │   │   ├── config.py      # 配置管理API
│   │   │   ├── stats.py       # 统计数据API
│   │   │   ├── email.py       # 邮件获取API
│   │   │   └── system.py      # 系统管理API
│   │   ├── services/          # 业务逻辑层
│   │   │   ├── detector.py    # 邮件检测引擎
│   │   │   ├── feature_extractor.py  # 特征提取
│   │   │   ├── url_analyzer.py       # URL分析
│   │   │   ├── traceback.py          # 溯源分析
│   │   │   ├── auto_tuner.py         # 智能配置
│   │   │   └── performance_monitor.py # 性能监控
│   │   ├── core/              # 核心配置
│   │   ├── models/            # 数据模型
│   │   └── utils/             # 工具函数
│   ├── tests/                 # 测试用例
│   └── run.py                 # 启动入口
├── src/
│   └── templates/             # 前端模板
│       ├── dashboard.html     # 主界面
│       └── report.html        # 报告页面
├── config/                    # 配置文件
│   ├── api_config.json        # API配置
│   ├── whitelist.json         # 白名单 (300+域名)
│   └── ioc_database.json      # IOC威胁情报库
├── models/                    # 模型文件
│   ├── phish_detector.pkl     # LightGBM模型
│   └── feature_info.json      # 特征信息
├── data/                      # 数据目录
├── scripts/                   # 工具脚本
│   ├── startup/               # 启动脚本
│   │   ├── deploy.bat         # Windows部署
│   │   ├── deploy.sh          # Linux部署
│   │   ├── Dockerfile         # Docker配置
│   │   └── docker-compose.yml # Docker编排
│   └── resource_monitor.py    # 资源监控
├── requirements.txt           # Python依赖
└── README.md                  # 项目文档
```

## 快速开始

### 方式一：一键部署（推荐）

**Windows系统：**
```cmd
scripts\startup\deploy.bat
```

**Linux/Mac系统：**
```bash
chmod +x scripts/startup/deploy.sh
./scripts/startup/deploy.sh
```

### 方式二：Docker部署

```bash
cd scripts/startup
docker-compose up -d
```

### 方式三：手动部署

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 创建目录
mkdir -p data/uploads data/logs logs uploads

# 3. 启动服务
cd backend
python run.py
```

### 访问系统

打开浏览器访问：http://localhost:5000

## 使用方式

### 邮件检测

1. **手动输入**：在界面中粘贴邮件内容
2. **上传文件**：上传.eml或.msg格式的邮件文件
3. **自动获取**：配置邮箱后自动收取检测

### 查看检测结果

- 主界面：查看统计概览和邮件列表
- 点击邮件：查看详细检测报告
- 报告内容：风险等级、置信度、模块评分、溯源信息

### 系统配置

点击右上角齿轮图标，配置：
- VirusTotal API Key（可选）
- 邮箱服务器信息（可选）

### 智能调优

点击"系统配置" → "智能调优"，系统将自动分析邮件模式并推荐最优参数。

## API接口

### 检测相关

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/detection/health` | GET | 健康检查 |
| `/api/detection/analyze` | POST | 分析邮件 |
| `/api/detection/upload` | POST | 上传邮件文件 |

### 告警管理

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/alerts` | GET | 获取告警列表 |
| `/api/alerts/<id>` | GET | 获取告警详情 |
| `/api/alerts/<id>` | DELETE | 删除告警 |

### 统计数据

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/stats/overview` | GET | 概览统计 |
| `/api/stats/daily` | GET | 每日统计 |

### 系统管理

| 接口 | 方法 | 说明 |
|------|------|------|
| `/api/system/auto-tune` | POST | 智能参数调优 |
| `/api/system/performance` | GET | 获取性能指标 |
| `/api/system/performance/report` | GET | 生成性能报告 |

## 技术架构

### 核心模块

| 模块 | 文件 | 功能 |
|------|------|------|
| 邮件解析 | `email_parser.py` | RFC格式邮件解析、附件提取 |
| 特征工程 | `feature_extractor.py` | 39维特征提取 |
| 检测模型 | `detector.py` | LightGBM分类器 |
| 溯源分析 | `traceback.py` | IP定位、URL追踪 |
| URL分析 | `url_analyzer.py` | VirusTotal集成 |
| 智能配置 | `auto_tuner.py` | 参数自动推荐 |
| 性能监控 | `performance_monitor.py` | 响应时间记录 |

### 特征维度 (39维)

- **邮件头特征 (8维)**：可疑域名、SPF/DKIM/DMARC验证
- **URL特征 (14维)**：域名年龄、HTTPS、短链接、IP地址
- **文本特征 (7维)**：紧急关键词、金融词汇、感叹号
- **附件特征 (5维)**：可执行文件、双重扩展名
- **HTML特征 (5维)**：隐藏链接、表单、iframe

## 性能指标

| 指标 | 目标值 | 实测值 |
|------|--------|--------|
| 检测准确率 | ≥90% | 95%+ |
| 误报率 | ≤5% | <3% |
| 检测响应时间 | <500ms | <100ms |
| 内存占用 | <2GB | <500MB |
| CPU占用 | <50% | <30% |

## 配置说明

### API配置

配置文件：`config/api_config.json`

```json
{
  "virustotal": {
    "api_key": "your_api_key",
    "api_url": "https://www.virustotal.com/vtapi/v2/url/report"
  },
  "email": {
    "email": "your_email@example.com",
    "password": "your_password",
    "server": "imap.example.com",
    "protocol": "imap",
    "port": 993,
    "enabled": false
  }
}
```

### 白名单配置

配置文件：`config/whitelist.json`

包含300+可信域名，覆盖：
- 中国互联网服务（QQ、阿里、腾讯、百度等）
- 国际科技公司（Google、Microsoft、Apple等）
- 邮件服务商（Gmail、Outlook、Yahoo等）
- 银行金融机构（ICBC、CCB、HSBC等）

## 系统要求

| 组件 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 2核 | 4核 |
| 内存 | 4GB | 8GB |
| 磁盘 | 10GB | 20GB |
| Python | 3.8+ | 3.9+ |

## 常见问题

### Q: 如何获取VirusTotal API Key？

1. 访问 https://www.virustotal.com
2. 注册账号
3. 在设置中获取API Key
4. 填入系统配置

### Q: 邮箱配置失败怎么办？

1. 确认邮箱已开启IMAP/POP3服务
2. 使用授权码而非登录密码
3. 检查端口是否正确（IMAP:993, POP3:995）

### Q: 如何提高检测准确率？

1. 配置VirusTotal API Key
2. 更新白名单配置
3. 使用智能调优功能

## 项目文档

- [项目文件说明文档](01_项目文件说明文档.md)
- [项目蓝图与使用说明](02_项目蓝图与使用说明.md)

## 版本历史

| 版本 | 日期 | 更新内容 |
|------|------|----------|
| v2.0.0 | 2026-03-22 | 39维特征模型、智能配置、性能监控 |
| v1.0.0 | 2024-01-01 | 初始版本 |

## 许可证

本项目用于毕业设计，仅供学习参考。

## 联系方式

如有问题或建议，请通过 GitHub Issues 反馈。

---

*最后更新：2026-03-22*
*版本号：v2.0.0*
