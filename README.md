# 面向中小型企业的轻量化钓鱼邮件检测与溯源系统

一个集高精度检测、自动化溯源、可视化管理和一键式部署于一体的综合性钓鱼邮件安全防护解决方案。

## 系统特性

- **轻量高效**：2 核 CPU、4GB 内存即可流畅运行
- **高精度检测**：基于 LightGBM 机器学习模型，准确率 >92%
- **多维度分析**：融合邮件头、URL、文本内容及威胁情报（44 维特征）
- **动静结合**：静态分析 + 动态沙箱分析，检测零日威胁和宏病毒
- **自动溯源**：追踪邮件传输路径和 URL 跳转链路
- **可视化界面**：直观的 Web 管理后台 + 详情展示面板
- **多种检测方式**：支持粘贴邮件内容 / 上传.eml.msg 文件
- **一键部署**：Docker Compose 快速上线

## 项目结构

```
├── src/                      # 源代码目录
│   ├── __init__.py           # 包初始化
│   ├── parse_email.py        # 邮件解析模块
│   ├── features.py           # 特征工程模块 (44 维)
│   ├── detector.py           # 检测模型模块
│   ├── email_traceback.py    # 溯源分析模块
│   ├── sandbox_analyzer.py   # 沙箱分析模块
│   ├── app.py                # Web 服务主程序
│   └── templates/            # 前端模板
│       └── dashboard.html    # 仪表盘页面
├── data/                     # 数据目录（持久化存储）
│   ├── alerts.db             # SQLite 数据库
│   ├── emails-enron.mbox     # 正常邮件数据集
│   ├── emails-phishing.mbox  # 钓鱼邮件数据集
│   ├── features-enron.csv    # 正常邮件特征
│   └── features-phishing.csv # 钓鱼邮件特征
├── models/                   # 模型目录
│   └── phish_detector.txt    # 训练好的 LightGBM 模型
├── progress/                 # 项目进度文档
│   ├── docs/                 # 文档目录
│   ├── scripts/              # 测试脚本
│   └── updates/              # 更新记录
├── Dockerfile                # Docker 镜像构建文件
├── docker-compose.yml        # Docker Compose 配置
├── requirements.txt          # Python 依赖
├── .env.example              # 环境变量示例
├── start.bat                 # Windows 启动脚本
├── start.sh                  # Linux/Mac 启动脚本
├── test_system.py            # 系统测试脚本
├── train_model.py            # 模型训练脚本
└── README.md                 # 项目说明文档
```

## 快速开始

### 方式一：Docker 部署（推荐）

1. **安装 Docker 和 Docker Compose**

```bash
# Ubuntu/Debian
curl -fsSL https://get.docker.com | sh
sudo systemctl enable docker
sudo apt-get install docker-compose-plugin
```

2. **启动系统**

```bash
./start.sh        # Linux/Mac
# 或双击 start.bat  # Windows
```

3. **访问系统**

打开浏览器访问：http://localhost:5000

### 方式二：本地开发

1. **安装 Python 环境**

```bash
# 建议 Python 3.9+
python --version
```

2. **安装依赖**

```bash
pip install -r requirements.txt
```

3. **启动服务**

```bash
python src/app.py
```

4. **访问系统**

打开浏览器访问：http://localhost:5000

## 使用方式

### 方式一：粘贴邮件内容
1. 在"粘贴邮件内容"标签页输入原始邮件内容
2. 点击"开始检测"按钮

### 方式二：上传邮件文件
1. 切换到"上传邮件文件"标签页
2. 点击上传区域或拖拽 `.eml` / `.msg` 文件
3. 点击"开始检测"按钮

### 查看邮件详情
检测结果页面右上角点击"原始邮件内容"按钮，展开查看：
- 邮件头信息 (Headers)
- 纯文本正文
- HTML 正文
- URL 列表
- 附件列表
- 原始完整邮件

## API 接口

### 健康检查
```bash
GET /api/health
```

### 粘贴邮件内容检测
```bash
POST /api/analyze
Content-Type: application/json

{
    "email": "原始邮件内容..."
}
```

### 上传邮件文件检测
```bash
POST /api/upload
Content-Type: multipart/form-data

file: <.eml or .msg file>
```

### 获取统计数据
```bash
GET /api/stats/overview
GET /api/stats/daily?days=7
```

### 获取告警记录
```bash
GET /api/alerts?page=1&per_page=20
GET /api/alerts?is_phish=true
```

### 关闭系统
```bash
POST /api/shutdown
# 仅限本地访问 (127.0.0.1)
```

## 技术架构

### 核心模块

| 模块 | 文件 | 功能 |
|------|------|------|
| 邮件解析 | `parse_email.py` | RFC 格式邮件解析、附件提取、HTML 链接分析 |
| 特征工程 | `features.py` | 44 维特征提取（邮件头/URL/文本/附件/HTML/沙箱） |
| 检测模型 | `detector.py` | LightGBM 分类器，支持真实模型/演示模式 |
| 溯源分析 | `email_traceback.py` | IP 定位、URL 跳转追踪、黑名单检查 |
| 沙箱分析 | `sandbox_analyzer.py` | 集成 VirusTotal API，动态文件分析 |
| Web 服务 | `app.py` | Flask RESTful API + SQLite 存储 |

### 特征维度 (44 维)

- **邮件头特征 (8 维)**：可疑域名、Received 跳数、SPF/DKIM/DMARC 验证
- **URL 特征 (14 维)**：域名年龄、HTTPS、短链接、IP 地址、可疑参数
- **文本特征 (7 维)**：紧急关键词、金融词汇、感叹号、大写比例
- **附件特征 (8 维)**：附件数量、可执行文件、双重扩展名、沙箱检测结果、检测率
- **HTML 特征 (5 维)**：HTML 正文、隐藏链接、表单、iframe
- **其他 (2 维)**：URL 总数、显示名不匹配

### 数据流程

```
原始邮件 → 解析 → 静态特征提取 → 动态沙箱分析 → 综合特征 → 模型预测 → 溯源分析 → 结果展示
                                                                 ↓
                                                            数据库存储
```

## 性能指标

| 指标 | 目标值 |
|------|--------|
| 准确率 | >92% |
| 误报率 | <5% |
| 静态检测耗时 | <1 秒 |
| 沙箱分析耗时 | 30 秒 - 2 分钟 |
| 空闲内存占用 | <500MB |
| 峰值内存占用 | <1.5GB |

## 配置说明

### API 配置管理

系统提供了可视化的 API 配置管理界面，可通过以下步骤进行配置：

1. 登录系统后，点击导航栏中的 "API 配置" 按钮
2. 在弹出的模态框中，可以配置以下 API：
   - **VirusTotal API**：增强 URL 威胁检测能力
   - **IP-API**：IP 地理位置查询
3. 点击 "测试连接" 按钮验证配置是否正确
4. 点击 "保存配置" 按钮保存更改

### 配置文件

配置会自动保存到 `config/api_config.json` 文件中，结构如下：

```json
{
  "virustotal": {
    "api_key": "your_virustotal_api_key",
    "api_url": "https://www.virustotal.com/vtapi/v2/url/report"
  },
  "ipapi": {
    "api_url": "http://ip-api.com/json/"
  }
}
```

### 白名单配置

系统支持通过配置文件自定义白名单，避免正常邮件被误报。

**配置文件位置：** `config/whitelist.json`

**配置项说明：**

```json
{
  "trusted_domains": [
    "qq.com",
    "deepphish.cn",
    "your-domain.com"
  ],
  "trusted_senders": [
    "noreply@deepphish.cn",
    "service@your-company.com"
  ],
  "verification_email_indicators": [
    "验证码",
    "verification",
    "verify",
    "code"
  ],
  "suspicious_domain_keywords": [
    "paypa1.com",
    "g0ogle.com"
  ]
}
```

| 配置项 | 说明 |
|--------|------|
| `trusted_domains` | 可信域名列表，系统会降低这些域名相关邮件的风险评分 |
| `trusted_senders` | 可信发件人列表，来自这些发件人的邮件更安全 |
| `verification_email_indicators` | 验证码邮件识别词，包含这些词汇的邮件会被视为验证码邮件 |
| `suspicious_domain_keywords` | 已知的恶意域名（精确匹配） |

**使用场景：**
- 如果你运营自己的服务平台（如 `deepphish.cn`），将其添加到 `trusted_domains`
- 如果经常收到来自合作伙伴的正常邮件，将其域名添加到白名单
- 系统会自动识别验证码邮件并降低风险评分

详细说明请参考 `config/README.md`

### 检测阈值

默认阈值为 0.50，可在代码中调整：

```python
detector.set_threshold(0.45)  # 调低阈值，增加敏感度
detector.set_threshold(0.60)  # 调高阈值，减少误报
```

**注意：** 白名单邮件不受阈值影响，会自动降低风险评分。

## 系统要求

| 组件 | 最低要求 | 推荐配置 |
|------|----------|----------|
| CPU | 2 核 | 4 核 |
| 内存 | 4GB | 8GB |
| 磁盘 | 1GB | 5GB |
| Python | 3.9+ | 3.11+ |

## 许可证

MIT License

## 联系方式

如有问题或建议，请通过 GitHub Issues 反馈。

---

*最后更新：2026-03-08*
*版本号：v1.3.0*
"# new-pishing" 
