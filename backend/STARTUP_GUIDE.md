# 钓鱼邮件检测与溯源系统 - 启动指南

## 快速启动

### 方式一：使用启动脚本（推荐）

```bash
# Windows
cd backend
python run.py

# 或使用 waitress 生产服务器
python -m waitress --port=5000 app:app
```

### 方式二：直接运行模块

```bash
cd backend
python -m app
```

### 方式三：使用 Flask CLI

```bash
cd backend
set FLASK_APP=app
flask run --host=0.0.0.0 --port=5000
```

---

## 环境准备

### 1. 安装依赖

```bash
cd backend
pip install -r requirements.txt
```

### 2. 配置环境变量（可选）

创建 `.env` 文件：

```env
# 应用环境
APP_ENV=development

# VirusTotal API
VT_API_KEY=your-api-key

# 数据库配置
DB_TYPE=sqlite
DB_PATH=data/alerts.db

# 日志级别
LOG_LEVEL=INFO
```

### 3. 配置API密钥

编辑 `config/api_config.json`：

```json
{
    "virustotal": {
        "api_key": "your-virustotal-api-key",
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
        "enabled": false
    }
}
```

---

## 访问系统

启动成功后，访问以下地址：

| 功能 | 地址 |
|------|------|
| 主页面 | http://localhost:5000/ |
| API文档 | http://localhost:5000/api/docs |
| 健康检查 | http://localhost:5000/api/detection/health |

---

## 生产环境部署

### 使用 Waitress（Windows推荐）

```bash
pip install waitress
waitress-serve --port=5000 app:app
```

### 使用 Gunicorn（Linux/Mac）

```bash
pip install gunicorn
gunicorn -w 4 -b 0.0.0.0:5000 app:app
```

### 使用 Docker

```bash
# 构建镜像
docker build -t phishing-detection .

# 运行容器
docker run -p 5000:5000 phishing-detection
```

---

## 常见问题

### Q: 启动时提示模块找不到？

```bash
# 确保在 backend 目录下运行
cd backend
python run.py
```

### Q: 数据库初始化失败？

```bash
# 确保 data 目录存在
mkdir -p data
```

### Q: VirusTotal API 无法连接？

1. 检查 API Key 是否正确
2. 检查网络连接
3. 访问 `/api/config/test` 测试连接

---

## 目录结构

```
backend/
├── app/                    # 应用主目录
│   ├── api/               # API路由
│   ├── core/              # 核心模块
│   ├── models/            # 数据模型
│   ├── services/          # 业务服务
│   ├── utils/             # 工具函数
│   └── __main__.py        # 入口文件
├── config/                # 配置文件
├── data/                  # 数据目录
├── logs/                  # 日志目录
├── models/                # ML模型
├── tests/                 # 测试用例
├── requirements.txt       # 依赖清单
└── run.py                 # 启动脚本
```
