# 钓鱼邮件检测与溯源系统 - 项目文件清单

## 📁 code/ (源代码目录)

### 根目录文件
| 文件名 | 大小 | 说明 |
|--------|------|------|
| `.env.example` | 309B | 环境变量示例配置文件 |
| `.gitignore` | 369B | Git 忽略规则 |
| `Dockerfile` | 1KB | Docker 镜像构建文件 |
| `README.md` | 4.5KB | 项目说明文档 |
| `docker-compose.yml` | 674B | Docker Compose 配置 |
| `requirements.txt` | 331B | Python 依赖列表 |
| `start.bat` | 1.4KB | Windows 启动脚本 |
| `start.sh` | 1.6KB | Linux/Mac 启动脚本 |
| `test_system.py` | 4.5KB | 系统测试脚本 |

### src/ (源代码目录)
| 文件名 | 大小 | 说明 |
|--------|------|------|
| `__init__.py` | 93B | 包初始化文件 |
| `app.py` | 13KB | Flask Web 服务主程序 |
| `detector.py` | 9.8KB | LightGBM 检测模型 |
| `email_traceback.py` | 12KB | 邮件溯源分析模块 |
| `features.py` | 19.7KB | 特征工程模块 (41 维) |
| `parse_email.py` | 15.6KB | 邮件解析模块 |
| `templates/dashboard.html` | ~46KB | Web 前端仪表盘页面 |

### data/ (数据存储目录)
| 文件名 | 大小 | 说明 |
|--------|------|------|
| `alerts.db` | 24KB | SQLite 告警数据库 |

### models/ (模型目录)
- 当前为空（使用演示模式规则）

---

## 🗑️ 已删除的无用文件

| 文件名 | 原因 |
|--------|------|
| `nul` | Windows 空设备名误创的空文件 |
| `uploads/` (空目录) | 上传功能不保存文件到磁盘 |
| `static/` (空目录) | 未使用静态资源，所有 CSS/JS 来自 CDN |

---

## ✅ 当前项目状态

**代码目录已整理干净：**
- 只保留必要的源代码和配置文件
- 删除了无用的空目录
- 删除了误创的空文件 `nul`

---

*更新时间：2026-02-26*
