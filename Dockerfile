# 面向中小型企业的轻量化钓鱼邮件检测与溯源系统
# Docker 镜像构建文件

# 使用官方 Python 3.9 slim 镜像作为基础，体积更小
FROM python:3.9-slim

# 设置工作目录
WORKDIR /app

# 设置环境变量
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# 安装系统依赖
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    g++ \
    curl \
    && rm -rf /var/lib/apt/lists/*

# 复制依赖文件并安装 Python 依赖
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 复制应用代码
COPY src/ ./src/

# 创建数据目录
RUN mkdir -p data models

# 暴露 Web 服务端口
EXPOSE 5000

# 健康检查
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:5000/api/health || exit 1

# 启动命令，使用 waitress 作为 WSGI 服务器（轻量级）
CMD ["python", "-m", "src.app"]
