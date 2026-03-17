#!/bin/bash

# 面向中小型企业的轻量化钓鱼邮件检测与溯源系统
# 启动脚本

echo "=========================================="
echo "钓鱼邮件检测与溯源系统 - 启动脚本"
echo "=========================================="

# 检查 Docker Compose 是否安装
if command -v docker-compose &> /dev/null; then
    echo "[1/3] Docker Compose 已安装"
elif docker compose version &> /dev/null; then
    echo "[1/3] Docker Compose 插件已安装"
else
    echo "[1/3] 未检测到 Docker Compose，正在检查 Docker..."
    if command -v docker &> /dev/null; then
        echo "使用 Docker compose 命令（Docker Desktop）"
        COMPOSE_CMD="docker compose"
    else
        echo "错误：未安装 Docker 或 Docker Compose"
        echo "请先安装 Docker: https://www.docker.com/get-started/"
        exit 1
    fi
fi

# 检查 .env 文件
if [ ! -f .env ]; then
    echo "[2/3] .env 文件不存在，从示例创建..."
    cp .env.example .env
    echo "请编辑 .env 文件配置 VirusTotal API Key（可选）"
fi

# 启动服务
echo "[3/3] 启动服务..."
if [ -n "$COMPOSE_CMD" ]; then
    $COMPOSE_CMD up -d
else
    docker-compose up -d
fi

if [ $? -eq 0 ]; then
    echo ""
    echo "=========================================="
    echo "系统启动成功！"
    echo "访问地址：http://localhost:5000"
    echo "API 状态：http://localhost:5000/api/health"
    echo "=========================================="
    echo ""
    echo "停止服务：docker-compose down"
    echo "查看日志：docker-compose logs -f"
else
    echo "错误：服务启动失败"
    exit 1
fi
