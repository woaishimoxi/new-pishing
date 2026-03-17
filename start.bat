@echo off
REM 面向中小型企业的轻量化钓鱼邮件检测与溯源系统
REM 启动脚本 (Windows)

echo ==========================================
echo 钓鱼邮件检测与溯源系统 - 启动脚本
echo ==========================================

REM 检查 Docker Compose 是否安装
where docker-compose >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [1/3] Docker Compose 已安装
    set COMPOSE_CMD=docker-compose
) else (
    where docker >nul 2>nul
    if %ERRORLEVEL% EQU 0 (
        echo [1/3] 使用 Docker Desktop 的 compose 命令
        set COMPOSE_CMD=docker compose
    ) else (
        echo [1/3] 未检测到 Docker
        echo 请先安装 Docker: https://www.docker.com/get-started/
        pause
        exit /b 1
    )
)

REM 检查 .env 文件
if not exist .env (
    echo [2/3] .env 文件不存在，从示例创建...
    copy .env.example .env
    echo 请编辑 .env 文件配置 VirusTotal API Key（可选）
)

REM 启动服务
echo [3/3] 启动服务...
%COMPOSE_CMD% up -d

if %ERRORLEVEL% EQU 0 (
    echo.
    echo ==========================================
    echo 系统启动成功！
    echo 访问地址：http://localhost:5000
    echo API 状态：http://localhost:5000/api/health
    echo ==========================================
    echo.
    echo 停止服务：%COMPOSE_CMD% down
    echo 查看日志：%COMPOSE_CMD% logs -f
) else (
    echo 错误：服务启动失败
)

pause
