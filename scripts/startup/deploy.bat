@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

echo ========================================
echo 钓鱼邮件检测与溯源系统 - 一键部署脚本
echo ========================================
echo.

:: 切换到项目根目录
cd /d "%~dp0\.."

:: 检查Python
echo [1/4] 检查Python环境...
python --version >nul 2>&1
if errorlevel 1 (
    echo [错误] 未检测到Python，请先安装Python 3.8+
    echo 下载地址: https://www.python.org/downloads/
    pause
    exit /b 1
)
for /f "tokens=2" %%i in ('python --version 2^>^&1') do set PYTHON_VERSION=%%i
echo [成功] Python版本: %PYTHON_VERSION%

:: 安装依赖
echo.
echo [2/4] 安装依赖包...
pip install -r requirements.txt -q
if errorlevel 1 (
    echo [错误] 依赖安装失败
    pause
    exit /b 1
)
echo [成功] 依赖安装完成

:: 创建必要目录
echo.
echo [3/4] 创建目录结构...
if not exist data mkdir data
if not exist data\uploads mkdir data\uploads
if not exist data\logs mkdir data\logs
if not exist logs mkdir logs
if not exist uploads mkdir uploads
if not exist config mkdir config
echo [成功] 目录创建完成

:: 初始化配置
echo.
echo [4/4] 初始化配置...
if not exist config\api_config.json (
    echo {> config\api_config.json
    echo   "virustotal": {>> config\api_config.json
    echo     "api_key": "",>> config\api_config.json
    echo     "api_url": "https://www.virustotal.com/vtapi/v2/url/report">> config\api_config.json
    echo   },>> config\api_config.json
    echo   "email": {>> config\api_config.json
    echo     "enabled": false>> config\api_config.json
    echo   }>> config\api_config.json
    echo }>> config\api_config.json
    echo [成功] 配置文件创建完成
) else (
    echo [跳过] 配置文件已存在
)

echo.
echo ========================================
echo 部署完成！
echo ========================================
echo.
echo 启动方式:
echo   cd backend
echo   python run.py
echo.
echo 或使用Docker:
echo   cd scripts
echo   docker-compose up -d
echo.
echo 访问地址:
echo   http://localhost:5000
echo.
echo 按任意键启动系统...
pause >nul

:: 启动系统
cd backend
python run.py
