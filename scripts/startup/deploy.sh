#!/bin/bash
# 钓鱼邮件检测与溯源系统 - 一键部署脚本 (Linux/Mac)

set -e

# 切换到项目根目录
cd "$(dirname "$0")/../.."

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 打印带颜色的消息
print_success() { echo -e "${GREEN}[成功]${NC} $1"; }
print_error() { echo -e "${RED}[错误]${NC} $1"; }
print_info() { echo -e "${YELLOW}[信息]${NC} $1"; }

echo "========================================"
echo "钓鱼邮件检测与溯源系统 - 一键部署脚本"
echo "========================================"
echo ""

# 步骤1: 检查Python
print_info "[1/4] 检查Python环境..."
if command -v python3 &> /dev/null; then
    PYTHON=python3
    PIP=pip3
elif command -v python &> /dev/null; then
    PYTHON=python
    PIP=pip
else
    print_error "未检测到Python，请先安装Python 3.8+"
    exit 1
fi

PYTHON_VERSION=$($PYTHON --version 2>&1)
print_success "Python版本: $PYTHON_VERSION"

# 步骤2: 安装依赖
print_info "[2/4] 安装依赖包..."
$PIP install -r requirements.txt -q
if [ $? -eq 0 ]; then
    print_success "依赖安装完成"
else
    print_error "依赖安装失败"
    exit 1
fi

# 步骤3: 创建目录
print_info "[3/4] 创建目录结构..."
mkdir -p data/uploads data/logs logs uploads config
print_success "目录创建完成"

# 步骤4: 初始化配置
print_info "[4/4] 初始化配置..."
if [ ! -f config/api_config.json ]; then
    cat > config/api_config.json << EOF
{
  "virustotal": {
    "api_key": "",
    "api_url": "https://www.virustotal.com/vtapi/v2/url/report"
  },
  "email": {
    "enabled": false
  }
}
EOF
    print_success "配置文件创建完成"
else
    print_info "配置文件已存在，跳过"
fi

echo ""
echo "========================================"
echo -e "${GREEN}部署完成！${NC}"
echo "========================================"
echo ""
echo "启动方式:"
echo "  cd backend && $PYTHON run.py"
echo ""
echo "Docker部署:"
echo "  cd scripts/startup && docker-compose up -d"
echo ""
echo "访问地址:"
echo "  http://localhost:5000"
echo ""

# 询问是否启动
read -p "是否立即启动系统? (y/n): " -n 1 -r
echo ""
if [[ $REPLY =~ ^[Yy]$ ]]; then
    cd backend
    $PYTHON run.py
fi
