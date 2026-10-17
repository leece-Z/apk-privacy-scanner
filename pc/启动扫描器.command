#!/bin/bash
# APK 隐私安全扫描器 — macOS 启动脚本
# 双击运行或在终端执行: bash 启动扫描器.command

cd "$(dirname "$0")"

echo ""
echo "  ========================================"
echo "    APK 隐私安全扫描器 v1.0"
echo "  ========================================"
echo ""

# 检查 Python3
if ! command -v python3 &> /dev/null; then
    echo "[错误] 未找到 Python3，请先安装"
    echo "下载地址：https://www.python.org/downloads/"
    echo ""
    read -p "按任意键退出..."
    exit 1
fi

# 检查并安装依赖
echo "[*] 检查依赖..."
python3 -c "import androguard" 2>/dev/null
if [ $? -ne 0 ]; then
    echo "[*] 正在安装 androguard..."
    python3 -m pip install androguard -q
    echo "[OK] 安装完成"
fi

echo "[*] 启动扫描器..."
echo ""

python3 "$(dirname "$0")/apk_scanner_gui.py"

read -p "按任意键退出..."
