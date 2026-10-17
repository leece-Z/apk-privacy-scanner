@echo off
chcp 65001 >nul
cd /d "%~dp0"
title APK 隐私安全扫描器

echo.
echo  ========================================
echo    APK 隐私安全扫描器 v1.0
echo  ========================================
echo.

REM 检查 Python
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未找到 Python，请先安装 Python 3
    echo 下载地址：https://www.python.org/downloads/
    echo 安装时请勾选 "Add Python to PATH"
    pause
    exit /b 1
)

REM 检查并安装依赖
echo [*] 检查依赖...
python -c "import androguard" >nul 2>&1
if %errorlevel% neq 0 (
    echo [*] 正在安装 androguard...
    python -m pip install androguard -q
    echo [OK] 安装完成
)

echo [*] 启动扫描器...
echo.

python "%~dp0apk_scanner_gui.py"

pause
