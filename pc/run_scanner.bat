@echo off
chcp 65001 >nul
set PYTHONIOENCODING=utf-8
python -W ignore apk_privacy_scanner.py %*
