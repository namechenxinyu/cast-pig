#!/bin/bash
# 投屏猪 · Linux 启动器
cd "$(dirname "$0")"
if ! command -v python3 >/dev/null; then
    echo "未找到 python3，请先安装" ; exit 1
fi
if ! python3 -c "import tkinter" 2>/dev/null; then
    echo "缺少 tkinter，Deepin/Ubuntu 可用: sudo apt install python3-tk" ; exit 1
fi
exec python3 cast_pig.py
