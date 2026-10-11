@echo off
rem ============================================
rem  投屏猪 v1.4 · Windows 启动器
rem  自动检查依赖, 缺 ffmpeg 时可一键下载
rem ============================================
cd /d %~dp0
title 投屏猪启动器

rem ---- 检查 Python ----
where python >nul 2>nul
if errorlevel 1 (
    echo [缺依赖] 未找到 Python。
    echo 请到 https://www.python.org/downloads/ 安装一次,
    echo 安装时务必勾选 "Add Python to PATH", 然后重新双击本文件。
    pause
    exit /b 1
)
python -c "import tkinter" >nul 2>nul
if errorlevel 1 (
    echo [缺依赖] 当前 Python 不含 tkinter, 请使用 python.org 官方完整版。
    pause
    exit /b 1
)

rem ---- 检查 ffmpeg: 本目录 → PATH ----
if exist ffmpeg.exe goto run
where ffmpeg >nul 2>nul
if not errorlevel 1 goto run

echo [缺依赖] 未找到 ffmpeg。
set /p YN=是否自动下载? 约40MB, 来自 ffmpeg 官方构建站 [Y/N]:
if /i not "%YN%"=="Y" (
    echo 跳过下载。也可手动下载 ffmpeg.exe 放到本文件夹后重新运行。
    pause
    goto run
)
echo 正在下载, 请稍候 ...
curl -L --progress-bar -o ffmpeg.zip https://www.gyan.dev/ffmpeg/builds/ffmpeg-release-essentials.zip
if not exist ffmpeg.zip (
    echo 下载失败, 请检查网络, 或手动下载 ffmpeg.exe 放到本文件夹。
    pause
    goto run
)
powershell -NoProfile -Command "Expand-Archive -Force ffmpeg.zip extract_tmp" >nul
for /r %%f in (extract_tmp\ffmpeg.exe) do move /y "%%f" ffmpeg.exe >nul
rd /s /q extract_tmp >nul 2>nul
del ffmpeg.zip >nul 2>nul
if exist ffmpeg.exe (echo ffmpeg 就绪 ✓) else (echo 解压失败, 请手动放置 ffmpeg.exe)

:run
start "" pythonw cast_pig.py
