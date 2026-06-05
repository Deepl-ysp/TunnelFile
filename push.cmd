@echo off
chcp 65001 > nul
echo [信息] 正在同步到所有远程仓库 (Gitee & GitHub)...

:: 1. 读取版本号
set /p VERSION=<version
echo [信息] 当前版本: %VERSION%

:: 2. 添加所有更改
git add .

:: 3. 提交更改 (使用版本号作为提交信息)
:: 如果没有变更，commit 会失败，我们忽略错误继续执行 pull
git commit -m "v%VERSION%"

:: 4. 拉取远程最新代码并合并
echo [信息] 正在拉取远程最新代码...
git pull --rebase origin main

if %errorlevel% neq 0 (
    echo [错误] 拉取或合并失败，可能存在冲突，请手动解决。
    pause
    exit /b 1
)

:: 5. 推送 (会自动推送到所有配置的 push 地址)
echo [信息] 正在推送...
git push

if %errorlevel% equ 0 (
    echo [成功] 推送完成！
) else (
    echo [错误] 推送失败，请检查网络或权限。
)
pause