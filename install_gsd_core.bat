@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>&1 || (echo [GSD Core] Node.js 18+ is required. Install Node.js, then rerun this script.& exit /b 1)
where npx >nul 2>&1 || (echo [GSD Core] npx is unavailable. Reinstall Node.js with npm, then rerun this script.& exit /b 1)
for /f %%V in ('node -p "Number(process.versions.node.split('.')[0])"') do set "NODE_MAJOR=%%V"
if %NODE_MAJOR% LSS 18 (echo [GSD Core] Node.js 18 or newer is required.& exit /b 1)
echo [GSD Core] Starting the official interactive installer.
echo Choose your AI coding runtime and local/global install scope when prompted.
call npx --yes @opengsd/gsd-core@latest
exit /b %ERRORLEVEL%
