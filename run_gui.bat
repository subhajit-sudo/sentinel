@echo off
setlocal
cd /d "%~dp0"
if not exist ".gsd-core-setup-asked" (
  echo.
  echo [Optional developer tooling] GSD Core adds AI-assisted spec-driven project workflows.
  echo It is separate from the Sentinel scanner and is installed into your chosen coding runtime.
  where npx >nul 2>&1
  if errorlevel 1 (
    echo [GSD Core] Node.js / npx not found. You can install it later with install_gsd_core.bat.
  ) else (
    choice /C YN /D Y /T 8 /M "Install GSD Core now? Default is Yes"
    if errorlevel 2 (
      echo [GSD Core] Skipped. Run install_gsd_core.bat whenever you are ready.
    ) else (
      call install_gsd_core.bat
      if errorlevel 1 echo [GSD Core] Setup did not complete. Run install_gsd_core.bat to retry.
    )
  )
  type nul > ".gsd-core-setup-asked"
)
if exist ".venv\Scripts\python.exe" (
  set "PYTHON=.venv\Scripts\python.exe"
) else (
  python -m venv .venv
  if errorlevel 1 exit /b 1
  set "PYTHON=.venv\Scripts\python.exe"
)
%PYTHON% -m pip install -r requirements.txt
if errorlevel 1 exit /b 1
%PYTHON% web_ui.py
