@echo off
setlocal
REM WiFi Analyzer Pro — Windows source installer and launcher.

cd /d "%~dp0"
echo.
echo  WiFi Analyzer Pro setup
 echo =======================

where node >nul 2>&1
if errorlevel 1 (
  echo [!] Node.js 22 or newer is required: https://nodejs.org/
  exit /b 1
)
where py >nul 2>&1
if errorlevel 1 (
  echo [!] Python 3 is required: https://python.org/
  exit /b 1
)

for /f "tokens=1 delims=." %%v in ('node -p "process.versions.node"') do set NODE_MAJOR=%%v
if %NODE_MAJOR% LSS 22 (
  echo [!] Node.js 22 or newer is required. Current major: %NODE_MAJOR%
  exit /b 1
)

echo [1/4] Installing frontend dependencies...
call npm ci --no-audit --no-fund
if errorlevel 1 exit /b 1

echo [2/4] Building the frontend...
call npm run build
if errorlevel 1 exit /b 1

echo [3/4] Creating an isolated Python environment...
if not exist "wifi_analyzer_backend\.venv\Scripts\python.exe" py -3 -m venv "wifi_analyzer_backend\.venv"
call "wifi_analyzer_backend\.venv\Scripts\python.exe" -m pip install --upgrade pip
call "wifi_analyzer_backend\.venv\Scripts\python.exe" -m pip install -r "wifi_analyzer_backend\requirements.txt"
if errorlevel 1 exit /b 1

if exist "wifi_analyzer_backend\dist" rmdir /s /q "wifi_analyzer_backend\dist"
xcopy /E /I /Y "dist" "wifi_analyzer_backend\dist" >nul
if errorlevel 1 exit /b 1

echo [4/4] Starting WiFi Analyzer Pro...
echo Open http://127.0.0.1:199 in your browser.
echo Press Ctrl+C in this window to stop the local service.
"wifi_analyzer_backend\.venv\Scripts\python.exe" "wifi_analyzer_backend\server.py"
