@echo off
echo.
echo  Checking proxy status on port 8083...
 
:: Check if port 8083 is already in use
netstat -ano | findstr ":8083" | findstr "LISTENING" >nul 2>&1
 
if %errorlevel% == 0 (
    echo  Proxy already running - skipping start.
) else (
    echo  Proxy not running - starting now...
    start "Claude Proxy" cmd /k "cd /d C:\Windows\System32\free-claude-code && call .venv\Scripts\activate.bat && uv run uvicorn server:app --host 0.0.0.0 --port 8083"
    echo  Waiting for proxy to be ready...
    timeout /t 5 /nobreak >nul
    echo  Proxy started!
)
 
echo.
echo  Launching Claude Code...
echo  Proxy : http://localhost:8083
echo  Token : ccnim
echo.
 
set ANTHROPIC_AUTH_TOKEN=ccnim
set ANTHROPIC_BASE_URL=http://localhost:8083
set CLAUDE_CODE_USE_POWERSHELL_TOOL=1
claude