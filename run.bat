@echo off
setlocal
cd /d "%~dp0"

if exist ".venv\Scripts\python.exe" (
    start "ThreatBot Server" "%CD%\.venv\Scripts\python.exe" -m uvicorn main:app --host 127.0.0.1 --port 8000
) else (
    start "ThreatBot Server" cmd /k "python -m uvicorn main:app --host 127.0.0.1 --port 8000"
)

timeout /t 3 /nobreak >nul
start "" "http://127.0.0.1:8000/"
