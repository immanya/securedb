@echo off
title SecureDB Server Launcher
color 0A

echo ======================================================================
echo                  SecureDB - Launching System
echo ======================================================================
echo.
echo Starting FastAPI Backend and React Dashboard...
echo Opening Web Browser at http://127.0.0.1:8000/ ...
echo.

start "" "http://127.0.0.1:8000/"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

pause
