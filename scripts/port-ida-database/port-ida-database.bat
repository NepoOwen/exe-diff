@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0port-ida-database.ps1" %*
exit /b %errorlevel%
