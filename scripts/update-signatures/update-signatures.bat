@echo off
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0update-signatures.ps1" %*
exit /b %errorlevel%
