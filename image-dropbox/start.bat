@echo off
rem Image Drop Box launcher: starts the app and the Cloudflare tunnel in two windows
cd /d "%~dp0"
start "image-dropbox app" cmd /k venv\Scripts\waitress-serve --host=127.0.0.1 --port=5000 --trusted-proxy=127.0.0.1 --trusted-proxy-headers=x-forwarded-for app:app
timeout /t 3 /nobreak >nul
start "image-dropbox tunnel" cmd /k cloudflared tunnel --url http://127.0.0.1:5000
