@echo off
NET SESSION >nul 2>&1
if %errorLevel% neq 0 (
    echo Administrator privileges required...
    powershell -Command "Start-Process -Verb RunAs -FilePath '%~f0'"
    exit /b
)

echo.
echo Stopping Explorer...
taskkill /f /im explorer.exe
timeout 2 /nobreak>nul
echo.

if exist "%LocalAppData%\iconCache.db" (
    DEL /F /S /Q /A "%LocalAppData%\iconCache.db"
)

echo Deleting Explorer cache files...
DEL /F /S /Q /A "%LocalAppData%\Microsoft\Windows\Explorer\iconcache_*.db"
DEL /F /S /Q /A "%LocalAppData%\Microsoft\Windows\Explorer\thumbcache_*.db"

timeout 2 /nobreak>nul
echo.
set/p<nul=Press any key to Restart Explorer.exe . . . &pause>nul
start explorer.exe
echo Done!
