@echo off
:: Check for administrative privileges
net session >nul 2>&1
if %errorlevel% neq 0 (
    powershell -Command "Start-Process '%~f0' -Verb RunAs"
    exit /b
)

echo Starting comprehensive Chrome cleanup with elevated privileges...
echo.
echo WARNING: This script will forcefully remove Chrome policies and settings.
echo Please close Chrome before continuing.
echo.
pause

echo.
echo Step 1: Removing Chrome registry keys...
:: Using /reg:32 and /reg:64 to remove both registry entries
reg delete "HKEY_CURRENT_USER\Software\Google\Chrome" /f /reg:32
reg delete "HKEY_CURRENT_USER\Software\Google\Chrome" /f /reg:64
reg delete "HKEY_CURRENT_USER\Software\Policies\Google\Chrome" /f /reg:32
reg delete "HKEY_CURRENT_USER\Software\Policies\Google\Chrome" /f /reg:64
reg delete "HKEY_LOCAL_MACHINE\Software\Google\Chrome" /f /reg:32
reg delete "HKEY_LOCAL_MACHINE\Software\Google\Chrome" /f /reg:64
reg delete "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" /f /reg:32
reg delete "HKEY_LOCAL_MACHINE\Software\Policies\Google\Chrome" /f /reg:64
reg delete "HKEY_LOCAL_MACHINE\Software\Policies\Google\Update" /f /reg:32
reg delete "HKEY_LOCAL_MACHINE\Software\Policies\Google\Update" /f /reg:64
reg delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Google\Enrollment" /f

echo.
echo Step 2: Removing CloudManagementEnrollmentToken...
reg delete "HKEY_LOCAL_MACHINE\Software\WOW6432Node\Google\Update\ClientState\{430FD4D0-B729-4F61-AA34-91526481799D}" /v CloudManagementEnrollmentToken /f

echo.
echo Step 3: Taking ownership and removing Google Policies directory...
:: Take ownership of Policies directory
if exist "%ProgramFiles(x86)%\Google\Policies" (
    takeown /F "%ProgramFiles(x86)%\Google\Policies" /A
    icacls "%ProgramFiles(x86)%\Google\Policies" /grant:R Administrators:F /T /C
    rd /s /q "%ProgramFiles(x86)%\Google\Policies"
    echo Policies directory removed successfully
) else (
    echo Policies directory not found - skipping
)

echo.
echo Step 4: Additional policy cleanup for "Managed by organization"...
:: Force remove additional policies with both 32-bit and 64-bit registry
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /f /reg:32
reg delete "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Google\Chrome" /f /reg:64
reg delete "HKEY_CURRENT_USER\Software\Policies\Google\Chrome" /f /reg:32
reg delete "HKEY_CURRENT_USER\Software\Policies\Google\Chrome" /f /reg:64

:: Clear Chrome preferences that might retain policy settings
:: May cause logging out of Chrome and loss of saved cookies
if exist "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Preferences" (
    echo Clearing Chrome preferences file...
    del /F /Q "%LOCALAPPDATA%\Google\Chrome\User Data\Default\Preferences"
)

echo.
echo Cleanup complete! Please note:
echo - You should restart Chrome to apply all changes
echo - If your device is domain-joined or managed by your organization,
echo   these policies might be automatically reinstated
echo - If you still see "Managed by your organization", your device
echo   might be managed through Group Policy or your organization's domain

pause