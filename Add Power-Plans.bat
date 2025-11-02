@(set "0=%~f0"^)#) & powershell -nop -c iex([io.file]::ReadAllText($env:0)) & exit /b
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script must be run as Administrator. Re-launching with elevated privileges..." -ForegroundColor Yellow
    Start-Process cmd -ArgumentList "/c `"$env:0`"" -Verb RunAs
    exit
}

Write-Host 'Checking power plans...' -ForegroundColor Cyan
$existing = Get-WmiObject -Namespace root\cimv2\power -Class Win32_PowerPlan | Select-Object -ExpandProperty ElementName

# Check and add each plan if missing
@{
    'Balanced' = '381b4222-f694-41f0-9685-ff5bb260df2e'
    'Power saver' = 'a1841308-3541-4fab-bc81-f71556f20b4a'
    'High performance' = '8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c'
    'Ultimate Performance' = 'e9a42b02-d5df-448d-aa00-03f14749eb61'
}.GetEnumerator() | ForEach-Object {
    if ($existing -contains $_.Key) {
        Write-Host "'$($_.Key)' already exists." -ForegroundColor Green
    } else {
        Write-Host "Adding '$($_.Key)'..." -ForegroundColor Yellow
        powercfg -duplicatescheme $_.Value
        Write-Host "'$($_.Key)' added." -ForegroundColor Green
    }
}

Write-Host 'Power plan setup complete.' -ForegroundColor Cyan
pause