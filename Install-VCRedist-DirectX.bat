@(set "0=%~f0"^)#) & powershell -NoProfile -ExecutionPolicy Bypass -Command "iex([io.file]::ReadAllText($env:0))" & exit /b

<#
:: Visual C++ Redistributables and DirectX Silent Installer
:: This script checks for and installs missing Visual C++ Redistributables (2008-2022) and DirectX
#>

# Check if running as administrator
if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    Write-Host "This script needs to be run as Administrator. Please restart with elevated privileges." -ForegroundColor Red
    Start-Sleep -Seconds 3
    exit
}

# Create a temporary folder for downloads
$tempFolder = "$env:TEMP\VC_DirectX_Installer"
if (-not (Test-Path $tempFolder)) {
    New-Item -ItemType Directory -Path $tempFolder -Force | Out-Null
}

# Function to check if a specific Visual C++ version is installed
function Test-VCRedistInstalled {
    param (
        [string]$DisplayName,
        [string]$Architecture
    )
    
    $installed = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*", 
                                 "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -like "*$DisplayName*" -and $_.DisplayName -like "*$Architecture*" }
    
    return $null -ne $installed
}

# Function to download a file
function Download-File {
    param (
        [string]$Url,
        [string]$OutputPath
    )
    
    Write-Host "Downloading $Url to $OutputPath..."
    
    try {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        $webClient = New-Object System.Net.WebClient
        $webClient.DownloadFile($Url, $OutputPath)
        return $true
    }
    catch {
        Write-Host "Failed to download: $_" -ForegroundColor Red
        return $false
    }
}

# Visual C++ Redistributables information
$vcRedists = @(
    @{
        Name = "Visual C++ 2008 x86"
        DisplayName = "Microsoft Visual C++ 2008 Redistributable"
        Architecture = "x86"
        Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x86.exe"
        Filename = "vcredist_2008_x86.exe"
        Arguments = "/q /norestart"
    },
    @{
        Name = "Visual C++ 2008 x64"
        DisplayName = "Microsoft Visual C++ 2008 Redistributable"
        Architecture = "x64"
        Url = "https://download.microsoft.com/download/5/D/8/5D8C65CB-C849-4025-8E95-C3966CAFD8AE/vcredist_x64.exe"
        Filename = "vcredist_2008_x64.exe"
        Arguments = "/q /norestart"
    },
    @{
        Name = "Visual C++ 2010 x86"
        DisplayName = "Microsoft Visual C++ 2010"
        Architecture = "x86"
        Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x86.exe"
        Filename = "vcredist_2010_x86.exe"
        Arguments = "/passive /norestart"
    },
    @{
        Name = "Visual C++ 2010 x64"
        DisplayName = "Microsoft Visual C++ 2010"
        Architecture = "x64"
        Url = "https://download.microsoft.com/download/1/6/5/165255E7-1014-4D0A-B094-B6A430A6BFFC/vcredist_x64.exe"
        Filename = "vcredist_2010_x64.exe"
        Arguments = "/passive /norestart"
    },
    @{
        Name = "Visual C++ 2012 x86"
        DisplayName = "Microsoft Visual C++ 2012 Redistributable"
        Architecture = "x86"
        Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x86.exe"
        Filename = "vcredist_2012_x86.exe"
        Arguments = "/install /quiet /norestart"
    },
    @{
        Name = "Visual C++ 2012 x64"
        DisplayName = "Microsoft Visual C++ 2012 Redistributable"
        Architecture = "x64"
        Url = "https://download.microsoft.com/download/1/6/B/16B06F60-3B20-4FF2-B699-5E9B7962F9AE/VSU_4/vcredist_x64.exe"
        Filename = "vcredist_2012_x64.exe"
        Arguments = "/install /quiet /norestart"
    },
    @{
        Name = "Visual C++ 2013 x86"
        DisplayName = "Microsoft Visual C++ 2013 Redistributable"
        Architecture = "x86"
        Url = "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x86.exe"
        Filename = "vcredist_2013_x86.exe"
        Arguments = "/install /quiet /norestart"
    },
    @{
        Name = "Visual C++ 2013 x64"
        DisplayName = "Microsoft Visual C++ 2013 Redistributable"
        Architecture = "x64"
        Url = "https://download.microsoft.com/download/2/E/6/2E61CFA4-993B-4DD4-91DA-3737CD5CD6E3/vcredist_x64.exe"
        Filename = "vcredist_2013_x64.exe"
        Arguments = "/install /quiet /norestart"
    },
    @{
        Name = "Visual C++ 2015-2022 x86"
        DisplayName = "Microsoft Visual C++ 2015-2022 Redistributable"
        Architecture = "x86"
        Url = "https://aka.ms/vs/17/release/vc_redist.x86.exe"
        Filename = "vcredist_2022_x86.exe"
        Arguments = "/install /quiet /norestart"
    },
    @{
        Name = "Visual C++ 2015-2022 x64"
        DisplayName = "Microsoft Visual C++ 2015-2022 Redistributable"
        Architecture = "x64"
        Url = "https://aka.ms/vs/17/release/vc_redist.x64.exe"
        Filename = "vcredist_2022_x64.exe"
        Arguments = "/install /quiet /norestart"
    }
)

# DirectX information
$directX = @{
    Name = "DirectX End-User Runtime"
    Url = "https://download.microsoft.com/download/1/7/1/1718CCC4-6315-4D8E-9543-8E28A4E18C4C/dxwebsetup.exe"
    Filename = "dxwebsetup.exe"
    Arguments = "/Q"
}

# Check and install Visual C++ Redistributables
foreach ($vcRedist in $vcRedists) {
    Write-Host "Checking for $($vcRedist.Name)..."
    $installed = Test-VCRedistInstalled -DisplayName $vcRedist.DisplayName -Architecture $vcRedist.Architecture
    
    if ($installed) {
        Write-Host "$($vcRedist.Name) is already installed." -ForegroundColor Green
    } else {
        Write-Host "$($vcRedist.Name) is not installed. Downloading and installing..." -ForegroundColor Yellow
        $outputPath = Join-Path $tempFolder $vcRedist.Filename
        
        if (Download-File -Url $vcRedist.Url -OutputPath $outputPath) {
            Write-Host "Installing $($vcRedist.Name)..."
            $process = Start-Process -FilePath $outputPath -ArgumentList $vcRedist.Arguments -PassThru -Wait -NoNewWindow
            
            if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
                Write-Host "$($vcRedist.Name) installed successfully!" -ForegroundColor Green
            } else {
                Write-Host "$($vcRedist.Name) installation failed with exit code $($process.ExitCode)" -ForegroundColor Red
            }
        }
    }
}

# Check if DirectX is installed (This is a basic check - DirectX is complex to verify completely)
Write-Host "Checking for DirectX..."
$dxSetupPath = Join-Path $tempFolder $directX.Filename
Download-File -Url $directX.Url -OutputPath $dxSetupPath

Write-Host "Installing/Updating DirectX End-User Runtime..."
$process = Start-Process -FilePath $dxSetupPath -ArgumentList $directX.Arguments -PassThru -Wait -NoNewWindow

if ($process.ExitCode -eq 0 -or $process.ExitCode -eq 3010) {
    Write-Host "DirectX installation/update completed successfully!" -ForegroundColor Green
} else {
    Write-Host "DirectX installation/update failed with exit code $($process.ExitCode)" -ForegroundColor Red
}

# Clean up
Write-Host "Cleaning up temporary files..."
Remove-Item -Path $tempFolder -Recurse -Force -ErrorAction SilentlyContinue

Write-Host "Installation process completed!" -ForegroundColor Cyan