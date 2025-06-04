@(set "0=%~f0"^)#) & powershell -nop -c iex([io.file]::ReadAllText($env:0)) & exit /b

# Check for Admin privileges
if (-not ([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator")) {
    Write-Host "This script must be run as Administrator. Please re-run it with administrative privileges." -ForegroundColor Red
    Read-Host -Prompt "Press Enter to exit"
    Exit
}

$RemoveWebView = $args -contains "-RemoveWebView"
$RemoveWidgets = $args -contains "-RemoveWidgets" 
$RemoveXboxSocial = $args -contains "-RemoveXboxSocial"
$Silent = $args -contains "-Silent"
$Confirm = $args -contains "-Confirm"

# Helper function for aggressive removal
function Set-ForceOwnAndRemove {
    param([Parameter(Mandatory)][string]$Path)
    
    try {
        $FullPath = Resolve-Path -Path $Path -ErrorAction Stop
        if (-not (Test-Path -Path $FullPath)) { return $true }
        
        $IsFolder = (Get-Item $FullPath).PSIsContainer
        
        # Remove read-only attributes
        try {
            if ($IsFolder) {
                Get-ChildItem -Path $FullPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        Set-ItemProperty -Path $_.FullName -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
                    } catch {}
                }
            } else {
                Set-ItemProperty -Path $FullPath -Name IsReadOnly -Value $false -ErrorAction SilentlyContinue
            }
        } catch {}
        
        # ACL method
        try {
            $Acl = Get-Acl $FullPath
            $Acl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
            $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            
            if ($IsFolder) {
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($CurrentUser, "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
            } else {
                $AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule($CurrentUser, "FullControl", "Allow")
            }
            
            $Acl.SetAccessRule($AccessRule)
            Set-Acl -Path $FullPath -AclObject $Acl
            
            # Apply to child items if folder
            if ($IsFolder) {
                Get-ChildItem -Path $FullPath -Recurse -Force -ErrorAction SilentlyContinue | ForEach-Object {
                    try {
                        $ChildAcl = Get-Acl $_.FullName
                        $ChildAcl.SetOwner([System.Security.Principal.NTAccount]"Administrators")
                        $ChildAcl.SetAccessRule((New-Object System.Security.AccessControl.FileSystemAccessRule($CurrentUser, "FullControl", "Allow")))
                        Set-Acl -Path $_.FullName -AclObject $ChildAcl
                    } catch {}
                }
            }
            
            Remove-Item -Path $FullPath -Force -Recurse -ErrorAction Stop
            return $true
        } catch {}
        
        # icacls fallback
        try {
            if($IsFolder) { 
                & takeown /F "$FullPath" /R /D Y 2>&1 | Out-Null 
            } else { 
                & takeown /F "$FullPath" /A 2>&1 | Out-Null 
            }
            
            $CurrentUser = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
            foreach ($Perm in @("*S-1-5-32-544:F", "System:F", "Administrators:F", "$CurrentUser`:F")) {
                if($IsFolder) { 
                    & icacls "$FullPath" /grant:R "$Perm" /T /C 2>&1 | Out-Null 
                } else { 
                    & icacls "$FullPath" /grant:R "$Perm" 2>&1 | Out-Null 
                }
                if ($LASTEXITCODE -eq 0) { break }
            }
            
            Remove-Item -Path $FullPath -Force -Recurse -ErrorAction Stop
            return $true
        } catch {}
        
        return $false
    }
    catch {
        return $false
    }
}

# Find Edge setup executable
function Find-EdgeSetupExecutable {
    $PossiblePaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\Edge\Application\*\Installer\setup.exe",
        "${env:ProgramFiles}\Microsoft\Edge\Application\*\Installer\setup.exe",
        "${env:LOCALAPPDATA}\Microsoft\Edge\Application\*\Installer\setup.exe"
    )
    
    foreach ($PathPattern in $PossiblePaths) {
        $FoundPaths = Get-ChildItem -Path $PathPattern -ErrorAction SilentlyContinue
        if ($FoundPaths) {
            return $FoundPaths[0].FullName
        }
    }
    return $null
}

# Edge uninstallation using built-in uninstaller
function Invoke-EdgeUninstall {
    Write-Host "`nAttempting Edge uninstallation..." -ForegroundColor Cyan
    
    $SetupPath = Find-EdgeSetupExecutable
    if ($SetupPath) {
        Write-Host "Found Edge setup at: $SetupPath" -ForegroundColor Green
        try {
            Write-Host "Uninstalling Edge using built-in uninstaller..." -ForegroundColor Yellow
            Start-Process -FilePath $SetupPath -ArgumentList "--uninstall", "--system-level", "--force-uninstall" -Wait -NoNewWindow
            Write-Host "Edge uninstaller completed." -ForegroundColor Green
        } catch {
            Write-Host "Built-in uninstaller failed: $($_.Exception.Message)" -ForegroundColor Red
        }
    } else {
        Write-Host "Edge setup not found. Proceeding with force removal..." -ForegroundColor Yellow
    }
    
    # WebView uninstallation
    $WebViewPaths = @(
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView\Application\*\Installer\setup.exe",
        "${env:ProgramFiles}\Microsoft\EdgeWebView\Application\*\Installer\setup.exe"
    )
    
    foreach ($PathPattern in $WebViewPaths) {
        $FoundPaths = Get-ChildItem -Path $PathPattern -ErrorAction SilentlyContinue
        if ($FoundPaths) {
            try {
                Write-Host "Uninstalling EdgeWebView using built-in uninstaller..." -ForegroundColor Yellow
                Start-Process -FilePath $FoundPaths[0].FullName -ArgumentList "--uninstall", "--msedgewebview", "--system-level", "--force-uninstall" -Wait -NoNewWindow
                Write-Host "EdgeWebView uninstaller completed." -ForegroundColor Green
            } catch {
                Write-Host "WebView uninstaller failed: $($_.Exception.Message)" -ForegroundColor Red
            }
            break
        }
    }
    
    # Remove WebView dirs
    $WebViewDirs = @(
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView",
        "${env:ProgramFiles}\Microsoft\EdgeWebView"
    )
    
    foreach ($WebViewDir in $WebViewDirs) {
        if (Test-Path $WebViewDir) {
            Write-Host "Removing WebView: $WebViewDir" -ForegroundColor Yellow
            Set-ForceOwnAndRemove -Path $WebViewDir
            try {
                $ParentDir = Split-Path $WebViewDir -Parent
                if ((Get-ChildItem $ParentDir -ErrorAction SilentlyContinue | Measure-Object).Count -eq 0) {
                    Remove-Item $ParentDir -Force -ErrorAction SilentlyContinue
                }
            } catch {}
        }
    }
}

# User profile cleanup
function Invoke-UserProfileCleanup {
    Write-Host "`nPerforming user profile cleanup..." -ForegroundColor Cyan
    
    # Get user profiles from registry
    $ProfileListPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\ProfileList"
    
    try {
        $PublicProfile = (Get-ItemProperty -Path $ProfileListPath -Name "Public" -ErrorAction SilentlyContinue).Public
        $DefaultProfile = (Get-ItemProperty -Path $ProfileListPath -Name "Default" -ErrorAction SilentlyContinue).Default
        
        $ProfilePaths = @()
        if ($PublicProfile) { $ProfilePaths += $PublicProfile }
        if ($DefaultProfile) { $ProfilePaths += $DefaultProfile }
        
        # Get user SIDs and profile paths
        Get-ChildItem -Path $ProfileListPath | ForEach-Object {
            $SID = $_.PSChildName
            if ($SID -notin @("S-1-5-18", "S-1-5-19", "S-1-5-20")) {
                try {
                    $ProfilePath = (Get-ItemProperty -Path $_.PSPath -Name "ProfileImagePath" -ErrorAction SilentlyContinue).ProfileImagePath
                    if ($ProfilePath -and (Test-Path $ProfilePath)) {
                        $ProfilePaths += $ProfilePath
                    }
                } catch {}
            }
        }
        
        # Remove Edge shortcuts
        foreach ($ProfilePath in $ProfilePaths) {
            $ShortcutPaths = @(
                "$ProfilePath\Desktop\Microsoft Edge.lnk",
                "$ProfilePath\Desktop\edge.lnk",
                "$ProfilePath\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
            )
            
            foreach ($ShortcutPath in $ShortcutPaths) {
                if (Test-Path $ShortcutPath) {
                    Write-Host "Removing shortcut: $ShortcutPath" -ForegroundColor Yellow
                    Remove-Item -Path $ShortcutPath -Force -ErrorAction SilentlyContinue
                }
            }
            
            # Clean Edge user data dirs
            $EdgeUserDataPaths = @(
                "$ProfilePath\AppData\Local\Microsoft\Edge",
                "$ProfilePath\AppData\Local\Microsoft\EdgeCore",
                "$ProfilePath\AppData\Local\Microsoft\EdgeUpdate"
            )
            
            foreach ($EdgeDataPath in $EdgeUserDataPaths) {
                if (Test-Path $EdgeDataPath) {
                    Write-Host "Removing user data: $EdgeDataPath" -ForegroundColor Yellow
                    Set-ForceOwnAndRemove -Path $EdgeDataPath
                }
            }
        }
        
        Write-Host "User profile cleanup completed." -ForegroundColor Green
    } catch {
        Write-Host "Error during user profile cleanup: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Function for system-level file cleanup
function Invoke-SystemLevelCleanup {
    Write-Host "`nPerforming system-level cleanup..." -ForegroundColor Cyan
    
    # Clean System32 Edge files
    $System32EdgeFiles = Get-ChildItem -Path "${env:SystemRoot}\System32\MicrosoftEdge*" -ErrorAction SilentlyContinue
    foreach ($File in $System32EdgeFiles) {
        Write-Host "Removing file: $($File.FullName)"
        Set-ForceOwnAndRemove -Path $File.FullName
    }
    
    # Clean scheduled tasks
    Write-Host "Cleaning Edge-related scheduled tasks..." -ForegroundColor Yellow
    
    # Remove task files
    $TaskFiles = Get-ChildItem -Path "${env:SystemRoot}\System32\Tasks" -Recurse -Filter "*MicrosoftEdge*" -ErrorAction SilentlyContinue
    foreach ($TaskFile in $TaskFiles) {
        Write-Host "Removing task: $($TaskFile.FullName)"
        Set-ForceOwnAndRemove -Path $TaskFile.FullName
    }
    
    # Remove registered tasks
    try {
        $EdgeTasks = Get-ScheduledTask | Where-Object { $_.TaskName -like "*MicrosoftEdge*" -or $_.TaskName -like "*Edge*" }
        foreach ($Task in $EdgeTasks) {
            Write-Host "Unregistering scheduled task: $($Task.TaskName)"
            Unregister-ScheduledTask -TaskName $Task.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
    } catch {}
    
    # Enhanced registry cleanup
    $RegistryPaths = @(
        "HKLM:\SOFTWARE\Microsoft\EdgeUpdate",
        "HKLM:\SOFTWARE\Microsoft\Edge",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Edge",
        "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\Microsoft Edge",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\msedge.exe",
        "HKLM:\SOFTWARE\Policies\Microsoft\Edge",
        "HKLM:\SOFTWARE\Policies\Microsoft\EdgeUpdate",
        "HKLM:\SOFTWARE\Microsoft\Active Setup\Installed Components\{9459C573-B17A-45AE-9F64-1857B5D58CEE}"
    )

    foreach ($path in $RegistryPaths) {
        if (Test-Path $path) {
            Write-Host "Removing registry key: $path"
            Remove-Item -Path $path -Recurse -Force -ErrorAction SilentlyContinue
        }
    }
    
    Write-Host "System-level cleanup completed." -ForegroundColor Green
}

# APPX package management
function Invoke-AdvAppxManagement {
    Write-Host "`nPerforming APPX package management..." -ForegroundColor Cyan
    
    # Get current user SID
    try {
        $CurrentUserSID = ([System.Security.Principal.WindowsIdentity]::GetCurrent()).User.Value
        Write-Host "User SID: $CurrentUserSID" -ForegroundColor Green
    } catch {
        Write-Host "Failed to get user SID" -ForegroundColor Red
        return
    }
    
    $EdgePackagePatterns = @(
        "*MicrosoftEdge*",
        "*Microsoft.MicrosoftEdge*",
        "*Microsoft.MicrosoftEdgeDevToolsClient*",
        "*Microsoft.Win32WebViewHost*",
        "*MicrosoftWindows.Client.WebExperience*"
    )
    
    # APPX removal with registry manipulation
    foreach ($Pattern in $EdgePackagePatterns) {
        $Packages = Get-AppxPackage -AllUsers -Name $Pattern -ErrorAction SilentlyContinue
        
        foreach ($Package in $Packages) {
            Write-Host "Processing package: $($Package.PackageFullName)"
            
            # Add to EndOfLife registry keys
            $EndOfLifeUserPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\$CurrentUserSID\$($Package.PackageFullName)"
            $EndOfLifeSystemPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\EndOfLife\S-1-5-18\$($Package.PackageFullName)"
            $DeprovisionedPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Appx\AppxAllUserStore\Deprovisioned\$($Package.PackageFullName)"
            
            try {
                New-Item -Path $EndOfLifeUserPath -Force -ErrorAction SilentlyContinue | Out-Null
                New-Item -Path $EndOfLifeSystemPath -Force -ErrorAction SilentlyContinue | Out-Null  
                New-Item -Path $DeprovisionedPath -Force -ErrorAction SilentlyContinue | Out-Null
                Write-Host "Added registry entries for: $($Package.PackageFullName)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to add registry entries for: $($Package.PackageFullName)" -ForegroundColor Red
            }
            
            # Remove the package
            try {
                Remove-AppxPackage -Package $Package.PackageFullName -ErrorAction SilentlyContinue
                Remove-AppxPackage -Package $Package.PackageFullName -AllUsers -ErrorAction SilentlyContinue
                Write-Host "Removed package: $($Package.PackageFullName)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove package: $($Package.PackageFullName)" -ForegroundColor Red
            }
        }
        
        # Remove provisioned packages
        $ProvisionedPackages = Get-AppxProvisionedPackage -Online | Where-Object { $_.PackageName -like $Pattern }
        foreach ($ProvPackage in $ProvisionedPackages) {
            try {
                Write-Host "Removing provisioned package: $($ProvPackage.PackageName)" -ForegroundColor Yellow
                Remove-AppxProvisionedPackage -PackageName $ProvPackage.PackageName -Online -AllUsers -ErrorAction SilentlyContinue
                Write-Host "Removed provisioned package: $($ProvPackage.PackageName)" -ForegroundColor Green
            } catch {
                Write-Host "Failed to remove provisioned package: $($ProvPackage.PackageName)" -ForegroundColor Red
            }
        }
    }
    
    # Clean SystemApps Edge dirs
    $SystemAppsEdge = Get-ChildItem -Path "${env:SystemRoot}\SystemApps\Microsoft.MicrosoftEdge*" -Directory -ErrorAction SilentlyContinue
    foreach ($EdgeApp in $SystemAppsEdge) {
        Write-Host "Removing SystemApps directory: $($EdgeApp.FullName)" -ForegroundColor Yellow
        Set-ForceOwnAndRemove -Path $EdgeApp.FullName
    }
    
    Write-Host "APPX management completed." -ForegroundColor Green
}

# Main execution
Write-Host "Microsoft Edge Removal Script" -ForegroundColor Cyan
Write-Host "==============================" -ForegroundColor Cyan

# Force kill all Edge-related processes
Write-Host "Killing Edge-related processes..." -ForegroundColor Yellow
Get-Process | Where-Object {$_.Name -like "*edge*" -or $_.Name -like "*WebView*"} | ForEach-Object {
    try {
        $_ | Stop-Process -Force -ErrorAction SilentlyContinue
    }
    catch {
        $null = & taskkill /F /IM "$($_.ProcessName).exe" /T 2>&1
    }
}

# Confirmation
if (-not $Silent -and -not $Confirm) {
    Write-Host "WARNING: This script will perform comprehensive Microsoft Edge removal." -ForegroundColor Red
    do {
        $EdgeConfirm = Read-Host "Are you sure you want to proceed? (Y/N)"
        $EdgeConfirm = $EdgeConfirm.ToUpper()
        
        if ($EdgeConfirm -eq 'N') {
            Write-Host "Operation cancelled." -ForegroundColor Red
            exit
        }
        elseif ($EdgeConfirm -ne 'Y') {
            Write-Host "Invalid input. Please enter 'Y' or 'N'." -ForegroundColor Yellow
        }
    } while ($EdgeConfirm -ne 'Y')
}

# Execute the removal process
try {
    # Step 1: Edge Uninstallation
    Invoke-EdgeUninstall
    
    # Step 2: Force Removal
    Write-Host "`nPerforming force removal..." -ForegroundColor Cyan
    
    # Remove Edge dirs
    $EdgePaths = @(
        "${env:ProgramFiles}\Microsoft\Edge",
        "${env:ProgramFiles}\Microsoft\EdgeCore", 
        "${env:ProgramFiles}\Microsoft\EdgeUpdate",
        "${env:ProgramFiles}\Microsoft\EdgeWebView",
        "${env:ProgramFiles(x86)}\Microsoft\Edge",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeCore",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeUpdate",
        "${env:ProgramFiles(x86)}\Microsoft\EdgeWebView",
        "${env:ProgramFiles(x86)}\Microsoft\Temp",
        "${env:LOCALAPPDATA}\Microsoft\Edge",
        "${env:LOCALAPPDATA}\Microsoft\EdgeCore",
        "${env:LOCALAPPDATA}\Microsoft\EdgeUpdate",
        "${env:LOCALAPPDATA}\Microsoft\EdgeWebView",
        "${env:ProgramData}\Microsoft\EdgeUpdate",
        "${env:SystemRoot}\System32\Microsoft-Edge",
        "${env:SystemRoot}\System32\Microsoft-EdgeCore",
        # "${env:SystemRoot}\WinSxS\amd64_microsoft-edge-webview*",
        "${env:SystemRoot}\System32\Microsoft-Edge-WebView"
    )

    foreach ($path in $EdgePaths) {
        Get-Item $path -ErrorAction SilentlyContinue | ForEach-Object {
            Write-Host "Removing directory: $($_.FullName)"
            Set-ForceOwnAndRemove -Path $_.FullName
        }
    }
    
    $SystemAppsEdgeItems = Get-ChildItem -Path "${env:SystemRoot}\SystemApps\Microsoft.MicrosoftEdge*" -ErrorAction SilentlyContinue
    foreach ($item in $SystemAppsEdgeItems) {
        Write-Host "Removing SystemApp: $($item.FullName)"
        Set-ForceOwnAndRemove -Path $item.FullName
    }
    
    # Remove Start Menu entries
    $StartMenuPaths = @(
        "${env:ProgramData}\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk",
        "${env:APPDATA}\Microsoft\Windows\Start Menu\Programs\Microsoft Edge.lnk"
    )

    foreach ($startMenuPath in $StartMenuPaths) {
        if (Test-Path $startMenuPath) {
            Write-Host "Removing Start Menu entry: $startMenuPath" -ForegroundColor Yellow
            Remove-Item -Path $startMenuPath -Force -ErrorAction SilentlyContinue
        }
    }
    
    # Force remove services
    $services = @('edgeupdate', 'edgeupdatem', 'MicrosoftEdgeElevationService')
    foreach ($service in $services) {
        if (Get-Service -Name $service -ErrorAction SilentlyContinue) {
            Write-Host "Removing service: $service" -ForegroundColor Yellow
            Stop-Service -Name $service -Force -ErrorAction SilentlyContinue
            $null = & sc.exe stop $service 2>&1
            $null = & sc.exe delete $service 2>&1
        }
    }
    
    Write-Host "Force removal completed." -ForegroundColor Green
    
    # Step 3: User Profile Cleanup
    Invoke-UserProfileCleanup
    
    # Step 4: System Level Cleanup  
    Invoke-SystemLevelCleanup
    
    # Step 5: APPX Management
    Invoke-AdvAppxManagement
    
} catch {
    Write-Host "An error occurred during execution: $($_.Exception.Message)" -ForegroundColor Red
}

# Restart Explorer
Write-Host "`nRestarting Explorer..." -ForegroundColor Yellow
try {
    $ExplorerProcess = Get-Process -Name explorer -ErrorAction SilentlyContinue
    if ($ExplorerProcess) {
        Stop-Process -Name explorer -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 2
    }
    Start-Process -FilePath "${env:WINDIR}\explorer.exe" -WindowStyle Hidden
} catch {
    Write-Host "Explorer restart encountered an issue, but continuing..." -ForegroundColor Yellow
}

if (-not $Silent) {
    Write-Host "`n===================================" -ForegroundColor Cyan
    Write-Host " Microsoft Edge removal completed!" -ForegroundColor Green
    Write-Host "===================================" -ForegroundColor Cyan
    Write-Host "Summary of actions performed:" -ForegroundColor Yellow
    Write-Host "1. ✓ Proper Edge uninstallation" -ForegroundColor Green
    Write-Host "2. ✓ Force removal of Edge files and dirs" -ForegroundColor Green  
    Write-Host "3. ✓ Comprehensive user profile cleanup" -ForegroundColor Green
    Write-Host "4. ✓ System-level file and registry cleanup" -ForegroundColor Green
    Write-Host "5. ✓ APPX package management" -ForegroundColor Green
    Write-Host "`nA system restart is recommended to complete the removal process."
    Write-Host "Note: Some protected system components may remain but core Edge functionality should be removed." -ForegroundColor Yellow
}