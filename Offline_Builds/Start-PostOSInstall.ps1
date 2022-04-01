<#

.FUNCTIONALITY
First steps after GUI launches on new Win assets built by autonunattend.xml process

.SYNOPSIS
Change log

March 13, 2022
-New version created from packer based script specifically for offline use
-Added internet check at end
-Renamed to Start-PostOSInstall.ps1

March 14, 2022
-ServiceUI copied over to c:\windows\System32
-Restart-computer timer set to 30 seconds
-Updated build log shortcut creation method
-This PC added to current user
-XML task copy added
-Creation of c:\Admin\scripts, language pack, build as required

March 15, 2022
-c:\admin folders only created as required
-Shortcut to Start-AppInstalls.ps1 is created at end of internet test, but not run in case there are further firewall/network changes required

March 19, 2022
-Read-only property removed from items copied from CDROM
-Added function to set wallpaper from my man Jose Espitia: https://www.joseespitia.com/2017/09/15/set-wallpaper-powershell-function
-Server 2019 lang pack supported added

March 27, 2022
-Updated wallpaper code
-Re-added optimize base image script

March 28, 2022
-Moved over code from optimize base image

March 31, 2022
-Amended Langpack key / cab detection based

March 31, 2022
-Fixed ExtraLangPackKey type-o

April 1, 2022
-Moved Set-WinUserLanguageList to correct position inside For loop


.EXAMPLE
./Start-PostOSInstall.ps1

.NOTES

.Link
https://github.com/getvpro/Standard-WinBuilds

#>

IF (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    write-warning "not started as elevated session, exiting"    
    EXIT

}

### Variables

# Powershell module/package management pre-reqs
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

Set-TimeZone -ID "Eastern Standard Time"

$OS = (Get-WMIobject -class win32_operatingsystem).Caption
$LogTimeStamp = (Get-Date).ToString('MM-dd-yyyy-hhmm-tt')
$PackerRegKey = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PackerLaunched -ErrorAction SilentlyContinue).PackerLaunched
$ExtraLangPack = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name ExtraLangPack -ErrorAction SilentlyContinue).ExtraLangPack
$PackerStaticIP = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PackerStaticIP -ErrorAction SilentlyContinue).PackerStaticIP
$CDDrive = Get-CimInstance Win32_LogicalDisk | ?{ $_.DriveType -eq 5} | select-object -expandproperty DeviceID

## Start of actual script commands

# Set High-perf powerprofile if not laptop type

If (!(Get-WmiObject -Class win32_battery)) {

    write-host "Asset is not a laptop, setting power profile to high performance"
    write-host "`r`n"
    powercfg.exe -SETACTIVE "8c5e7fda-e8bf-4a96-9a85-a6e23a8c635c"
}

### Create directory structure as required
IF (-not(test-path -Path "c:\Admin\Scripts")) {

    new-item -ItemType Directory -Path "c:\Admin\Scripts"

}

IF (-not(test-path -Path "c:\Admin\Build")) {

    new-item -ItemType Directory -Path "C:\Admin\Build"

}

IF (-not(test-path -Path "c:\Admin\Language Pack")) {

    new-item -ItemType Directory -Path "C:\Admin\Language Pack"

}

# Set log path based on being launched by packer, or not

$ScriptLog = "c:\Admin\Build\Start-PostOSInstall-$LogTimeStamp.txt"


if (-not(Get-Variable ScriptLog -ErrorAction SilentlyContinue)) {

	Write-warning "Script log not set, script will exit"	
	EXIT
}

### End Variables

### Functions

Function Write-CustomLog {
    Param(
    [String]$ScriptLog,    
    [String]$Message,
    [String]$Level
    
    )

    switch ($Level) { 
        'Error' 
            {
            $LevelText = 'ERROR:' 
            $Message = "$(Get-Date): $LevelText Ran from $Env:computername by $($Env:Username): $Message"
            Write-host $Message -ForegroundColor RED            
            } 
        
        'Warn'
            { 
            $LevelText = 'WARNING:' 
            $Message = "$(Get-Date): $LevelText Ran from $Env:computername by $($Env:Username): $Message"
            Write-host $Message -ForegroundColor YELLOW            
            } 

        'Info'
            { 
            $LevelText = 'INFO:' 
            $Message = "$(Get-Date): $LevelText Ran from $Env:computername by $($Env:Username): $Message"
            Write-host $Message -ForegroundColor GREEN            
            } 

        }
        
        Add-content -value "$Message" -Path "$ScriptLog"
}

Function Set-WallPaper {
 
<#
 
    .SYNOPSIS
    Applies a specified wallpaper to the current user's desktop
    
    .PARAMETER Image
    Provide the exact path to the image
 
    .PARAMETER Style
    Provide wallpaper style (Example: Fill, Fit, Stretch, Tile, Center, or Span)
  
    .EXAMPLE
    Set-WallPaper -Image "C:\Wallpaper\Default.jpg"
    Set-WallPaper -Image "C:\Wallpaper\Background.jpg" -Style Fit
  
#>
 
param (
    [parameter(Mandatory=$True)]
    # Provide path to image
    [string]$Image,
    # Provide wallpaper style that you would like applied
    [parameter(Mandatory=$False)]
    [ValidateSet('Fill', 'Fit', 'Stretch', 'Tile', 'Center', 'Span')]
    [string]$Style
)
 
$WallpaperStyle = Switch ($Style) {
  
    "Fill" {"10"}
    "Fit" {"6"}
    "Stretch" {"2"}
    "Tile" {"0"}
    "Center" {"0"}
    "Span" {"22"}
  
}
 
If($Style -eq "Tile") {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 1 -Force
 
}
Else {
 
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name WallpaperStyle -PropertyType String -Value $WallpaperStyle -Force
    New-ItemProperty -Path "HKCU:\Control Panel\Desktop" -Name TileWallpaper -PropertyType String -Value 0 -Force
 
}
 
Add-Type -TypeDefinition @" 
using System; 
using System.Runtime.InteropServices;
  
public class Params
{ 
    [DllImport("User32.dll",CharSet=CharSet.Unicode)] 
    public static extern int SystemParametersInfo (Int32 uAction, 
                                                   Int32 uParam, 
                                                   String lpvParam, 
                                                   Int32 fuWinIni);
}
"@ 
  
    $SPI_SETDESKWALLPAPER = 0x0014
    $UpdateIniFile = 0x01
    $SendChangeEvent = 0x02
  
    $fWinIni = $UpdateIniFile -bor $SendChangeEvent
  
    $ret = [Params]::SystemParametersInfo($SPI_SETDESKWALLPAPER, 0, $Image, $fWinIni)
}

### Functions

### Remove Windows welcome for new accounts

reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "PrivacyConsentStatus" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "SkipMachineOOBE" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "ProtectYourPC" /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\OOBE" /v "SkipUserOOBE" /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v "EnableFirstLogonAnimation" /t REG_DWORD /d 0 /f

### Windows server - Adding RSAT roles

IF ((Get-WMIObject -class win32_operatingsystem).Caption -like "*Server*") {

    write-host "Windows server OS confirmed, proceeding with windows feature changes" -ForegroundColor cyan

    IF ((Get-WindowsFeature RSAT-DHCP).Installed -eq $False) {

        write-host "Installing DHCP remote admin role" -ForegroundColor cyan
        Install-WindowsFeature RSAT-DHCP
    }

    IF ((Get-WindowsFeature RSAT-DNS-Server).Installed -eq $False) {

        write-host "Installing DNS remote admin feature"
        Install-WindowsFeature RSAT-DNS-Server
    }

    IF ((Get-WindowsFeature RSAT-AD-Tools).Installed -eq $False) {

        write-host "Installing AD remote admin feature"
        Install-WindowsFeature RSAT-AD-Tools
    }

    IF ((Get-WindowsFeature GPMC).Installed -eq $False) {

        write-host "Installing GPMC remote admin feature"
        Install-WindowsFeature GPMC
    }

}

### Install RSAT roles on Win 10

IF ((Get-WmiObject -class win32_operatingsystem).Caption -like "*Windows 10*") {

    $Roles = @(
    "Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0"
    "Rsat.DHCP.Tools~~~~0.0.1.0"
    "Rsat.Dns.Tools~~~~0.0.1.0"    
    "Rsat.GroupPolicy.Management.Tools~~~~0.0.1.0"
    "Rsat.ServerManager.Tools~~~~0.0.1.0"
    )

    ForEach ($Item in $Roles) {

        IF ((Get-WindowsCapability -name $Item -Online).State -eq "NotPresent") {

            write-host "Adding $Item"    
            Add-WindowsCapability -Online -name $Item

        }

        Else {

            write-host "$Item is already installed, no action taken" -ForegroundColor Cyan

        }

    }

}

### Change C drive name to match $Env:Computername
IF ($Drive.Label -ne $env:COMPUTERNAME) {

    write-host "Change C drive name to match $Env:Computername" -ForegroundColor Cyan
    write-host "`r`n"

    $drive = Get-WMIObject win32_volume -Filter "DriveLetter = 'C:'"
    $drive.Label = $env:COMPUTERNAME
    $drive.put()

}

### Wallpaper
copy-item "$CDDrive\Scripts\tetris_build_wallpaper.jpg" -Destination C:\Admin\Scripts -Force -PassThru | Set-ItemProperty -name isreadonly -Value $false
Set-WallPaper -Image "C:\Admin\scripts\tetris_build_wallpaper.jpg" -Style Fit

If ($PackerStaticIP -eq 1) {

    write-host "Attempting to set IP based on StaticIP.CSV info" -ForegroundColor Cyan

    $StaticIPcsv = import-csv "a:\StaticIP.csv"
    $IPAddr = ($StaticIPcsv)[0].Value
    $IPGW = ($StaticIPcsv)[1].Value
    $DNS1 = ($StaticIPcsv)[2].Value
    $DNS2 = ($StaticIPcsv)[3].Value

    write-host "Changing IP address to $IPAddr. Seting defaults for gateway and DNS servers" -ForegroundColor cyan
    Get-NetAdapter | Where Status -eq UP | New-NetIPAddress -IPAddress $IPAddr -PrefixLength 24 -DefaultGateway $IPGW
    Get-NetAdapter | Where Status -eq UP | Set-DnsClientServerAddress -ServerAddresses $DNS1, $DNS2

    IF ((Test-NetConnection $IPGW -ErrorAction SilentlyContinue).PingSucceeded -eq $True) {

        Write-host "$IPGW pings back as expected" -ForegroundColor Green

    }

    Else {

        Write-warning "Default gateway is not pinglabe"

    }

    write-host "Pause for IP check" -ForegroundColor Cyan

    PAUSE

}

write-host "Start of part 1 in 3 seconds . . ." -ForegroundColor Cyan
start-sleep -s 3

[Environment]::SetEnvironmentVariable("WinPackerBuildStartDate", $(Get-Date), [EnvironmentVariableTarget]::Machine)

Get-ScheduledTask -TaskName MicrosoftEdgeUpdateTaskMachine* -ErrorAction SilentlyContinue | Stop-ScheduledTask
Get-ScheduledTask -TaskName MicrosoftEdgeUpdateTaskMachine* -ErrorAction SilentlyContinue | Disable-ScheduledTask

### Create 'this pc' on current users deskop

$path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$name="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons
new-item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons -Name NewStartPanel

New-ItemProperty -Path $path -Name $name -Value 0 -Force

### remove server manager from startup for current user
New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -PropertyType DWORD -Value "0x1" –Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWORD -Value "0x1" -Force

IF (Get-process "servermanager" -ErrorAction SilentlyContinue) {

    Stop-Process -name servermanager -Force    
}

# Remove Server Manager link
Remove-Item -Path "c:\Users\Default\AppData\Roaming\Microsoft\Internet Explorer\Quick Launch\Server Manager.lnk" -ErrorAction SilentlyContinue

New-Item -Path HKLM:\SYSTEM\CurrentControlSet\Control\Network\NewNetworkWindowOff -Force

netsh advfirewall firewall set rule group="Network Discovery" new enable=No

### Open RDP
netsh advfirewall firewall add rule name="Open Port 3389" dir=in action=allow protocol=TCP localport=3389

New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -name fDenyTSConnections -PropertyType DWORD -Value 0 -Force

Write-host "Restart explorer"

stop-process -Name explorer

<#
### Part 2 - Requires internet connection, install Powershell package managers and modules

Write-CustomLog -ScriptLog $ScriptLog -Message "Installing PowershellGet / nuget package providers" -Level INFO

Install-PackageProvider -Name PowerShellGet -Force -Confirm:$False
Install-PackageProvider -Name Nuget -Force -Confirm:$False

Write-CustomLog -ScriptLog $ScriptLog -Message "Installing Powershell App Deploy ToolKit module" -Level INFO

Install-Module -Name PSADT -AllowClobber -Force -Confirm:$False

if (Get-module -ListAvailable -name PSADT) {

 Write-host "Pre-req PSADT is installed, script will continue" -ForegroundColor Green

}

Else {
 
 Write-CustomLog -ScriptLog $ScriptLog -Message "Internet / Proxy / Firewall issues are preventing the installation of pre-req modules, please resolve and re-try, script will exit" -Level ERROR 
 EXIT

}

#>

$TempFolder = "C:\TEMP"
New-Item -ItemType Directory -Force -Path $TempFolder
[Environment]::SetEnvironmentVariable("TEMP", $TempFolder, [EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable("TMP", $TempFolder, [EnvironmentVariableTarget]::Machine)
[Environment]::SetEnvironmentVariable("TEMP", $TempFolder, [EnvironmentVariableTarget]::User)
[Environment]::SetEnvironmentVariable("TMP", $TempFolder, [EnvironmentVariableTarget]::User)

### Part 3

start-sleep -s 3

Write-CustomLog -ScriptLog $ScriptLog -Message "Copying over scripts and binaries from ISO temp drive $CDDrive" -Level INFO

Get-ChildItem "$CDDrive\Scripts" -Filter *.ps1 | Select-Object -ExpandProperty FullName | ForEach {

    copy-item -Path $_ -Destination C:\Admin\Scripts -Force -PassThru | Set-ItemProperty -name isreadonly -Value $false

}

Get-ChildItem "$CDDrive\Scripts" -Filter *.xml | Select-Object -ExpandProperty FullName | ForEach {

    copy-item -Path $_ -Destination C:\Admin\Scripts -Force -PassThru | Set-ItemProperty -name isreadonly -Value $false

}

copy-item "$CDDrive\Scripts\ServiceUI.exe" C:\Windows\System32 -Force -PassThru | Set-ItemProperty -name isreadonly -Value $false

set-location C:\admin\Scripts

Write-CustomLog -ScriptLog $ScriptLog -Message "Importing Windows Update task" -Level INFO

Register-ScheduledTask -XML (Get-content "C:\Admin\Scripts\Start-WinUpdates.xml" | Out-String) -TaskName Start-WinUpdates -Force

Register-ScheduledTask -XML (Get-content "C:\Admin\Scripts\Monitor-WinUpdates.xml" | Out-String) -TaskName Monitor-WinUpdates -Force

### Fr-ca language pack download for Server 2022 systems / Win 10 21H1 is pending

If ($ExtraLangPack -eq 1) {

    Write-CustomLog -ScriptLog $ScriptLog -Message "ExtraLangPack key is set to 1, proceeeding with extra steps to provision extra lang pack" -Level INFO    
    
    IF ($OS -like "*Windows 10*") {    
        
        $LangPacks = GCI "$CDDrive\langpack\Win 10\*.cab" | Select-Object -ExpandProperty FullName

        ForEach ($Lang in $LangPacks) {            
            
            $LangShortCode = $Lang.Substring($Lang.Length -9).Split(".")[0]

            Write-CustomLog -ScriptLog $ScriptLog -Message "Installing $LangShortCode. Note: This process can be up to 10 mins" -Level INFO
            
            Add-WindowsPackage -Online -PackagePath "$Lang" -LogPath "C:\admin\Build\Lang-Pack-Install.log" -NoRestart
            
            Write-CustomLog -ScriptLog $ScriptLog -Message "Adding $LangShortCode to preferred display languages" -Level INFO
            
            $OldList = Get-WinUserLanguageList
			$OldList.Add("$LangShortCode")
			Set-WinUserLanguageList -LanguageList $OldList -Confirm:$False -Force
        }    
    } 
    
    IF ($OS -like "*Windows 11*") {    
        
        $LangPacks = GCI "$CDDrive\langpack\Win 11\*.cab" | Select-Object -ExpandProperty FullName

        ForEach ($Lang in $LangPacks) {            
            
            $LangShortCode = $Lang.Substring($Lang.Length -9).Split(".")[0]

            Write-CustomLog -ScriptLog $ScriptLog -Message "Installing $LangShortCode. Note: This process can be up to 10 mins" -Level INFO            
            
            Add-WindowsPackage -Online -PackagePath "$Lang" -LogPath "C:\admin\Build\Lang-Pack-Install.log" -NoRestart        
            
            Write-CustomLog -ScriptLog $ScriptLog -Message "Adding $LangShortCode to preferred display languages" -Level INFO
            
            $OldList = Get-WinUserLanguageList
			$OldList.Add("$LangShortCode")
			Set-WinUserLanguageList -LanguageList $OldList -Confirm:$False -Force
        }        
    
    IF ($OS -like "*Microsoft Windows Server 2019*") {
        
        $LangPacks = GCI "$CDDrive\langpack\Win 2019\*.cab" | Select-Object -ExpandProperty FullName

        ForEach ($Lang in $LangPacks) {            
            
            $LangShortCode = $Lang.Substring($Lang.Length -9).Split(".")[0]

            Write-CustomLog -ScriptLog $ScriptLog -Message "Installing $LangShortCode. Note: This process can be up to 10 mins" -Level INFO           
            
            Add-WindowsPackage -Online -PackagePath "$Lang" -LogPath "C:\admin\Build\Lang-Pack-Install.log" -NoRestart        
            
            Write-CustomLog -ScriptLog $ScriptLog -Message "Adding $LangShortCode to preferred display languages" -Level INFO
            
            $OldList = Get-WinUserLanguageList
			$OldList.Add("$LangShortCode")
			Set-WinUserLanguageList -LanguageList $OldList -Confirm:$False -Force
        }                
    
    }    

}

    IF ($OS -like "*Microsoft Windows Server 2022*") {
        
            $LangPacks = GCI "$CDDrive\langpack\Win 2022\*.cab" | Select-Object -ExpandProperty FullName

            ForEach ($Lang in $LangPacks) {            
            
                $LangShortCode = $Lang.Substring($Lang.Length -9).Split(".")[0]               

                Write-CustomLog -ScriptLog $ScriptLog -Message "Installing $LangShortCode. Note: This process can be up to 10 mins" -Level INFO                
            
                Add-WindowsPackage -Online -PackagePath "$Lang" -LogPath "C:\admin\Build\Lang-Pack-Install.log" -NoRestart        
            
                Write-CustomLog -ScriptLog $ScriptLog -Message "Adding $LangShortCode to preferred display languages" -Level INFO
                
                $OldList = Get-WinUserLanguageList
				$OldList.Add("$LangShortCode")
				Set-WinUserLanguageList -LanguageList $OldList -Confirm:$False -Force

            }                   
    
        }    

    }

Else {

    Write-CustomLog -ScriptLog $ScriptLog -Message "ExtraLangPack key is not set to 1. Only En-US will be enabled on this system" -Level INFO

}

### END

### Test internet before starting windows update process as per https://stackoverflow.com/questions/33283848/determining-internet-connection-using-powershell
#Get-NetRoute | ? DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where ConnectionState -eq 'Connected'

If ((Get-NetConnectionProfile).IPv4Connectivity -eq 'Internet') {


    Write-host "Basic internet connectivity test completed" -ForegroundColor Green

}

Else {

    Write-warning "Basic internet test failed, please check firewall / static IP config / DHCP is recommended for these builds. The next phase requires reqular non firewall / proxy access to windowsupdate.com"
    PAUSE
}

Write-CustomLog -ScriptLog $ScriptLog -Message "Running Optimize Base image script" -Level INFO

set-location C:\admin\Scripts
powershell.exe -executionpolicy bypass -file .\Start-OptimizeBaseImage.ps1

### Desktop shortcut creation for build account

## Shortcut creations
## 1 Build logs
$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\desktop\BuildLogs.lnk")
$Shortcut.TargetPath = "C:\Admin\Build"
$Shortcut.Save()

## 2 App installs script
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\Download App Install Scripts.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"    
$Shortcut.Arguments = '-NoProfile -ExecutionPolicy Bypass -File "C:\Admin\Scripts\Start-AppInstalls.ps1"'
$Shortcut.IconLocation = ",0"
$Shortcut.WindowStyle = 1 #Minimized
$Shortcut.WorkingDirectory = "C:\Admin\Scripts"
$Shortcut.Description ="Download App install scripts"
$Shortcut.Save()
$bytes = [System.IO.File]::ReadAllBytes("$Home\Desktop\Download App Install Scripts.lnk")
$bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
[System.IO.File]::WriteAllBytes("$Home\Desktop\Download App Install Scripts.lnk", $bytes)

## 3 Reboot now
$WshShell = New-Object -ComObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$Home\Desktop\REBOOT NOW!.lnk")
$Shortcut.TargetPath = "C:\Windows\System32\cmd.exe"
$Shortcut.Arguments = 'C:\Windows\System32\cmd.exe /c shutdown -r -f -t 10'
$Shortcut.IconLocation = ",0"
$Shortcut.WindowStyle = 1 #Minimized
$Shortcut.WorkingDirectory = "C:\Windows\System32"
$Shortcut.Description ="REBOOT PC AFTER 10 SECONDS"
$Shortcut.Save()
$bytes = [System.IO.File]::ReadAllBytes("$Home\Desktop\REBOOT NOW!.lnk")
$bytes[0x15] = $bytes[0x15] -bor 0x20 #set byte 21 (0x15) bit 6 (0x20) ON
[System.IO.File]::WriteAllBytes("$Home\Desktop\REBOOT NOW!.lnk", $bytes)

Write-CustomLog -ScriptLog $ScriptLog -Message "Start-PostOSInstall script completed, the VM will reboot and auto logon to start windows update processing will close in 30 seconds" -Level INFO

start-sleep -s 30

Restart-Computer -Force


