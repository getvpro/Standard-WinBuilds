<#

.FUNCTIONALITY
First steps after GUI launches on new Win assets built by packer/autonunattend.xml process

.SYNOPSIS
Change log

July 23, 2020
-Initial version

July 25, 2020
-Removed WinRM enablement

July 27, 2020
-Amended to support Win 10

Aug 25, 2021
-Added import of PSWindowsUpdate

Nov 25, 2021
-Install PowerShell App Deploy toolkit
-Downloaded PSWindows Update and set as scheduled task
-Setup scheduled task for initial build tasks
-Download and run Optimize-BaseImage
-Replaced reg calls with native Powershell equivalent

Nov 26, 2021
-c:\Scripts changed to c:\Admin\Scripts
-Removed search box from HKCU

Nov 27, 2021
-Additional code to download scripts from github
-Import of Windows Updates PS task
-PSADT used for installation progress
-ServiceUI is downloaded from github

Nov 28, 2021
-Start-Optimized based image no longer launched minimized
-Custom logging added

Nov 29, 2021
-Removed WinRM code @ end
-Exit it not started elevated (admin)
-Environment variables for WinPackerStart/End added
-7-Zip portable download / install
-Fr-Ca language pack download / install

Nov 30, 2021
-c:\Admin\7-Zip is no longer created, as it's covered by .zip extraction
-Updated code to remove Fr-Ca .zip file set

Dec 1, 2021
-Logging method updated to reference new environment variable pushed from autounattend.xml that's only used with packer
-Server manager disable moved to start
-Search window disable moved to start
-c:\Admin\* folders creation moved to start
-RDP/network changes moved to start
-Exit if not started as admin moved to start
-Powershell security changes for TLS 1.2
-Commented out above security changes as part of testing
-Moved $ScriptLog variable before function that uses it
-Created $PackerRegKey
-Above $PackerRegKey resolved issues with $ScriptLog not being read, pause statements removed

Dec 2, 2021
-Code to import Windows update run on boot scheduled task disabled

Dec 4, 2021
-Code to import Windows update run on boot scheduled task re-enabled
-Added code to stop/disable Edge scheduled tasks @ start
-Removed un-needed restart of explorer.exe @ start
-New PS1 /XML Start/Monitor win updates

Dec 5, 2021
-Fixed path on lines 240-245 for XML/PS1 download

Dec 17, 2021
-Added OS detection to support downloads / installs of Fr-CA language pack for both Win 10 / Win 2022

.DESCRIPTION
Author https://github.com/getvpro (Owen Reynolds)

Jan 05, 2022
-Line 327: Fixed missing * for server OS detection

Jan 06, 2022
-Detection of sys env variable from autounattend.xml to install Fr-Ca lang pack
-Various edits to Show-InstallationProgress

Jan 10, 2022
-Edit to pause for IP check

Jan 11, 2022
-Code added to read in values from StaticIP.csv to deal with non-DHCP enabled environments
-Set-TimeZone -ID "Eastern Standard Time" added @ start to resolve issues with logging

Feb 11, 2022
-Added Fr-CA support for Windows 11 21H1

Feb 13, 2022
-c:\Admin only created as required

March 13, 2022
-New version specifically for offline use
-Added internet check at end
-Renamed to Start-PostOSInstall.ps1

March 14, 2022
-ServiceUI copied over to c:\windows\System32
-Restart-computer timer set to 30 seconds
-Updated build log shortcut creation method

.EXAMPLE
./Start-PostOSInstall.ps1

.NOTES

.Link
https://github.com/getvpro/Build-Packer

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
$FrenchCaLangPack = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name FrenchCaLangPack -ErrorAction SilentlyContinue).FrenchCaLangPack
$PackerStaticIP = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PackerStaticIP -ErrorAction SilentlyContinue).PackerStaticIP
$CDDrive = Get-CimInstance Win32_LogicalDisk | ?{ $_.DriveType -eq 5} | select-object -expandproperty DeviceID

### Create directory structure as required

If (-not(test-path c:\admin -ErrorAction SilentlyContinue)) {

    new-item -ItemType Directory -Path "c:\Admin\Scripts"
    new-item -ItemType Directory -Path "C:\Admin\Build"
    new-item -ItemType Directory -Path "C:\Admin\Language Pack"

}

# Set log path based on being launched by packer, or not

IF ($PackerRegKey -eq 1) {

    $ScriptLog = "c:\Admin\Build\WinPackerBuild-$LogTimeStamp.txt"
    
}

Else {
    
    $ScriptLog = (Get-ChildItem C:\Admin\Build | Sort-Object -Property LastWriteTime | Where-object {$_.Name -like "WinPackerBuild*"} | Select -first 1).FullName

}

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

### Part 1 - Start of script processing, first steps, requires no internet connection

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

New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name HideDesktopIcons\NewStartPanel
New-ItemProperty -Path $path -Name $name -Value 0 -Force

New-ItemProperty -Path "HKCU:\Software\Microsoft\ServerManager" -Name "DoNotOpenServerManagerAtLogon" -PropertyType DWORD -Value "0x1" –Force
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -PropertyType DWORD -Value "0x1" -Force

IF (Get-process "servermanager" -ErrorAction SilentlyContinue) {

    Stop-Process -name servermanager -Force    
}

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

GCI "$CDDrive\Scripts" -Filter *.ps1 | Select-Object -ExpandProperty FullName | ForEach {copy-item -Path $_ -Destination C:\Admin\Scripts}

copy-item "$CDDrive\Scripts\ServiceUI.exe" C:\Windows\System32 -Force

set-location C:\admin\Scripts

Write-CustomLog -ScriptLog $ScriptLog -Message "Running Optimize Base image script" -Level INFO

### Requires additional edits to remove use of PSADT - March 13, 2022
#powershell.exe -executionpolicy bypass -file .\Start-OptimizeBaseImage.ps1

Write-CustomLog -ScriptLog $ScriptLog -Message "Importing Windows Update task" -Level INFO

Register-ScheduledTask -XML (Get-content "C:\Admin\Scripts\Start-WinUpdates.xml" | Out-String) -TaskName Start-WinUpdates -Force

Register-ScheduledTask -XML (Get-content "C:\Admin\Scripts\Monitor-WinUpdates.xml" | Out-String) -TaskName Monitor-WinUpdates -Force

$WshShell = New-Object -comObject WScript.Shell
$Shortcut = $WshShell.CreateShortcut("$env:USERPROFILE\desktop\BuildLogs.lnk")
$Shortcut.TargetPath = "C:\Admin\Build"
$Shortcut.Save()

### Fr-ca language pack download for Server 2022 systems / Win 10 21H1 is pending

If ($FrenchCaLangPack -eq 1) {

    Write-CustomLog -ScriptLog $ScriptLog -Message "FrenchCaLangPack key is set to 1, proceeeding with extra steps to provision Fr-Ca lang pack" -Level INFO
    Set-Location 'C:\Admin\Language Pack'    

    Write-CustomLog -ScriptLog $ScriptLog -Message "Installing Fr-ca.cab, this process can be up to 10 mins" -Level INFO
    
    IF ($OS -like "*Windows 10*") {

    

        Add-WindowsPackage -Online -PackagePath "$CDDrive\langpack\Win10-21H1-x64-Fr-Ca.cab" -LogPath "C:\admin\Build\Fr-ca-Install.log" -NoRestart
        
        Write-CustomLog -ScriptLog $ScriptLog -Message "Adding Fr-Ca to preferred display languages" -Level INFO

		$OldList = Get-WinUserLanguageList
		$OldList.Add("fr-CA")
		Set-WinUserLanguageList -LanguageList $OldList -Confirm:$False -Force
    
    } 
    
    IF ($OS -like "*Windows 11*") {

        Add-WindowsPackage -Online -PackagePath "$CDDrive\langpack\Win11-21H1-x64-Fr-Ca.cab" -LogPath "C:\admin\Build\Fr-ca-Install.log" -NoRestart
        
        Write-CustomLog -ScriptLog $ScriptLog -Message "Adding Fr-Ca to preferred display languages" -Level INFO

		$OldList = Get-WinUserLanguageList
		$OldList.Add("fr-CA")
		Set-WinUserLanguageList -LanguageList $OldList -Confirm:$False -Force
    
    }    

    IF ($OS -like "*Windows Server*") {

        Add-WindowsPackage -Online -PackagePath "$CDDrive\langpack\Server-2022-x64-Fr-Ca.cab" -LogPath "C:\admin\Build\Fr-ca-Install.log" -NoRestart
        
        Write-CustomLog -ScriptLog $ScriptLog -Message "Adding Fr-Ca to preferred display languages" -Level INFO

		$OldList = Get-WinUserLanguageList
		$OldList.Add("fr-CA")
		Set-WinUserLanguageList -LanguageList $OldList -Confirm:$False -Force
    
    }
    
    Write-CustomLog -ScriptLog $ScriptLog -Message "Remove .zip files that contained Fr-ca.cab" -Level INFO
    

}

Else {

    Write-CustomLog -ScriptLog $ScriptLog -Message "FrenchCaLangPack key is not set to 1. Only En-US will be enabled on this system" -Level INFO

}

### END

### Test internet before starting windows update process as per https://stackoverflow.com/questions/33283848/determining-internet-connection-using-powershell
#Get-NetRoute | ? DestinationPrefix -eq '0.0.0.0/0' | Get-NetIPInterface | Where ConnectionState -eq 'Connected'

If ((Get-NetConnectionProfile).IPv4Connectivity -eq 'Internet') {


    Write-host "$IPGW pings back as expected" -ForegroundColor Green

}

Else {

    Write-warning "Basic internet test failed, please check firewall / static IP config / DHCP is recommended for these builds. The next phase requires reqular non firewall / proxy access to windowsupdate.com"
    PAUSE
}

Write-CustomLog -ScriptLog $ScriptLog -Message "Start-FirstSteps script completed, the VM will reboot and auto logon to start windows update processing will close in 30 seconds" -Level INFO

start-sleep -s 30

Restart-Computer -Force


