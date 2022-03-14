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
$FrenchCaLangPack = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name FrenchCaLangPack -ErrorAction SilentlyContinue).FrenchCaLangPack
$PackerStaticIP = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PackerStaticIP -ErrorAction SilentlyContinue).PackerStaticIP
$CDDrive = Get-CimInstance Win32_LogicalDisk | ?{ $_.DriveType -eq 5} | select-object -expandproperty DeviceID

### Create directory structure as required

new-item -ItemType Directory -Path "c:\Admin\Scripts"
new-item -ItemType Directory -Path "C:\Admin\Build"
new-item -ItemType Directory -Path "C:\Admin\Language Pack"

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

### Create 'this pc' on current users deskop

$path="HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HideDesktopIcons\NewStartPanel"
$name="{20D04FE0-3AEA-1069-A2D8-08002B30309D}"

New-Item -Path HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer -Name HideDesktopIcons\NewStartPanel
New-ItemProperty -Path $path -Name $name -Value 0 -Force

### remove server manager from startup for current user
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

Get-ChildItem "$CDDrive\Scripts" -Filter *.ps1 | Select-Object -ExpandProperty FullName | ForEach {copy-item -Path $_ -Destination C:\Admin\Scripts -Force}

Get-ChildItem "$CDDrive\Scripts" -Filter *.xml | Select-Object -ExpandProperty FullName | ForEach {copy-item -Path $_ -Destination C:\Admin\Scripts -Force}

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


    Write-host "Basic internet connectivity test completed" -ForegroundColor Green

}

Else {

    Write-warning "Basic internet test failed, please check firewall / static IP config / DHCP is recommended for these builds. The next phase requires reqular non firewall / proxy access to windowsupdate.com"
    PAUSE
}

Write-CustomLog -ScriptLog $ScriptLog -Message "Start-PostOSInstall script completed, the VM will reboot and auto logon to start windows update processing will close in 30 seconds" -Level INFO

start-sleep -s 30

Restart-Computer -Force


