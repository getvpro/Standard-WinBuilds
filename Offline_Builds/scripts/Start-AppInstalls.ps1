<#

.FUNCTIONALITY
App installs

.SYNOPSIS
Change log

Dec 7, 2021
-Initial version

Dec 8, 2021
-App worklist updated

April 1, 2022
-Added logging
-App installs called @ end
-Added more apps

April 2, 2022
-Commented out apps not setup yet
-Code for O365 install amended to use to start-process

April 26, 2022
-Sys Internals code moved over to Post-Build script

.DESCRIPTION
Author oreynolds@gmail.com

.EXAMPLE
./Start-AppInstalls.ps1

.NOTES

.Link
https://github.com/getvpro/Build-Packer

#>

IF (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    write-warning "not started as elevated session, exiting"    
    EXIT

}

IF (-not(test-path -Path c:\Admin\Scripts\App_Installs)) {

    New-Item -path c:\Admin\Scripts\App_Installs -ItemType Directory

}

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

### End Functions

# Powershell module/package management pre-reqs
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

$OS = (Get-WMIobject -class win32_operatingsystem).Caption
$LogTimeStamp = (Get-Date).ToString('MM-dd-yyyy-hhmm-tt')
#$PackerRegKey = (Get-ItemProperty -Path "hklm:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PackerLaunched -ErrorAction SilentlyContinue).PackerLaunched
$ScriptLog = "c:\Admin\Build\App-Installs-$LogTimeStamp.txt"

Write-host "Downloading Microsoft Runtimes install script" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Microsoft RunTimes')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Microsoft RunTimes' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Visual%20C%2B%2B%20Runtimes/Install-All.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft RunTimes\Install-All.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Visual%20C%2B%2B%20Runtimes/Install-LatestOnly.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft RunTimes\Install-Latest.ps1'

#2 Microsoft  Edge Business

Write-host "Downloading Microsoft  Edge Business install script" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Microsoft Edge Business')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Microsoft Edge Business' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Edge%20for%20Business/Install.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Edge Business\Install.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Edge%20WebView2%20Runtime/Install.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Edge Business\Install_EdgeWebViewRunTime.ps1'

#3 Microsoft OneDrive

Write-host "Downloading Microsoft OneDrive enterprise install script" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Microsoft OneDrive Enterprise')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Microsoft OneDrive Enterprise' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/OneDrive%20for%20Business/Install.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft OneDrive Enterprise\Install.ps1'

###

#4 MS Teams

Write-host "Downloading Microsoft Teams VDI install script" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Microsoft Teams')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Microsoft Teams' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Teams/Install.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Teams\install.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://github.com/JonathanPitre/Apps/blob/master/Microsoft/Teams/Teams.mst?raw=true `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Teams\Teams.mst'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Teams/desktop-config.json `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Teams\desktop-config.json'

# 5 FSlogix

Write-host "Downloading Microsoft FSLogix install script" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Microsoft FSLogix')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Microsoft FSLogix' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/FSLogix%20Apps/Install-Agent.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft FSLogix\install-Agent.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/FSLogix%20Apps/Install-JavaRuleEditor.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft FSLogix\Install-JavaRuleEditor.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/FSLogix%20Apps/Install-RuleEditor.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft FSLogix\Install-RuleEditor.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/FSLogix%20Apps/Redirection/Redirections.xml `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft FSLogix\redirections.xml'

#6 Office 365 via script

Write-host "Downloading Microsoft Office 365 install script" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Microsoft Office 365')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Microsoft Office 365' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Office%20365/Install-Office.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Office 365\Install-Office.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Office%20365/Office365-x64-VDI.xml `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Office 365\Office365-x64-VDI.xml'

#7 Google Chrome

Write-host "Downloading Google Chrome install script" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Google Chrome')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Google Chrome' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Google/Chrome%20Enterprise/Install.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Google Chrome\Install.ps1'

#8 - Citrix VDA

Write-host "Downloading Citrix VDA install scripts for PVS/MCS/Server/Desktop, delete un-needed scripts as required" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Citrix VDA')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Citrix VDA' -ItemType Directory

}

IF ($OS -like "*Windows 1*") {

    Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-WorkstationMCS-CR.ps1 `
    -OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-WorkStationMCS-CR.ps1'

    Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-WorkstationPVS-CR.ps1 `
    -OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-WorkStationPVS-CR.ps1'

}

Else {

    Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-ServerMCS-CR.ps1 `
    -OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-ServerMCS-CR.ps1'

    Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-ServerPVS-CR.ps1 `
    -OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-ServerPVS-CR.ps1'

}

#7 - END Citrix VDA

#8 Citrix Workspace App

IF ($OS -like "*Windows 1*") {

    Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Workspace%20App/Install-Workstation-CR.ps1 `
    -OutFile 'c:\Admin\Scripts\App_Installs\Citrix Workspace app\Install-Workstation-CR.ps1'

}

Else {

   Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Workspace%20App/Install-Server-CR.ps1 `
    -OutFile 'c:\Admin\Scripts\App_Installs\Citrix Workspace app\Install-Server-CR.ps1'

}

#10 7-zip
new-item -Path 'c:\Admin\Scripts\App_Installs\7-zip\' -ItemType Directory
Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/7-Zip/Install.ps1 -OutFile 'c:\Admin\Scripts\App_Installs\7-zip\Install.ps1'

#11 Download Adobe Reader / DC

new-item -Path 'c:\Admin\Scripts\App_Installs\Adobe DC\' -ItemType Directory

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Adobe/Acrobat%20DC/Install.ps1 -OutFile `
'c:\Admin\Scripts\App_Installs\Adobe DC\Install_Adobe_DC_Pro_x64.ps1'

#14 Control UP analyze logon script

EXIT

#15 Citrix CQI - rarely updated
#https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Connection%20Quality%20Indicator/Install.ps1 # read from ISO

#16 Citrix Optimizer - irregular updates
#https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Optimizer%20Tool/Install.ps1 # read from ISO

#17 Powershell SDK - regular updates
#https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Remote%20Powershell%20SDK/Install.ps1 # read from ISO

#18 Citrix GPO - tied to CR/LTSR regular updates
#https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Group%20Policy%20Management/Install-CR.ps1 # read from ISO

### Start app installs

Write-host "Starting install of MS RunTimes" -ForegroundColor Cyan
. "C:\admin\scripts\App_Installs\Microsoft RunTimes\Install-Latest.ps1"

Write-host "Starting install of 7-7ip" -ForegroundColor Cyan
. 'c:\Admin\Scripts\App_Installs\7-zip\Install.ps1'

Write-host "Starting install of Google Chrome" -ForegroundColor Cyans
. "C:\admin\scripts\App_Installs\Google Chrome\Install.ps1"

Write-host "Starting install of Edge Chrome" -ForegroundColor Cyan
. "c:\Admin\Scripts\App_Installs\Microsoft Edge Business\Install_EdgeWebViewRunTime.ps1"
. "C:\admin\scripts\App_Installs\Microsoft Edge Business\Install.ps1"

Write-host "Starting install of FSLogix Suite" -ForegroundColor Cyan
. "C:\admin\scripts\App_Installs\Microsoft FSLogix\install-Agent.ps1"
. "C:\admin\scripts\App_Installs\Microsoft FSLogix\Install-JavaRuleEditor.ps1"
. "C:\admin\scripts\App_Installs\Microsoft FSLogix\Install-RuleEditor.ps1"

Write-host "Starting install of MS Office 365" -ForegroundColor Cyan
Set-Location "C:\Admin\Scripts\App_Installs\Microsoft Office 365"
Start-Process powershell .\Install-Office.ps1 -PassThru -Wait

Write-host "Starting install of MS OneDrive" -ForegroundColor Cyan
. "C:\admin\scripts\App_Installs\Microsoft OneDrive Enterprise\Install.ps1"

Write-host "Starting install of MS Teams" -ForegroundColor Cyan
. "C:\admin\scripts\App_Installs\Microsoft Teams\install.ps1"

### Citrix installs from ISO here
#Requries detection of Single OS / Multi OS, PVS or MCS, default to MCS after 30 seconds
# Multi-OS requires RDS pre-install + runOnce key to start actual install


