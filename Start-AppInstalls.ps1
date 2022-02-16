## Script prep

if (-not(test-path -Path c:\Admin\Scripts\App_Installs)) {

    New-Item -path c:\Admin\Scripts\App_Installs -ItemType Directory

}

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

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Microsoft/Edge%20for%20Business/master_preferences `
-OutFile 'c:\Admin\Scripts\App_Installs\Microsoft Edge Business\master_preferences'

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

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Google/Chrome%20Enterprise/master_preferences `
-OutFile 'c:\Admin\Scripts\App_Installs\Google Chrome\master_preferences'

#8 - Citrix VDA

Write-host "Downloading Citrix VDA install scripts for PVS/MCS/Server/Desktop, delete un-needed scripts as required" -ForegroundColor Cyan

if (-not(test-path -Path 'c:\Admin\Scripts\App_Installs\Citrix VDA')) {

   New-Item -path 'c:\Admin\Scripts\App_Installs\Citrix VDA' -ItemType Directory

}

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-ServerMCS-CR.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-ServerMCS-CR.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-ServerPVS-CR.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-ServerPVS-CR.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-WorkstationMCS-CR.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-WorkStationMCS-CR.ps1'

Invoke-WebRequest -UseBasicParsing -Uri https://raw.githubusercontent.com/JonathanPitre/Apps/master/Citrix/Virtual%20Delivery%20Agent/Install-WorkstationPVS-CR.ps1 `
-OutFile 'c:\Admin\Scripts\App_Installs\Citrix VDA\Install-WorkStationPVS-CR.ps1'

#7 - END Citrix VDA