<#

.FUNCTIONALITY
-Basic Citrix golden image prep script
-Run this before you take a snapshot on a MCS / PVS master
-Ensure you've got delprof2 extracted to c:\windows\system32: https://helgeklein.com/free-tools/delprof2-user-profile-deletion-tool/
-Edit the line with $CTXBuildID for your environment or comment out if you don't have a dedicated build account, but you should!

.SYNOPSIS

-Basic Citrix golden image prep script
-Run this before you take a snapshot on a MCS / PVS master
-Ensure you've got delprof2 extracted to c:\windows\system32: https://helgeklein.com/free-tools/delprof2-user-profile-deletion-tool/
-Edit Line 45 for your environmenb or comment out if you don't have a dedicated build account, but you should!
-Edit the line with $CTXBuildID for your environment or comment out if you don't have a dedicated build account, but you should!

.NOTES
Change log

Nov 3, 2021
-Initial version

Nov 29, 2021
-Added download of delprof2.exe from getvpro github

Nov 30, 2021
-Windows update will be set to disabled

Dec 10, 2021
-Added WEM cache reset

.DESCRIPTION
Author oreynolds@gmail.com

.EXAMPLE
./Start-ClonePrep.ps1

.NOTES

.Link
N/A

#>

If ($psISE) {

    $CurrentDir = Split-path $psISE.CurrentFile.FullPath
}

Else {

    $CurrentDir = split-path -parent $MyInvocation.MyCommand.Definition

}

### Change per environment here
$CTXBuildIDName = ""

###
$ErrorActionPreference = "SilentlyContinue"
$ShortDate = (Get-Date).ToString('MM-dd-yyyy')
$LogTimeStamp = (Get-Date).ToString('MM-dd-yyyy-hhmm-tt')
$ScriptLog = "$CurrentDir\Build\CXTImageBuild-$LogTimeStamp.log"
$ShortDate = (Get-Date).ToString('MM/dd/yyyy')
$CTXBuildDate = (Get-Date).ToString('MMMM dd, yyyy')

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
        
        Add-content -value "$Message" -Path $ScriptLog
}


function Select-BuildEnv {
    param (
        [string]$Title = 'Build environment selection'
    )
    Clear-Host
    Write-Host "================ $Title ================"    
    Write-Host "`r"
    Write-Host "1: Press '1' UAT (TESTING)"
    Write-Host "`r"
    Write-Host "2: Press '2' PROD"    
    Write-Host "`r"
    Write-Host "Q: Press 'Q' to quit"
}

##Pending reboot
#Based on <http://gallery.technet.microsoft.com/scriptcenter/Get-PendingReboot-Query-bdb79542>
Function Test-PendingReboot {
    if (Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -EA Ignore) { return $true }
    if (Get-Item "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired" -EA Ignore) { return $true }
    if (Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager" -Name PendingFileRenameOperations -EA Ignore) { return $true }
    try { 
        $util = [wmiclass]"\\.\root\ccm\clientsdk:CCM_ClientUtilities"
        $status = $util.DetermineIfRebootPending()
        if (($status -ne $null) -and $status.RebootPending) {
            return $true
        }
    }
    catch { }

    return $false
}
### User prompt for build env

do {
    Select-BuildEnv
    Write-Host "`r"
    $input = Read-Host "Please make a selection"
    switch ($input) {
        '1' {
            Clear-Host
            $BuildEnv = "UAT"
        }

        '2' {
            Clear-Host
            $BuildEnv = "PROD"

        }       

        'q' {
            Write-Warning "Script will now exit"
            EXIT
        }
    }

    "Build environment is $BuildEnv"
    Write-Host "`r"
    Pause
}
until ($input -ne $null)

IF (-not(test-path $CurrentDir\Build)) {

    new-item -Path $CurrentDir\Build -ItemType Directory

}

Write-CustomLog -Message "Downloading delfprof.exe from getvpro github" -Level INFO -ScriptLog $ScriptLog

Invoke-WebRequest -Uri "https://github.com/getvpro/Standard-WinBuilds/blob/master/Delprof2/DelProf2.exe?raw=true" -OutFile "C:\Windows\System32\delprof2.exe"

Write-CustomLog -Message "Running MCS prep steps" -Level INFO -ScriptLog $ScriptLog

### Pre-check section, the script will exit if these conditions are not met
IF (($CTXBuildName).Length -ge 0) {

    Write-CustomLog -Message "You must enter in a build ID into line 48. If you don't have a dedicated ID, enter in your own ID. The script will now exit." -Level WARN -ScriptLog $ScriptLog

}

IF ($Env:Username -ne "$CTXBuildIDName") {

    Write-CustomLog -Message "The build script must be from the $CTXBuildIDName account. The script will now exit." -Level WARN -ScriptLog $ScriptLog
    EXIT
}

if (Test-PendingReboot -eq $True) {

    Write-CustomLog -Message A reboot is pending on this machine. Please reboot this machine first -Level WARN -ScriptLog $ScriptLog
    EXIT

}

Else {

    Write-host "No reboots required, script will continue" -ForegroundColor Green

}

[Environment]::SetEnvironmentVariable("BuildEnv", "$BuildEnv", "Machine")
[Environment]::SetEnvironmentVariable("CTXBuildDate", "$CTXBuildDate", "Machine")

Write-CustomLog -Message "Reset Win 10 start menu/taskbar for current_user based on custom layout copied down in preceding step" -Level INFO -ScriptLog $ScriptLog

Copy-Item -path "c:\users\default\AppData\Local\Microsoft\Windows\Shell\LayoutModification.xml" -Destination "$env:LocalAppData\Microsoft\Windows\Shell" -force

Remove-item -Path 'HKCU:\Software\Microsoft\Windows\CurrentVersion\CloudStore\Store\Cache\DefaultAccount\*$start.tilegrid$windows.data.curatedtilecollection.tilecollection' -force -recurse

Get-Process Explorer | Stop-Process -Force

Write-CustomLog -Message "Clearing old cached profiles and temp files" -Level INFO -ScriptLog $ScriptLog

### Run delprof2 to remove any locally cached profiles
Set-Location c:\Windows\System32
Delprof2.exe /ed:*administrator* /ed:$CTXBUILD /u

Get-ChildItem $env:Temp -recurse | Remove-Item -ErrorAction $ErrorActionPreference  -Force -Recurse

### Clear recycle bin
Clear-RecycleBin -force

### Set windows update to startup type disabled
Set-Service -Name wuauserv -StartupType Disabled -ErrorAction SilentlyContinue

<#Set WU-Updates key back to default, which is 1
IF ((Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU").UseWUServer -ne "1") {

    Write-CustomLog -Message "Setting WSUS updates key back to 1 " -Level INFO   -ScriptLog $ScriptLog
    reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU" /v "UseWUServer" /t REG_DWORD /d 1 /F
    Get-Service -name "Windows update" | Restart-Service -force

}
#>

IF (Get-Service -Name AppVClient -ErrorAction $ErrorActionPreference) {

    Write-CustomLog -Message "Running reset of App-V cache" -Level INFO -ScriptLog $ScriptLog
    Get-AppvClientPackage -All | Remove-AppvClientPackage
    Get-Service -name AppVClient | Stop-Service -Force
    Get-ChildItem -Path $env:ProgramData\App-V -ErrorAction $ErrorActionPreference SilentlyContinue | Remove-Item -force -Recurse
    Start-Service -name AppVClient -ErrorAction $ErrorActionPreference

}

### Delete WEM cache on a PVS device
### https://www.carlstalhood.com/workspace-environment-management/
IF (Get-service -Name WemAgentSVC -ErrorAction SilentlyContinue) {

    Stop-Service -Name WemAgentSVC -force

    Stop-Service -Name WemLogonSVC -force    

    #net stop "Citrix WEM Agent Host Service" /y
    #net stop "Norskale Agent Host Service" /y
    
    GCI D:\WEMCache\ /S /F /q
    
    Start-Service -Name WemAgentSVC -force

    Start-Service -Name WemLogonSVC -force
    
    Start-Service -Name "Netlogon"    
    Start-sleep -Seconds 45

    #"C:\Program Files (x86)\Citrix\Workspace Environment Management Agent\AgentCacheUtility.exe" -refreshcache -brokername:XXXX
    #"C:\Program Files (x86)\Norskale\Norskale Agent Host\AgentCacheUtility.exe" -refreshCache -brokerName:XXXX

}


Write-CustomLog -Message "End of Win 10 $BuildEnv script processing @ $shortDate" -Level INFO -ScriptLog $ScriptLog
Write-CustomLog -Message "Software installation is now completed. The computer $envComputerName will now reboot!" -Level INFO -ScriptLog $ScriptLog
Start-Sleep -s 15
Stop-Computer -Force