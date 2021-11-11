<#
.FUNCTIONALITY
-Calls PSWindowsUpdate module https://www.powershellgallery.com/packages/PSWindowsUpdate/2.2.0.2
-Can easily be called to run as a  scheduled task
-Logs to event viewer

.SYNOPSIS
-Calls PSWindowsUpdate module https://www.powershellgallery.com/packages/PSWindowsUpdate/2.2.0.2
-Can easily be called to run as a  scheduled task
-Logs to event viewer

.NOTES
Change log

July 25, 2020: Added write-host

Nov 8, 2020: Updated line 43 

Nov 9, 2020: Removed minimum version on Nuget install

Feb 23, 2020: Exit if not run as admin

July 12, 2021
-Added EA silently contune

.DESCRIPTION
Author oreynolds@gmail.com

.EXAMPLE
./Get-WindowsUpdatesSingle.ps1

.NOTES

.Link
N/A

#>

$EventIDSrc = "PSWindowsUpdate"

IF (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    write-warning "not started as elevated session, exiting"
    EXIT

}

IF (-not([System.Diagnostics.EventLog]::SourceExists("$EventIDSrc"))) {
    
    New-EventLog -LogName SYSTEM -Source $EventIDSrc

}

IF (!(Get-PackageProvider -ListAvailable nuget) ) {

    Install-PackageProvider -Name NuGet -Force
    Write-EventLog -LogName SYSTEM -Source $EventIDSrc -EventId 0 -EntryType INFO -Message "The Nuget package manager will be installed"

}

IF (!(Get-Module -ListAvailable -Name PSWindowsUpdate)) {

    Install-module pswindowsupdate -force
    Write-host "The PSWindowsUpdate module will be installed" -foregroundcolor cyan
    Write-EventLog -LogName SYSTEM -Source $EventIDSrc -EventId 0 -EntryType INFO -Message "The PSWindowsUpdate module will be installed"

}

write-host "Importing PSWindowsUpdate" -ForegroundColor Cyan
Import-Module -Name PSWindowsUpdate

$Updates  = Get-WUList
$Updates = $Updates  | Select KB, Size, Title

IF  ($Updates -ne $Null) {

    Write-host "The following windows updates will be installed: `n $($Updates | Out-String)" -ForegroundColor Cyan

    Write-EventLog -LogName SYSTEM -Source $EventIDSrc -EventId 0 -EntryType INFO -Message "The following windows updates will be installed `n $($Updates | Out-String)"
    
    Get-WUInstall -MicrosoftUpdate -AcceptAll -UpdateType Software -Install -AutoReboot  
    
}

Else {

    Write-host "No windows updates to install at this time" -foregroundcolor green
    Write-EventLog -LogName SYSTEM -Source $EventIDSrc -EventId 0 -EntryType INFO -Message "No windows updates to install at this time"

}    
