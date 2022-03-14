<#
.FUNCTIONALITY
-Attempts to ID major hypervisor types: Citrix/Nutnaix/VMware and install drivers from the root custom windows ISO folder 'hypervisor_drivers'

.SYNOPSIS
-This script was created to be used as part of automating windows 10/server builds via autounattend.xml
-The script assumes the VM has NOT internet access, so is hard-coded to use the drivers in the above path , which are the latest as of Nov 30, 2021
-Updates to VMware drivers can later be handled via the following script: https://github.com/JonathanPitre/Apps/tree/master/VMWare/Tools
-Automated updates to Nutanix/Citrix are TBD

.NOTES
Change log

Nov 30, 2021
-Initial version

Dec 1, 2021
-Added code to switch logging method based on being launched from packer/custom ISO
-PowerShellGet installed before PSADT to resolve prompt on pre-req
-Powershell security changes

March 14, 2022
-Offline version
-New variable of $VMT used to stop VMware tools from re-installing where it's already installed, mostly for testing script edits

.EXAMPLE
./Install-HyperVisorDrivers.ps1

.NOTES

.Link
https://scriptech.io/automatically-reinstalling-vmware-tools-on-server2016-after-the-first-attempt-fails-to-install-the-vmtools-service/
https://github.com/getvpro/Build-Packer
https://getvpro.wordpress.com/2020/07/29/10-min-windows-10-server-2019-build-automation-via-osdbuilder-autounattend-xml-and-packer-io/

#>

IF (-not(test-path c:\admin\Build)) {

    New-Item -Path c:\Admin\Build -ItemType Directory

}

$OS = (Get-WMIobject -class win32_operatingsystem).Caption
$LogTimeStamp = (Get-Date).ToString('MM-dd-yyyy-hhmm-tt')

### Powershell module/package management pre-reqs
[Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
[System.Net.WebRequest]::DefaultWebProxy.Credentials = [System.Net.CredentialCache]::DefaultCredentials

$ScriptLog = "c:\Admin\Build\HyperVisorDriverInstall-$LogTimeStamp.txt"

###

$CDDrive = Get-CimInstance Win32_LogicalDisk | ?{ $_.DriveType -eq 5} | select-object -expandproperty DeviceID
$VMType = (Get-ItemProperty -path HKLM:\HARDWARE\DESCRIPTION\System\BIOS -Name SystemManufacturer).SystemManufacturer

Function Get-VMToolsInstalled {
    
    IF (((Get-ChildItem "HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall") | Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0) {
        
        [int]$Version = "32"
    }

    IF (((Get-ChildItem "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall") | Where-Object { $_.GetValue( "DisplayName" ) -like "*VMware Tools*" } ).Length -gt 0) {

       [int]$Version = "64"
    }    

    return $Version
}

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


### VMware
### REBOOT=R means supress reboot

$VMT = Get-VMToolsInstalled

IF (($VMType -eq "VMware, Inc.") -and (-not($VMT))) {

    Write-CustomLog -ScriptLog $ScriptLog -Message "VMware type VM confirmed, starting install attempt of VMware tools" -Level INFO    

    Start-Process "$CDDrive\hypervisor_drivers\VMware-tools-11.3.5 x64.exe" -ArgumentList '/s /v "/qb REBOOT=R"' -Wait

    ### 3 - After the installation is finished, check to see if the 'VMTools' service enters the 'Running' state every 2 seconds for 10 seconds
    $Running = $false
    $iRepeat = 0

    while (-not$Running -and $iRepeat -lt 5) {      

      Write-CustomLog -ScriptLog $ScriptLog -Message "Pause for 2 seconds to check running state on VMware tools service" -Level INFO
      Start-Sleep -s 2
      $Service = Get-Service "VMTools" -ErrorAction SilentlyContinue
      $Servicestatus = $Service.Status

      if ($ServiceStatus -notlike "Running") {

        $iRepeat++

      }

      Else {

        $Running = $true

        Write-CustomLog -ScriptLog $ScriptLog -Message "VMware tools service found to be running state after first install attempt" -Level INFO
        
      }

    }
    ### 4 - If the service never enters the 'Running' state, re-install VMWare Tools
    if (-not$Running) {

      #Uninstall VMWare Tools
      Write-CustomLog -ScriptLog $ScriptLog -Message "Running un-install on first attempt of VMware tools install" -Level WARN

      IF (Get-VMToolsInstalled -eq "32") {
  
        $GUID = (Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -Like '*VMWARE Tools*' }).PSChildName

      }

      Else {
  
        $GUID = (Get-ItemProperty HKLM:\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | Where-Object { $_.DisplayName -Like '*VMWARE Tools*' }).PSChildName

      }

      ### 5 - Un-install VMWARe tools based on 32-bit/64-bit install GUIDs captured via Get-VMToolsIsInstalled function
  
      Start-Process -FilePath msiexec.exe -ArgumentList "/X $GUID /quiet /norestart" -Wait  

      Write-CustomLog -ScriptLog $ScriptLog -Message "Running re-install of VMware tools install" -Level INFO
    
      #Install VMWare Tools
      Start-Process "$CDDrive\hypervisor_drivers\VMware-tools-11.3.5 x64.exe" -ArgumentList '/s /v "/qb REBOOT=R"' -Wait

      ### 6 - Re-check again if VMTools service has been installed and is started

     Write-CustomLog -ScriptLog $ScriptLog -Message "Re-checking if VMTools service has been installed and is started" -Level INFO 
  
    $iRepeat = 0
    while (-not$Running -and $iRepeat -lt 5) {

        Start-Sleep -s 2
        $Service = Get-Service "VMTools" -ErrorAction SilentlyContinue
        $ServiceStatus = $Service.Status
    
        If ($ServiceStatus -notlike "Running") {

          $iRepeat++

        }

        Else {

          $Running = $true
          Write-CustomLog -ScriptLog $ScriptLog -Message "VMware tools service found to be running state after SECOND install attempt" -Level INFO      
        
        }

      }

      ### 7 If after the reinstall, the service is still not running, this is a failed deployment

      IF (-not$Running) {
        Write-CustomLog -ScriptLog $ScriptLog -Message "VMWare Tools is still not installed correctly. The automated deployment will not process any further until VMWare Tools is installed" -Level ERROR
        EXIT

      }

    }

} #VMware Tools

### Citrix Hypervisor VM tools

IF ($VMType -eq "Xen") {   

    Write-CustomLog -ScriptLog $ScriptLog -Message "Citrix Xen  type VM confirmed, starting install attempt of Citrix XenServer VM Tools" -Level INFO
    (Start-Process "msiexec.exe" -ArgumentList '/quiet /norestart /i "$CDDrive\hypervisor_drivers\Citrix VM Tools 9.2.1 x64.msi"' -NoNewWindow -Wait -PassThru).ExitCode
    
}

### End  Hypervisor VM tools

### Nutanix

IF ($VMType -eq "Nutanix") {   

    Write-CustomLog -ScriptLog $ScriptLog -Message "Nutanix type VM confirmed, starting install attempt of Nutanix VirtIO drivers" -Level INFO
    (Start-Process "msiexec.exe" -ArgumentList '/QB /norestart /i "$CDDrive\hypervisor_drivers\Nutanix-VirtIO-1.1.7-amd64.msi"' -NoNewWindow -Wait -PassThru).ExitCode
    
}

### End Nutanix

Write-CustomLog -ScriptLog $ScriptLog -Message "Hypervisor driver install script completed, please reboot" -Level INFO
