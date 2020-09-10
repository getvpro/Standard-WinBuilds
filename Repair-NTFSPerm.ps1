<#
.FUNCTIONALITY
Level-set NTFS permissions for roaming profiles

.SYNOPSIS
Level-set NTFS permissions for roaming profiles

.NOTES
Change log

Sept 8, 2020
-Initial version

.DESCRIPTION
Author owenr@procontact.ca

.EXAMPLE
./Repair-NTFSPerm.ps1

.NOTES

.Link
N/A

#>

$ShortDate = (Get-Date).ToString('MM-dd-yyyy')
$LogTimeStamp = (Get-Date).ToString('MM-dd-yyyy-hhmm-tt')
$ScriptLogPath = "\\CHANGE ME"
$ScriptLogTXT = "$ScriptLogPath\Migrate-Win7UserData-$LogTimeStamp.log"
$ReportsPath = "TBD"
$scriptpath = $MyInvocation.MyCommand.Path
$dir = Split-Path $scriptpath
$ShortDate = (Get-Date).ToString('MM/dd/yyyy')
$AllWin10VDIGroups = @("", "")
$CSS = ".\CSS.XML"
$EmailFrom = "NoReply@Customer.com"
$EmailTo = $EmailFrom
$EmailSMTP = "TBD"
$EmailRetryCount = "5"
$EmailSleepTimer = "5"
$WScript = New-Object -ComObject WScript.Shell
$OutputEncoding = [Console]::OutputEncoding
$AllDomains = (Get-ADForest).domains
$FilerPath = "\\FILERNAME\vdi_store"
#$HEAD = Get-Content $CSS

Function Check-ADUser {
    Param(
    $ADUser,
    $ADList    
    )
    
    $ADUserArray = @()

    ForEach ($Domain in $ADList) {

        write-host "Checking for $ADuser on $Domain ..."

        try {
                    
            $VDIuserDomain = Get-ADUser -Identity $ADUser -Server $Domain -Properties * -ErrorAction SilentlyContinue | Select @{n="DomainName"; e={($_.CanonicalName -split '/')[0]}}`
            | Select-Object DomainName -ExpandProperty DomainName            
            
        }

        catch {}

    } #ForEach $Domain 
    
    If (!$VDIuserDomain) {

        Write-Warning "AD User doesn't exist"
        $VDIuserDomain = "AD User doesn't exist"
    }

    Else {

        write-host "Collecting $ADUser AD properties.." -ForegroundColor Cyan

        $UserADObject = Get-ADUser -Identity $ADUser -server $VDIuserDomain -Properties * -ErrorAction SilentlyContinue
        $UserHomeDrv = $UserADObject | Select -ExpandProperty HomeDirectory
        $UserSite = $UserADObject| Select-Object -ExpandProperty msExchExtensionAttribute20
        $UserEmail = $UserADObject| Select-Object -ExpandProperty UserPrincipalName
        $UserFullName = $UserADObject| Select-Object -ExpandProperty Name
    }

    $ADUserArray += New-object PSobject -Property @{
    VDIuserDomain = $VDIuserDomain
    UserHomeDrv = $UserHomeDrv
    UserSite = $UserSite
    UserEmail = $UserEmail
    UserFullName = $UserFullName
    }
    
    Return $ADUserArray

} #Function Check-ADUser

function Select-OpMode
{
     param (
           [string]$Title = 'Repair NTFS permissions script'
     )
     cls
     Write-Host "================ $Title ================"
     Write-host "`r"
     Write-Host "1: Press '1' Report only"
     Write-host "`r"
     Write-Host "2: Press '2' Fix permissions"
     Write-host "`r"
     Write-Host "Q: Press 'Q' to quit"
}

Function Send-ReportEmail {
    
    Param(
    $EmailFrom,
    $EmailTo,
    $EmailBCC,
    $Subject,
    $EmailBody,
    $EmailSMTP
    )
    
    $Count = 0

    DO {
    
        $Error.Clear()


        try
        {            
            Send-MailMessage -From $EmailFrom -To $EmailTo -bcc $EmailBCC -Subject $Subject -Body $EmailBody -BodyAsHtml -SmtpServer $EmailSMTP -ErrorAction Stop -Encoding $OutputEncoding
            $success = $true
        }
    
        catch
        {
            $count++        
            Write-warning "$Error : Next attempt in 5 seconds. The email function has failed $count times so far"            
            Start-sleep -Seconds 5
        }    
    
    } # DO

    Until ($count -eq 5 -or $success)

    IF(-not($success)) {

            Write-warning "Threshold of $EmailRetryCount hit. Email function will now stop"
            
    }

} #Email Function



###

function Select-ExecMode
{
     param (
           [string]$Title = 'Repair NTFS permissions script'
     )
     cls
     Write-Host "================ $Title ================"
     Write-host "`r"
     Write-Host "1: Press '1' Single"
     Write-host "`r"
     Write-Host "2: Press '2' Batch"
     Write-host "`r"
     Write-Host "Q: Press 'Q' to quit"
}

### END FUNCTIONS

$OutArray = @()

IF (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {

    write-warning "Powershell was not started as an elevated session, exiting"
    EXIT

}

IF ($Env:UserName -notin (Get-ADGroup GL-SEC-XenDesktop-Administrators | Get-ADGroupMember | Select-object -ExpandProperty SAMAccountName)) {

    write-warning "User account $($:Env:username) is not permissioned in the GL-SEC-XenDesktop-Administrators group, the script will now exit"
    Write-warning "Please contact a member of the above group to run the script, else, permissions on the remote filer will not be set correctly"
    EXIT
}

IF (-not(Get-Command -name Get-ADForest -ErrorAction SilentlyContinue)) {

    write-warning "Required AD powershell commands not present. Please install via the below command in an admin prompt on your Computer"
    write-host '"Add-WindowsCapability –online –Name “Rsat.ActiveDirectory.DS-LDS.Tools~~~~0.0.1.0”' -ForegroundColor Cyan
    write-warning "The Script will now exit"
    EXIT
}

DO
{
     Select-ExecMode
     write-host "`r"
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                cls                
                $ExecMode = "Single"
           }
           
           '2' {
                cls                
                $ExecMode = "Batch"                
           }          
           
           'q' {
                write-warning "Script will exit"
                EXIT
           }
     }

     "user migration mode is $ExecMode"
     write-host "`r"
}

until ($input -ne $null)

###

DO
{
     Select-OpMode
     write-host "`r"
     $input = Read-Host "Please make a selection"
     switch ($input)
     {
           '1' {
                cls                
                $OpMode = "Report"
           }
           
           '2' {
                cls                
                $OpMode = "Fix"                
           }          
           
           'q' {
                write-warning "Script will exit"
                EXIT
           }
     }

     "Script operation mode is $OpMode"
     write-host "`r"
}

until ($input -ne $null)


###

IF (Get-variable User -ErrorAction SilentlyContinue) {Remove-variable User}
IF (Get-variable Users -ErrorAction SilentlyContinue) {Remove-variable Users}

#SingleMode

IF ($ExecMode -eq "Single") {

    $UserShort = Read-Host -Prompt "Enter the shortname for the user to be migrated"
    $UsersCount = "1"

}

Else {

    write-host "Importing users from users variable" -ForegroundColor Cyan
    $Users = GCI $FilerPath  | Select-Object -ExpandProperty Name
    $UsersCount = $Users | measure | Select-object -ExpandProperty Count

    IF ($Users | Where {$_.DataCopy -eq ""}) {

        write-warning "The DataCopy value needs to be set to Yes/No on all entries within the add.csv file"
        write-warning "Please open/edit the add.csv file and answer YES/NO for all rows"
        EXIT

    }

}

IF ((-Not($Users)) -and ($UserShort)) {

    $Users = $UserShort

}

IF ((-Not($Users)) -and (-Not($User))) {

    Write-warning "Users variable not populated, script will exit in 10 seconds"
    start-sleep -Seconds 10
    EXIT

}

### Start of script run
$ScriptStart = Get-Date

$ScriptUser = Get-ADuser -Identity $Env:Username | Select-Object -ExpandProperty Name

$UsersTotal = $Users | Measure | Select-Object -ExpandProperty Count
$UsersLeft = $UsersTotal

### Start of for loop against $User(s)

ForEach ($i in $Users) {

    IF ($ExecMode -eq "Batch") {

        $UserShort = $i.split(".")[0]
        $UserFull = $i

    }

    Else {
    
        $UserShort = $i

    }   
        
    write-host "`r`n"
    Write-Host "Checking $UserShort now" -ForegroundColor yellow    
    write-host  "$UsersLeft remaining to process.." -ForegroundColor Yellow

    $aa = Check-ADUser -ADUser $UserShort -ADList $AllDomains

    $userDomainFull = $aa.VDIuserDomain  
    
    IF ($userDomainFull -ne "AD User doesn't exist") {

        $UserDomainShort = $userDomainFull.Split(".")[1]
        $UserHomeFolder = $aa.UserHomeDrv
        $UserSite = $aa.UserSite
        $UserEmail = $aa.UserEmail
        $UserFullName = $aa.UserFullName
        
        ### Add home folder directory for users where it's not set

        write-host "Found $userShort on $UserDomainShort" -ForegroundColor Green

        write-host "Reading NTFS rights for $userShort"                
                
        # Get existing permissions

        IF (test-path "$FilerPath\$UserShort.$UserDomainShort.v2") {

            $ACLPermissions = Get-Acl "$FilerPath\$UserShort.$UserDomainShort.v2"

        }

        Else {

            $ACLPermissions = Get-Acl "$FilerPath\$UserShort.$UserDomainShort"

        }        
        
        $UserFolderName = $ACLPermissions.PSChildName.Split(".")[0]
                
        $ACLNewRuleFolder = New-Object system.security.accesscontrol.filesystemaccessrule($userShort,"FullControl","ContainerInherit, ObjectInherit","None", "Allow")

        IF ((($ACLPermissions).Access | Where {$_.IdentityReference -eq "$UserDomainShort\$UserShort"}).FileSystemRights -eq "FullControl") {

            write-host "$UserShort has full rights to their folder" -ForegroundColor Green
            $NTFSFixReq = "No"
        
        }

        Else {

            write-warning "$UserShort does NOT have full control rights to their folder"
            $NTFSFixReq = "Yes"

            IF ($OpMode -eq "Fix") {

                Write-Warning "Adding $UserShort to $FilerPath\$userShort.$UserDomainShort" 

                $ACLPermissions.SetAccessRule($ACLNewRuleFolder)        
                write-host "Apply updated permissions to main $User folder" -ForegroundColor Cyan
	            Set-Acl "$FilerPath\$userShort.$UserDomainShort" $ACLPermissions
                $NTFSFixRan = "Yes"

            }

        }        
                
    } #AD user exists

    Else {

            write-warning "User doesn't exist, they will be skipped"            
            $UserDomainFull = "N/A"
            $UserDomainShort = "N/A"
            $UserHomeFolder = "N/A"
            $UserSite = "N/A"
            $UserFullName = "N/A"
            $NTFSFixReq = "N/A"
            $NTFSFixRan = "N/A"
        }        

    $outarray += New-Object PSObject -Property @{
    User = $UserShort    
    UserDomainFull = $userDomainFull
    UserDomainShort = $UserDomainShort
    UserHomeFolder = $UserHomeFolder    
    UserFullName  = $UserFullName
    NTFSFixReq = $NTFSFixReq
    NTFSFixRan = $NTFSFixRan    
    } #OutArray

    $UsersLeft --

} #ForEach Users

$outarray | Select User, NTFSFixReq, NTFSFixRan, UserDomainFull, UserDomainShort, UserHomeFolder, UserFullNane  | Out-GridView

write-warning "TEMP EXIT"
EXIT

$OutArray | Export-CSV -NoTypeInformation -Path "$ScriptLogPath\Migrate-Win7VDIUserData-$LogTimeStamp.csv"

$EmailBCC = $OutArray.UserEmail

## Email body to user
$Pre1 = ""
$Post = ""
$Pre1 = "<H2>Bienvenue ! / Welcome !</H2>"
$Post += "<H5>- Vous avez été migré vers la plateforme VDI Windows 10 $Win10VDIPlatform </H5>"
$Post += "<H5>- Vous pouvez accéder à votre nouvelle machine virtuelle Windows 10 sur votre ordinateur ou thin client (client léger) - Win 10</H5>"
$Post += "<H5>- Si vous êtes présentement connecté dans Win 7 VDI, vous devez fermer votre session et utiliser le nouveau Win 10 VDI</H5>"
$Post += "<H5>- Où trouvé et applicable, les données de votre Win 7 VDI ont été migrées le $($LogTimeStamp): incluant le Bureau, les favoris, et les téléchargements</H5>"

$Post += "<H5>--------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------</H5>"

$Post += "<H5>- You've been migrated to the Windows 10 $Win10VDIPlatform VDI platform</H5>"
$Post += "<H5>- If you're already logged into your  Win 7 session, you should log off and access your new Win 10 VDI</H5>"
$Post += "<H5>- Where applicable, Your existing Win 7 VDI user data was migrated over on $($LogTimeStamp): Desktop, favorites, downloads</H5>"
$Body1 = ConvertTo-HTML -Head $Head -PreContent $Pre1 -PostContent $Post -As Table | Out-String

## Remove empty table created on preceeding line
$Body1 = $Body1 -replace '<table>',""
# $TSBody | Out-String

$Subject = "Bienvenue a / Welcome to Windows 10 VDI"

Send-ReportEmail -EmailFrom $EmailFrom -EmailTo $EmailTo -EmailBCC $EmailBCC -Subject $Subject -EmailBody $Body1 -EmailSMTP $EmailSMTP

write-host "Sending email to CSI / Citrix team"

### Email to CSI / CTX team
$Pre1 = "<H2>Win 7 VDI > Win 10 $Win10VDIPlatform VDI migration script report</H2>"
$Pre1 += "<H5>The script was run by $ScriptUser ($Env:username) against the below $UsersCount user(s):</H5>"
$Pre1 += "<H5>Information on the Win 7 VDI > Win 10 VDI user migration process and script is available $UserMigDocLNK</H5>"
$UserListHTML = $Outarray | Select UserFullname, @{E={$_.User};Name="User Name"}, UserDomainFull, UserEmail, UserSite, UserHomeFolder, Win10VDIADGrp, Computer
$Body2 += $UserListHTML | ConvertTo-HTML -Head $Head -PreContent $Pre1 -As Table | Out-String

## Remove empty table created on preceeding line
#$Body2 = $Body2 -replace '<table>',""

$Subject = "Win 7 VDI > Win 10 VDI migration script ran on $ShortDate"

Send-ReportEmail -EmailFrom $EmailFrom -EmailTo $EmailToCTXAdmin -EmailBCC $EmailToCTXAdmin -Subject $Subject -EmailBody $Body2 -EmailSMTP $EmailSMTP

$ScriptEnd = Get-Date 
$ScriptTotalTime = $ScriptEnd -$ScriptStart
$Hours = $ScriptTotalTime.Hours
$Mins = $ScriptTotalTime.Minutes
$Seconds = $ScriptTotalTime.Seconds

add-content -Value "Script finished in $hours hours, $mins minutes, $seconds seconds" -Path $ScriptLogTXT

write-host "Script completed! @ $ScriptEnd ! Total run time was $ScriptTotalTime" -ForegroundColor Cyan

