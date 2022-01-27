<#
.FUNCTIONALITY
Used to import backed up GPOs. You will need to create a folder called c:\Admin\GPOImport on the computer you run this script from on the client domain. 

You would then extract/copy over your GPOs in the following format:

c:\Admin\GPOImport\GPO1\{LongGUIDHERE}
c:\Admin\GPOImport\GPO2\{LongGUIDHERE}
c:\Admin\GPOImport\GPO3\{LongGUIDHERE}

The script will recurse through the sub-folder to ID the correct GPO Name the GPBackup.XML file 

If a GPO exists already, then the following will be appended: Citrx_VDA_Common_(imported_1/27/2022-158PM)

This will avoid over-writing existing GPOs with the same name

.SYNOPSIS
- See above
.NOTES
Change log

Jan 27, 2022
- Initial version

#> 

if (test-path 'C:\Admin\GPO Export') {

    $GPOPath =  "C:\Admin\GPOImport"

}

Else {

    Write-Warning "GPO import folder doesn't exit, please create it and download the relevant backed up GPOs to the c:\Admin\GPOImport folder"
    EXIT

}

$ShortDate = (Get-Date).ToString('MM-dd-yyyy-ss')

$GPOToImport = GCI -Path $GPOPath | Select-Object -ExpandProperty FullName

ForEach ($i in $GPOToImport) {

    $GPOReport = (GCI $i | Where-Object {$_.PSIsContainer} | Select-Object -ExpandProperty FullName) + "\GPReport.xml"
    
    [xml]$iXml = (Get-Content $GPOReport)

    $GPOname = $($ixml.GPO.Name)

    if ($iXML) {        

        if (-not(Get-GPO -Name $GPOname -ErrorAction SilentlyContinue)) {

            Write-host "Confirmed $GPOName doesn't already exist in $Env:UserDomain" -ForegroundColor Green
            
            Write-host "Attempting to import $GPOName" -ForegroundColor Cyan
        
            Import-GPO -BackupGpoName $GPOname -TargetName $GPOname -path $i -CreateIfNeeded

        }

        Else {

            Write-Warning "$GPOName already exists in $Env:UserDomain, a new name will be created"
            
            $GPOname = $($ixml.GPO.Name)

            Write-host "Attempting to import $GPOName" -ForegroundColor Cyan
        
            Import-GPO -BackupGpoName $GPOname -TargetName ($GPOname + " (Imported_$(Get-Date))") -path $i -CreateIfNeeded

        }

    } # Create only if lines 13 / iXML variables is created    

    Else {

        Write-Warning "Error on GPO for $i"

    }    

}



