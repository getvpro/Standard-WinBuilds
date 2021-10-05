<#
.FUNCTIONALITY
Sets fr-CA as primary display language for Win 10 and logs user out, but keeps en-US as second

.SYNOPSIS
Sets fr-CA as primary display language for Win 10 and logs user out, but keeps en-US as second

.NOTES
Change log

March 16, 2021
-Initial version

.DESCRIPTION
Author owen.reynolds@procontact.ca & jonathan.pitre@procontact.ca

.EXAMPLE
./Set-FrenchLang.ps1

.NOTES
.Link
N/A

#>

Add-Type -AssemblyName System.Windows.Forms

#Button Legend
#                  OK 0
#            OKCancel 1
#    AbortRetryIgnore 2
#         YesNoCancel 3
#               YesNo 4
#         RetryCancel 5

#Icon legend
#                None 0
#                Hand 16
#               Error 16
#                Stop 16
#            Question 32
#         Exclamation 48
#             Warning 48
#            Asterisk 64
#         Information 64

#$language = "ENGLISH"
$language = "FRANCAIS"
$messageBoxTitle = "Set Language"
$UserResponse = [System.Windows.Forms.MessageBox]::Show("Voulez vous changer la langue en $language ?",$messageBoxTitle , 4, 32)

If ($UserResponse -eq "YES" ) {
    
    #Set-Culture en-US
    #Set-WinUILanguageOverride en-US
    Set-WinUserLanguageList -LanguageList fr-CA, en-US -Force	
    Set-WinSystemLocale -SystemLocale fr-FR
    # Set Geo Location to Canada
    Set-WinHomeLocation -GeoId 39
    
    #Sets primary editing language to En-US
    #https://docs.microsoft.com/en-us/deployoffice/office2016/customize-language-setup-and-settings-for-office-2016
	
function Change-Language {            
    param ($LanguageFR)            
    Set-ItemProperty 'HKCU:\Control Panel\Desktop' -Name "PreferredUILanguages" -Value $LanguageFR            
}                      
Change-Language -languageFR 'fr-FR'

    New-ItemProperty -Path "HKCU:\Software\Microsoft\office\16.0\common\languageresources" -Name "preferrededitinglanguage" -Value "fr-FR"  -PropertyType "String" -Force

    # Set 7-zip to English
    IF (-not(test-path "HKCU:\Software\7-Zip")) {
        New-Item -Path "HKCU:\Software\7-Zip" -Force
    }   
    New-ItemProperty -Path "HKCU:\Software\7-Zip" -Name "Lang" -Value "fr" -PropertyType "String" -Force
	
    # Set SnagIt 2020 to English
    IF (-not(test-path "HKCU:\Software\TechSmith\SnagIt\20")) {
        New-Item -Path "HKCU:\Software\TechSmith\SnagIt\20" -Force
    }   

    New-ItemProperty -Path "HKCU:\Software\TechSmith\SnagIt\20" -Name "ApplicationLanguage" -Value "FRA"  -PropertyType "String" -Force
    New-ItemProperty -Path "HKCU:\Software\TechSmith\SnagIt\20" -Name "DictionaryName" -Value "fr" -PropertyType "String" -Force
	
    # Set Adobe Acrobat Reader DC spelling language order
    
    IF (-not(test-path "HKCU:\Software\Adobe\Acrobat Reader\DC\Spelling\cDictionaryOrderID")) {
        New-Item -Path "HKCU:\Software\Adobe\Acrobat Reader\DC\Spelling\cDictionaryOrderID" -Force
    }      
    New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\DC\Spelling\cDictionaryOrderID" -Name "i0" -Value "14"  -PropertyType "DWORD" -Force # French (Canada)
    New-ItemProperty -Path "HKCU:\Software\Adobe\Acrobat Reader\DC\Spelling\cDictionaryOrderID" -Name "i1" -Value "2"  -PropertyType "DWORD" -Force # English (US)	
    # Set Notepad++ to English
    # Set Consul-PC to English
    # Set Travelport Smartpoint to English
    # $env:AppData\Travelport\Travelport.Smartpoint\user.config
    # en or fr-CA

    [System.Windows.Forms.MessageBox]::Show("Vous allez etre deconnecté dans 10 secondes, à la prochaine ouverture de session, votre session sera en $language.", $messageBoxTitle, 0, 64)
    
    Start-Sleep -s 10
    Logoff
} 

Else { 
    Write-Host -Object "Script will now exit"
    Exit
} 
