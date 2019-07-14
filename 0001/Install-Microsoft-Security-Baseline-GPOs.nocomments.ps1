$ErrorActionPreference = "Stop" 
$VerbosePreference = "Continue" 
Import-Module GroupPolicy 

$importADMX = $true 
$SB_Root = "C:\temp\Windows 10 Version 1903 and Windows Server Version 1903 Security Baseline" 
$Domain_FQDN = "example.com" 
$sysvolpath = "c:\Windows\SYSVOL\sysvol\" 
$GPONamePrefix = (get-date).ToShortDateString() 

$SB_GPO_Folder = $SB_Root + "\gpos" 

$SB_GPO_Names = get-childitem -path $SB_GPO_Folder | Select-object name, fullname, psparentpath, root 

if($importADMX = $true) {
   $SB_Templates = get-childitem -path ($SB_Root + "\Templates") -Filter "*.admx" | select-object fullname, directory 
   New-item -Name "en-US" -Type directory -Path "$sysvolpath$domain_fqdn\Policies\PolicyDefinitions\" -ErrorAction Ignore
   foreach ($template in $SB_Templates) {

       Copy-Item -Path $template.directory -Destination "c:\Windows\SYSVOL\sysvol\$domain_fqdn\Policies\PolicyDefinitions\en-US" -Force -ErrorAction Inquire -Verbose
        }
}

foreach ($GPO in $SB_GPO_Names) { 

   $XMLFile = $GPO.fullname + "\gpreport.xml"
   $XMLData = [XML](get-content $XMLFile)
   $GPOName = $XMLData.GPO.Name
  
  
   import-gpo -BackupId $GPO.Name -TargetName "$GPONamePrefix-$GPOName" -path $SB_GPO_Folder -CreateIfNeeded -Verbose
}
