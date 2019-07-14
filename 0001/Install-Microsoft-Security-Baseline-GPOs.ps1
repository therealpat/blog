<# Requirements/Assumptions
-This script is being run on a domain controller as an administrator (my testing was with domain admin)
-The sysvol location is c:\Windows\SYSVOL\sysvol\
-Microsoft don't modify the file\folder structure of there Microsoft Security Compliance Toolkit,
in particular under the root dir, this script assumes the folder folder structure looks like this:
   \GPOs
       \{1BB77C55-578B-49B6-AE60-7D4CB8AD29AF}
       \{3D4EEBCD-E6C0-4ADC-BAD4-0B1691A6396A}
       \etc
   \Templates
       \AdmPwd.admx
       \SecGuide.admx
       \etc
-The baseline zip has been downloaded and unzipped.
-You'll read the script before you run it and ensure this won't cause some catastrophic issue in your environment :)
#>
<#Purpose
The purpose of this script is to import GPO's and ADMX templates from the Security Baseline packages that Microsoft publishes periodically:
(eg https://blogs.technet.microsoft.com/secguide/2019/04/24/security-baseline-draft-for-windows-10-v1903-and-windows-server-v1903/
https://www.microsoft.com/en-us/download/details.aspx?id=55319)

The script imports the ADMX templates from the \Templates folder into your policy definitions folder in domains sysvol (creates folders if they don't exist) and then imports all GPOs in the \gpos folder into your domain group policy objects, if an existing policy exists with the same name it will overwrite any settings in it, otherwise the policy will be created.
#>

<#Warnings / Notes !!!
**Note that if you have existing GPOs that match the name of a GPO in the Security Baseline package the act of importing will wipe all existing settings and replace with those in the package.

*** Really note! - If you do replace an existing policies settings by importing a GPO from the Baseline package that matches one or more of your existing group policies the links to OU's etc will be MAINTAINED so you'd effectively be putting the policy in effect immediately. E.g You have previously diligently imported, tested and rolled out the policy microsoft packaged called "MSFT Internet Explorer 11 - User". Next time you are rolling in the baselines they make changes to this policy which is named the same in the Security Baseline package, more restrictive and untested constraints to IE would effectively become active as soon as you run the script.

I've put a date prefix on the name of the GPO's that will be installed to reduce the likelihood someone will do this.

#>

$ErrorActionPreference = "Stop" # Haven't built any error handling in to this script so I was running this with stop set
$VerbosePreference = "Continue" # Delete this line or set to "SilentlyContinue" if you don't want verbose output
         
Import-Module GroupPolicy #We need this to do the GPO import, as this designed to run on DC we can assume its installed.

$importADMX = $true #if true import the ADMX templates into your sysvol location
$SB_Root = "C:\temp\Windows 10 Version 1903 and Windows Server Version 1903 Security Baseline" #don't put a backslash at the end of the path.
$Domain_FQDN = "example.com" #use this to construct path for policies to be installed if required.
$sysvolpath = "c:\Windows\SYSVOL\sysvol\" #well use this plus the domain FQDN to determine where the ADMX should be written to.
$GPONamePrefix = (get-date).ToShortDateString() #all GPO's imported will have this prefix


$SB_GPO_Folder = $SB_Root + "\gpos" #constructing the path to GPO's and storing in SB_GPO_Folder

$SB_GPO_Names = get-childitem -path $SB_GPO_Folder | Select-object name, fullname, psparentpath, root #getting the name of each folder in the GPO folder and storing in SB_GPO_Names


#The import admx section will only run if $importADMX variable is set to true
if($importADMX = $true) {
   $SB_Templates = get-childitem -path ($SB_Root + "\Templates") -Filter "*.admx" | select-object fullname, directory #finding all the ADMX files in the templates folder and storing in SB_Templates
   New-item -Name "en-US" -Type directory -Path "$sysvolpath$domain_fqdn\Policies\PolicyDefinitions\" -ErrorAction Ignore #Attempt to create policy definitions folder domains sysvol directory
   #loop over each template we found in the \Templates directory and copy to the domains sysvol policy definitions folder.
   foreach ($template in $SB_Templates) {

       Copy-Item -Path $template.directory -Destination "c:\Windows\SYSVOL\sysvol\$domain_fqdn\Policies\PolicyDefinitions\en-US" -Force -ErrorAction Inquire -Verbose
      
       }

}


foreach ($GPO in $SB_GPO_Names) { #loop through each folder we found in the \GPOs folder, extract the name of the GPO that Microsoft have backed up which is in the XML data in gpreport.xml and import the GPO into the domain.

   $XMLFile = $GPO.fullname + "\gpreport.xml"
   $XMLData = [XML](get-content $XMLFile)
   $GPOName = $XMLData.GPO.Name
  
  
   import-gpo -BackupId $GPO.Name -TargetName "$GPONamePrefix-$GPOName" -path $SB_GPO_Folder -CreateIfNeeded -Verbose
}

<#Credits:
These articles were excellent and helped a lot when figuring out how to create the above script.
https://johnpenford.wordpress.com/2015/02/27/import-gpos-from-one-domain-to-another-using-powershell/
https://www.systemcenterdudes.com/how-to-use-the-windows-10-security-baseline/
https://danielengberg.com/powershell-copy-a-file-to-a-directory-that-does-not-exist/
#>

<# Environment Info:
C:\Users\>systeminfo | findstr /B /C:"Host Name" /C:"OS Name" /C:"OS Version"
Host Name:                 Redacted
OS Name:                   Microsoft Windows Server 2019 Datacenter
OS Version:                10.0.17763 N/A Build 17763

PS C:\Windows\system32> $PSVersionTable

Name                           Value                                                                                                               
----                           -----                                                                                                               
PSVersion                      5.1.17763.503                                                                                                       
PSEdition                      Desktop                                                                                                             
PSCompatibleVersions           {1.0, 2.0, 3.0, 4.0...}                                                                                             
BuildVersion                   10.0.17763.503                                                                                                      
CLRVersion                     4.0.30319.42000                                                                                                     
WSManStackVersion              3.0                                                                                                                 
PSRemotingProtocolVersion      2.3                                                                                                                 
SerializationVersion           1.1.0.1                                                                                                             


PS C:\Windows\system32> Get-Module

ModuleType Version    Name                                ExportedCommands                                                                         
---------- -------    ----                                ----------------                                                                         
Manifest   1.0.1.0    ActiveDirectory                     {Add-ADCentralAccessPolicyMember, Add-ADComputerServiceAccount, Add-ADDomainControllerP...
Manifest   1.0.0.0    GroupPolicy                         {Backup-GPO, Copy-GPO, Get-GPInheritance, Get-GPO...}                                    
Script     1.0.0.0    ISE                                 {Get-IseSnippet, Import-IseSnippet, New-IseSnippet}                                      
Manifest   3.1.0.0    Microsoft.PowerShell.Management     {Add-Computer, Add-Content, Checkpoint-Computer, Clear-Content...}                       
Manifest   3.0.0.0    Microsoft.PowerShell.Security       {ConvertFrom-SecureString, ConvertTo-SecureString, Get-Acl, Get-AuthenticodeSignature...}
Manifest   3.1.0.0    Microsoft.PowerShell.Utility        {Add-Member, Add-Type, Clear-Variable, Compare-Object...}                                
Manifest   3.0.0.0    Microsoft.WSMan.Management          {Connect-WSMan, Disable-WSManCredSSP, Disconnect-WSMan, Enable-WSManCredSSP...}

#>
