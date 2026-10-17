# The domain controller, step 1: install Active Directory and make a new forest. The VM restarts after.
param([string]$SafeModePassword, [string]$Domain)
$ErrorActionPreference = "Stop"
if ((Get-WmiObject Win32_ComputerSystem).PartOfDomain) { "already a domain controller for $Domain"; exit 0 }
Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
Import-Module ADDSDeployment
Install-ADDSForest -DomainName $Domain -DomainNetbiosName ($Domain.Split('.')[0].ToUpper()) -InstallDns `
    -SafeModeAdministratorPassword (ConvertTo-SecureString $SafeModePassword -AsPlainText -Force) `
    -NoRebootOnCompletion -Force | Out-Null
"forest $Domain created: restart to finish"
