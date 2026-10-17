# The SQL VM, step 1: use the domain controller for DNS, and join the domain. The VM restarts after.
param([string]$AdminPassword, [string]$Domain)
$ErrorActionPreference = "Stop"
if ((Get-WmiObject Win32_ComputerSystem).Domain -eq $Domain) { "already joined to $Domain"; exit 0 }
Get-NetAdapter | Set-DnsClientServerAddress -ServerAddresses 10.42.1.4
$credential = New-Object PSCredential ("$($Domain.Split('.')[0].ToUpper())\tdsadmin", (ConvertTo-SecureString $AdminPassword -AsPlainText -Force))
Add-Computer -DomainName $Domain -Credential $credential -Force
"joined ${Domain}: restart to finish"
