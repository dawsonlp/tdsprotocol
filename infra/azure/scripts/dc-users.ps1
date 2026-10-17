# The domain controller, step 2, after its restart: DNS for the outside world, the test user, and SQL Server's
# Kerberos service names (registered on the SQL VM's computer account, which its virtual service account uses).
param([string]$TestUserPassword, [string]$Domain)
$ErrorActionPreference = "Stop"
Import-Module ActiveDirectory
if (-not (Get-DnsServerForwarder).IPAddress) { Add-DnsServerForwarder -IPAddress 168.63.129.16 }  # Azure's resolver
$upn = "tdsuser@$Domain"
if (-not (Get-ADUser -Filter "SamAccountName -eq 'tdsuser'")) {
    New-ADUser -Name tdsuser -SamAccountName tdsuser -UserPrincipalName $upn -Enabled $true -PasswordNeverExpires $true `
        -AccountPassword (ConvertTo-SecureString $TestUserPassword -AsPlainText -Force)
}
"user $upn ready"
if (Get-ADComputer -Filter "Name -eq 'tdssql'") {
    setspn -S "MSSQLSvc/tdssql.$($Domain):1433" tdssql | Out-Null
    setspn -S "MSSQLSvc/tdssql.$Domain" tdssql | Out-Null
    "service names: " + ((setspn -L tdssql) -match "MSSQLSvc" -join ", ").Trim()
}
