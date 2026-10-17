# The SQL VM, step 2, after its restart: SQL Server as the tests need it. Without the SQL IaaS extension no Windows
# account is sysadmin yet, so the logins are made in single-user mode, where local administrators are.
param([string]$SqlAdminPassword, [string]$Domain)
$ErrorActionPreference = "Stop"
$instance = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER"
Set-ItemProperty "$instance\MSSQLServer" -Name LoginMode -Value 2  # SQL Server logins as well as Windows ones
Set-ItemProperty "$instance\MSSQLServer\SuperSocketNetLib\Tcp" -Name Enabled -Value 1
Set-ItemProperty "$instance\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -Name TcpPort -Value "1433"
Set-ItemProperty "$instance\MSSQLServer\SuperSocketNetLib\Tcp\IPAll" -Name TcpDynamicPorts -Value ""
foreach ($rule in @(@{n="tds sql"; p="TCP"; port=1433}, @{n="tds browser"; p="UDP"; port=1434})) {
    if (-not (Get-NetFirewallRule -DisplayName $rule.n -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $rule.n -Direction Inbound -Protocol $rule.p -LocalPort $rule.port -Action Allow | Out-Null
    }
}
Set-Service SQLBrowser -StartupType Automatic
Start-Service SQLBrowser
$netbios = $Domain.Split('.')[0].ToUpper()
$sql = @"
IF SUSER_ID('tdsadmin') IS NULL CREATE LOGIN tdsadmin WITH PASSWORD = N'$($SqlAdminPassword.Replace("'", "''"))', CHECK_POLICY = OFF;
ALTER SERVER ROLE sysadmin ADD MEMBER tdsadmin;
IF SUSER_ID(N'$netbios\tdsuser') IS NULL CREATE LOGIN [$netbios\tdsuser] FROM WINDOWS;
ALTER SERVER ROLE sysadmin ADD MEMBER [$netbios\tdsuser];
IF SUSER_ID(N'TDSSQL\tdsadmin') IS NULL CREATE LOGIN [TDSSQL\tdsadmin] FROM WINDOWS;
ALTER SERVER ROLE sysadmin ADD MEMBER [TDSSQL\tdsadmin];
EXEC sp_configure 'remote admin connections', 1; RECONFIGURE;
"@
function Stop-Sql {  # SQL Server Agent depends on it: net stop /y stops both
    net stop MSSQLSERVER /y 2>&1 | Out-Null
    for ($i = 0; $i -lt 30 -and (Get-Service MSSQLSERVER).Status -ne "Stopped"; $i++) { Start-Sleep 2 }
    if ((Get-Service MSSQLSERVER).Status -ne "Stopped") { throw "SQL Server didn't stop" }
}
Stop-Sql
net start MSSQLSERVER /mSQLCMD 2>&1 | Out-Null  # single-user: local administrators connect as sysadmin
Start-Sleep 10
sqlcmd -S . -E -b -Q $sql | Out-Null
if ($LASTEXITCODE -ne 0) { throw "creating the logins failed ($LASTEXITCODE)" }
Stop-Sql
net start MSSQLSERVER 2>&1 | Out-Null
net start SQLSERVERAGENT 2>&1 | Out-Null
"SQL Server ready: SQL logins on, TCP 1433, the Browser running, logins for tdsadmin, $netbios\tdsuser and TDSSQL\tdsadmin"
