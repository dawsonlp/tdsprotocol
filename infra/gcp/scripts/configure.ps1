# Secrets arrive over authenticated SSH stdin, never argv, metadata or Terraform.
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$secure = ConvertTo-SecureString $p.admin_password -AsPlainText -Force
$credential = [pscredential]::new('TDS\Administrator', $secure)
$root = 'C:\tds'
New-Item -ItemType Directory -Force $root | Out-Null
icacls $root /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null

switch ($p.step) {
    'dc' {
        if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) { 'DC ready'; break }
        Set-LocalUser -Name Administrator -Password $secure
        if ($env:COMPUTERNAME -ne 'tdsdc') {
            Rename-Computer -NewName tdsdc -Force
            'REBOOT'; break
        }
        Install-WindowsFeature AD-Domain-Services -IncludeManagementTools | Out-Null
        Import-Module ADDSDeployment
        Install-ADDSForest -DomainName 'tds.test' -DomainNetbiosName TDS -InstallDns `
            -SafeModeAdministratorPassword $secure -NoRebootOnCompletion -Force | Out-Null
        'REBOOT'
    }
    'users' {
        Import-Module ActiveDirectory
        if (-not (Get-ADUser -Filter "SamAccountName -eq 'tdsuser'")) {
            New-ADUser -Name tdsuser -SamAccountName tdsuser -UserPrincipalName 'tdsuser@tds.test' `
                -Enabled $true -PasswordNeverExpires $true -AccountPassword (ConvertTo-SecureString $p.user_password -AsPlainText -Force)
        }
        # Preserve GCP's Windows DNS path for non-domain names. AD hosts the test
        # zone; clients query the DC. Resolve activation/download endpoints too.
        $gateway = (Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1).NextHop
        Set-DnsServerForwarder -IPAddress $gateway | Out-Null
        Set-DnsClientServerAddress -InterfaceAlias 'Ethernet*' -ServerAddresses '127.0.0.1'
        if (Get-ADComputer -Filter "Name -eq 'tdssql'") {
            & setspn -S 'MSSQLSvc/tdssql.tds.test:1433' 'TDSSQL' | Out-Null
            if ($LASTEXITCODE -ne 0) { throw 'SPN registration failed' }
        }
        'Users/DNS/SPN ready'
    }
    'join' {
        Set-LocalUser -Name Administrator -Password $secure
        $system = Get-CimInstance Win32_ComputerSystem
        if ($system.PartOfDomain -and $system.Domain -eq 'tds.test') { 'Domain ready'; break }
        Set-DnsClientServerAddress -InterfaceAlias 'Ethernet*' -ServerAddresses '10.43.1.4'
        Add-Computer -DomainName 'tds.test' -Credential $credential -NewName $p.computer_name -Force
        'REBOOT'
    }
    'install' {
        if (Get-Service MSSQLSERVER -ErrorAction SilentlyContinue) { 'SQL installed'; break }
        # The old Microsoft SSEI 2022 downloader refuses its own current
        # minimum-version manifest. Fetch the official Developer media directly
        # and verify the mounted Microsoft setup signature before execution.
        $media = "$root\SQLServer2022-x64-ENU-Dev.iso"
        if (-not (Test-Path $media)) {
            Invoke-WebRequest -UseBasicParsing -Uri 'https://download.microsoft.com/download/3/8/d/38de7036-2433-4207-8eae-06e247e17b25/SQLServer2022-x64-ENU-Dev.iso' -OutFile "$media.partial" -TimeoutSec 600
            Move-Item "$media.partial" $media
        }
        $iso = Get-ChildItem $root -Filter '*.iso' | Select-Object -First 1
        if (-not $iso) { throw 'SQL media missing' }
        $volume = Mount-DiskImage -ImagePath $iso.FullName -PassThru | Get-Volume
        $setup = "$($volume.DriveLetter):\setup.exe"
        $signature = Get-AuthenticodeSignature $setup
        if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'Invalid SQL setup signature' }
        $ini = "$root\sql-install.ini"
        # Developer PID from Microsoft's public edition-selection documentation;
        # this is not a purchased production SQL Server license.
        $content = @"
[OPTIONS]
ACTION="Install"
QUIET="True"
IACCEPTSQLSERVERLICENSETERMS="True"
FEATURES="SQLENGINE"
INSTANCENAME="MSSQLSERVER"
PID="22222-00000-00000-00000-00000"
SQLSVCACCOUNT="NT Service\MSSQLSERVER"
SQLSYSADMINACCOUNTS="TDS\Administrator"
SECURITYMODE="SQL"
SAPWD="$($p.sql_password)"
TCPENABLED="1"
NPENABLED="0"
UpdateEnabled="False"
SUPPRESSPRIVACYSTATEMENTNOTICE="True"
"@
        try {
            Set-Content $ini -Value $content -Encoding Unicode
            # Public-key SSH has no password-backed DPAPI user logon. SQL setup
            # serializes secrets with DPAPI and fails under that token. Use a
            # bounded SYSTEM task; the INI stays ACL-restricted to SYSTEM/Admin.
            $task = 'TdsSqlInstall'
            $action = New-ScheduledTaskAction -Execute $setup -Argument "/ConfigurationFile=$ini"
            $principal = New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
            $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 25)
            Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -Force | Out-Null
            $started = Get-Date
            Start-ScheduledTask -TaskName $task
            do {
                Start-Sleep -Seconds 5
                $info = Get-ScheduledTaskInfo -TaskName $task
                $state = (Get-ScheduledTask -TaskName $task).State
                if ((Get-Date) -gt $started.AddMinutes(25)) { throw 'SQL install deadline exceeded' }
            } while ($info.LastRunTime -lt $started.AddSeconds(-1) -or $state -eq 'Running')
            $installCode = $info.LastTaskResult
            if ($installCode -notin @(0,3010)) { throw 'SQL installation failed; inspect protected guest logs' }
        } finally {
            Stop-ScheduledTask -TaskName 'TdsSqlInstall' -ErrorAction SilentlyContinue
            Unregister-ScheduledTask -TaskName 'TdsSqlInstall' -Confirm:$false -ErrorAction SilentlyContinue
            Remove-Item $ini -Force -ErrorAction SilentlyContinue
            Dismount-DiskImage -ImagePath $iso.FullName | Out-Null
        }
        if ($installCode -eq 3010) { 'REBOOT' } else { 'SQL installed' }
    }
    'patch' { & "$root\sql-update.ps1" }
    'sql' {
        $instance = 'HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER'
        $network = "$instance\MSSQLServer\SuperSocketNetLib"
        Set-ItemProperty "$network\Tcp" -Name Enabled -Value 1
        Set-ItemProperty "$network\Tcp\IPAll" -Name TcpPort -Value '1433'
        Set-ItemProperty "$network\Tcp\IPAll" -Name TcpDynamicPorts -Value ''
        $cert = Import-PfxCertificate -FilePath "$root\sql.pfx" -CertStoreLocation Cert:\LocalMachine\My `
            -Password (ConvertTo-SecureString $p.pfx_password -AsPlainText -Force)
        # RSA CSP key grants the SQL virtual account access without exporting it.
        $rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
        if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
            $keypath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($rsa.CspKeyContainerInfo.UniqueKeyContainerName)"
        } else {
            $keypath = "$env:ProgramData\Microsoft\Crypto\Keys\$($rsa.Key.UniqueName)"
        }
        icacls $keypath /grant 'NT SERVICE\MSSQLSERVER:R' | Out-Null
        Set-ItemProperty $network -Name Certificate -Value $cert.Thumbprint.ToLower()
        Set-ItemProperty $network -Name ForceEncryption -Value 1
        Remove-Item "$root\sql.pfx" -Force
        foreach ($entry in @(@{n='tds-sql';p='TCP';port=1433},@{n='tds-browser';p='UDP';port=1434})) {
            if (-not (Get-NetFirewallRule -Name $entry.n -ErrorAction SilentlyContinue)) {
                New-NetFirewallRule -Name $entry.n -DisplayName $entry.n -Direction Inbound -Action Allow -Protocol $entry.p -LocalPort $entry.port | Out-Null
            }
        }
        Set-Service SQLBrowser -StartupType Automatic
        Start-Service SQLBrowser
        Restart-Service MSSQLSERVER -Force
        # Use a SQL credential over verified TCP to avoid SSH logon/delegation
        # behavior being mistaken for the independent native-login witness.
        $connection = [System.Data.SqlClient.SqlConnection]::new()
        $builder = [System.Data.SqlClient.SqlConnectionStringBuilder]::new()
        $builder['Data Source'] = 'tcp:tdssql.tds.test,1433'
        $builder['User ID'] = 'sa'; $builder['Password'] = $p.sql_password
        $builder['Encrypt'] = $true; $builder['TrustServerCertificate'] = $false
        Import-Certificate -FilePath "$root\ca.pem" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
        $connection.ConnectionString = $builder.ConnectionString
        $connection.Open()
        try {
            $command = $connection.CreateCommand()
            $command.CommandText = @"
IF SUSER_ID(N'TDS\tdsuser') IS NULL CREATE LOGIN [TDS\tdsuser] FROM WINDOWS;
ALTER SERVER ROLE sysadmin ADD MEMBER [TDS\tdsuser];
IF SUSER_ID(N'TDSSQL\Administrator') IS NULL CREATE LOGIN [TDSSQL\Administrator] FROM WINDOWS;
ALTER SERVER ROLE sysadmin ADD MEMBER [TDSSQL\Administrator];
SELECT SERVERPROPERTY('Edition');
"@
            $edition = $command.ExecuteScalar()
            if ($edition -notmatch 'Developer') { throw 'Expected Developer edition' }
            "SQL ready: $edition"
        } finally { $connection.Dispose() }
    }
    default { throw 'Unknown configuration step' }
}
