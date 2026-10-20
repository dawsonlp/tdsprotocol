# The SQL VM, step 3: SQL Server's TLS certificate, signed by the campaign's disposable CA (configure.py certs), so
# clients that verify TLS can connect. The CA is trusted on this machine too, for local clients.
param([string]$Pfx, [string]$PfxPassword, [string]$Ca)
$ErrorActionPreference = "Stop"
$path = "C:\tds-sql.pfx"
[IO.File]::WriteAllBytes($path, [Convert]::FromBase64String($Pfx))
$cert = Import-PfxCertificate -FilePath $path -CertStoreLocation Cert:\LocalMachine\My `
    -Password (ConvertTo-SecureString $PfxPassword -AsPlainText -Force)
Remove-Item $path -Force
[IO.File]::WriteAllBytes("C:\tds-ca.pem", [Convert]::FromBase64String($Ca))
Import-Certificate -FilePath "C:\tds-ca.pem" -CertStoreLocation Cert:\LocalMachine\Root | Out-Null
# SQL Server's service account reads the private key; the key is not exported.
$rsa = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($cert)
if ($rsa -is [System.Security.Cryptography.RSACryptoServiceProvider]) {
    $keypath = "$env:ProgramData\Microsoft\Crypto\RSA\MachineKeys\$($rsa.CspKeyContainerInfo.UniqueKeyContainerName)"
} else {
    $keypath = "$env:ProgramData\Microsoft\Crypto\Keys\$($rsa.Key.UniqueName)"
}
icacls $keypath /grant 'NT SERVICE\MSSQLSERVER:R' | Out-Null
$network = "HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib"
Set-ItemProperty $network -Name Certificate -Value $cert.Thumbprint.ToLower()
Set-ItemProperty $network -Name ForceEncryption -Value 1
net stop MSSQLSERVER /y 2>&1 | Out-Null
net start MSSQLSERVER 2>&1 | Out-Null
net start SQLSERVERAGENT 2>&1 | Out-Null
"SQL Server uses certificate $($cert.Thumbprint) from the disposable CA; encryption forced"
