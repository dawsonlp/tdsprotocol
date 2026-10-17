# On the SQL VM: fetch the driver from the runner, install uv and Python, make a certificate in LocalMachine/My (its
# key not exportable), and run the Windows certificate store's test against this VM's SQL Server.
param([string]$SqlPassword, [string]$Source)
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"
Invoke-WebRequest "$Source/tds.zip" -OutFile C:\tds.zip
if (Test-Path C:\tds) { Remove-Item C:\tds -Recurse -Force }
Expand-Archive C:\tds.zip C:\tds
$env:UV_INSTALL_DIR = "C:\uv"
if (-not (Test-Path C:\uv\uv.exe)) { Invoke-RestMethod https://astral.sh/uv/install.ps1 | Invoke-Expression 2>&1 | Out-Null }
$cert = Get-ChildItem Cert:\LocalMachine\My | Where-Object Subject -eq "CN=tds always encrypted" | Select-Object -First 1
if (-not $cert) {
    $cert = New-SelfSignedCertificate -Subject "CN=tds always encrypted" -CertStoreLocation Cert:\LocalMachine\My `
        -KeyAlgorithm RSA -KeyLength 2048 -KeyExportPolicy NonExportable -Provider "Microsoft Software Key Storage Provider" `
        -KeyUsage KeyEncipherment, DigitalSignature
}
"certificate $($cert.Thumbprint) in LocalMachine/My (key exportable: $($cert.PrivateKey -ne $null -and $false))"
Set-Location C:\tds
$env:TDS_CERT_THUMBPRINT = $cert.Thumbprint
$env:TDS_SQL_PASSWORD = $SqlPassword
$out = & C:\uv\uv.exe run -q --extra encryption pytest -q -p no:cacheprovider tests/test_certstore_windows.py 2>&1 | Out-String
$out
if ($out -notmatch " passed") { exit 1 }
