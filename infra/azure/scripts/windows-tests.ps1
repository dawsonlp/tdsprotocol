# On the SQL VM: fetch the drivers from the runner, make a certificate in LocalMachine/My (its key not exportable), and
# run the Windows certificate store's tests against this VM's SQL Server: Python's first (it leaves its database), then
# Rust's, built here with the Visual C++ tools from windows-tools.ps1. Rust reads Python's value and checks its
# envelopes and signatures with Python's provider. Output is filtered: run-command keeps only the last few KB.
param([string]$SqlPassword, [string]$Source, [string]$Domain)
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
"certificate $($cert.Thumbprint) in LocalMachine/My (key not exportable)"
$env:TDS_CERT_THUMBPRINT = $cert.Thumbprint
$env:TDS_SQL_PASSWORD = $SqlPassword
Set-Location C:\tds\clients\python
$out = & C:\uv\uv.exe run -q --extra encryption pytest -q -p no:cacheprovider tests/test_certstore_windows.py 2>&1 | Out-String
"PYTHON: $($out.Trim())"
if ($out -notmatch " passed") { exit 1 }

Set-Location C:\tds\clients\rust
$env:TDS_CERTSTORE_TEST_KEY_PATH = "LocalMachine/My/$($cert.Thumbprint)"
$env:TDS_CERTSTORE_TEST_PYTHON = "C:\tds\clients\python\.venv\Scripts\python.exe"
$env:TDS_SQL_HOST = "tdssql.$Domain"
$env:TDS_SQL_CA = "C:\tds-ca.pem"
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
$log = "C:\tds-rust-tests.log"
cmd /c "call `"$vcvars`" >nul && `"$cargo`" test --locked --features certificate-store --test certstore_native --test certstore_live -- --ignored --nocapture > $log 2>&1"
$code = $LASTEXITCODE
Select-String -Path $log -Pattern "test result|CERTSTORE|panicked|FAILED|^error" | ForEach-Object { "RUST: $($_.Line)" }
exit $code
