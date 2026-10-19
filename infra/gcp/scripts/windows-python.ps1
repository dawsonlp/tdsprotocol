# Python runner for the bounded follow-up campaign; no credentials are inputs.
$ErrorActionPreference = 'Stop'
$python = 'C:\tds\python\python.exe'
if (-not (Test-Path $python)) {
    $installer = 'C:\tds\python-3.14.8-amd64.exe'
    Invoke-WebRequest -UseBasicParsing 'https://www.python.org/ftp/python/3.14.8/python-3.14.8-amd64.exe' -OutFile $installer -TimeoutSec 120
    $expected = '759be887b96e736a3ca886daf8d575f18fcae1a09efab6902f42d59e8999f8ef'
    if ((Get-FileHash $installer -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expected) { throw 'Python installer hash mismatch' }
    $signature = Get-AuthenticodeSignature $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Python Software Foundation') { throw 'Python installer signature rejected' }
    $process = Start-Process $installer -ArgumentList '/quiet InstallAllUsers=0 TargetDir=C:\tds\python Include_test=0 Include_launcher=0 PrependPath=0' -PassThru
    if (-not $process.WaitForExit(180000)) { $process.Kill(); throw 'Python installation timed out' }
    if ($process.ExitCode -notin @(0,3010)) { throw 'Python installation failed' }
}
& $python -m pip install --disable-pip-version-check 'pyspnego==0.12.4' 'cryptography==50.0.2' 'pytest>=8'
if ($LASTEXITCODE -ne 0) { throw 'Python runner dependencies failed' }
icacls C:\tds\python /grant 'TDS\tdsuser:(OI)(CI)RX' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Python runtime read permission failed' }
icacls C:\tds\source\clients\python /grant 'TDS\tdsuser:(OI)(CI)RX' /T /Q | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Python source read permission failed' }
& $python --version
