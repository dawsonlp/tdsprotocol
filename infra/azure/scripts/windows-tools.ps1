$ErrorActionPreference = 'Stop'
$root = 'C:\tds'
New-Item -ItemType Directory -Force $root | Out-Null
$installer = "$root\vs_BuildTools.exe"
if (-not (Test-Path 'C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat')) {
    if (-not (Test-Path $installer)) { Invoke-WebRequest -UseBasicParsing 'https://aka.ms/vs/17/release/vs_BuildTools.exe' -OutFile $installer }
    $signature = Get-AuthenticodeSignature $installer
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'Build tools signature invalid' }
    $run = Start-Process -Wait -PassThru $installer -ArgumentList @('--quiet','--wait','--norestart','--nocache',
        '--installPath','"C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools"',
        '--add','Microsoft.VisualStudio.Workload.VCTools','--add','Microsoft.VisualStudio.Component.VC.CMake.Project','--includeRecommended')
    if ($run.ExitCode -notin @(0,3010)) { throw 'Build tools installation failed' }
}
if (-not (Test-Path "$env:USERPROFILE\.cargo\bin\rustc.exe")) {
    $rustup = "$root\rustup-init.exe"
    Invoke-WebRequest -UseBasicParsing 'https://win.rustup.rs/x86_64' -OutFile $rustup
    $hash = Get-FileHash $rustup -Algorithm SHA256
    $run = Start-Process -Wait -PassThru $rustup -ArgumentList @('-y','--profile','minimal','--default-toolchain','1.99.1','--default-host','x86_64-pc-windows-msvc','--no-modify-path')
    if ($run.ExitCode -ne 0) { throw 'Rust installation failed' }
    "rustup installer SHA256: $($hash.Hash)"
}
& "$env:USERPROFILE\.cargo\bin\rustc.exe" --version
