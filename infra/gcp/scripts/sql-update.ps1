# Pin the cumulative update: SQL 2022 RTM has a known TDS 8 RPC parser bug
# (2042238, fixed in CU1). Preserve the existing VM/domain/certificates.
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
$root='C:\tds'
$expected='675E3CEDD6C7A3D0FFBE713E46E54A86A92AF7B96CA4A6BEB987AE99C79B96F5'
$setupKey='HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\Setup'
if ([version](Get-ItemProperty $setupKey).PatchLevel -ge [version]'16.0.4295.3') { 'CU27 already installed';return }
$installer="$root\SQLServer2022-KB5104824-x64.exe"
if (-not (Test-Path $installer)) {
    Invoke-WebRequest -UseBasicParsing 'https://download.microsoft.com/download/a89001cb-9c99-48d3-9f14-ded054b35fe4/SQLServer2022-KB5104824-x64.exe' -OutFile "$installer.partial" -TimeoutSec 600
    Move-Item "$installer.partial" $installer
}
if ((Get-FileHash $installer -Algorithm SHA256).Hash -ne $expected) { throw 'CU27 SHA256 mismatch' }
$signature=Get-AuthenticodeSignature $installer
if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'Microsoft Corporation') { throw 'CU27 signature invalid' }
$task='TdsSqlUpdate'
try {
    $action=New-ScheduledTaskAction -Execute $installer -Argument '/quiet /IAcceptSQLServerLicenseTerms /Action=Patch /AllInstances'
    $principal=New-ScheduledTaskPrincipal -UserId SYSTEM -LogonType ServiceAccount -RunLevel Highest
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 25)
    Register-ScheduledTask -TaskName $task -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    $started=Get-Date
    Start-ScheduledTask -TaskName $task
    do {
        Start-Sleep -Seconds 5
        $info=Get-ScheduledTaskInfo -TaskName $task
        $state=(Get-ScheduledTask -TaskName $task).State
        if ((Get-Date) -gt $started.AddMinutes(25)) { throw 'CU27 update deadline exceeded' }
    } while ($info.LastRunTime -lt $started.AddSeconds(-1) -or $state -eq 'Running')
    if ($info.LastTaskResult -notin @(0,3010)) { throw 'CU27 installation failed; inspect protected setup log' }
    if ([version](Get-ItemProperty $setupKey).PatchLevel -lt [version]'16.0.4295.3') { throw 'CU27 version did not advance' }
    'CU27 installed: 16.0.4295.3'
    if ($info.LastTaskResult -eq 3010) { 'REBOOT' }
} finally {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
}
