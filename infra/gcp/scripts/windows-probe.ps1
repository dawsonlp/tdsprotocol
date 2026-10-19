# Run under a real domain-user password logon, not the SSH public-key token.
# Protected controller input carries the task credential only over SSH stdin.
$ErrorActionPreference = 'Stop'
$p = [Console]::In.ReadToEnd() | ConvertFrom-Json
$root = 'C:\tds-run'
New-Item -ItemType Directory -Force $root | Out-Null
icacls $root /inheritance:r /grant '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' 'TDS\tdsuser:(OI)(CI)M' | Out-Null
Copy-Item C:\tds\ca.pem "$root\ca.pem" -Force
if ($p.client -eq 'rust') {
    Copy-Item C:\tds\source\clients\rust\target\debug\examples\login_probe.exe "$root\login_probe.exe" -Force
}
if ($p.client -eq 'python') {
    Copy-Item C:\tds\python-probe.py "$root\python-probe.py" -Force
}
if ($p.config.local_key_ae) {
    New-Item -ItemType Directory -Force "$root\keys" | Out-Null
    Copy-Item C:\tds\source\clients\rust\tests\fixtures\encryption\master.pem "$root\keys\master.pem" -Force
    $p.config | Add-Member -NotePropertyName ae_key_dir -NotePropertyValue "$root\keys" -Force
}
$p.config.ca_file = "$root\ca.pem"
if ($p.config.progress) { $p.config | Add-Member -NotePropertyName progress_file -NotePropertyValue "$root\progress.jsonl" -Force }
$p.config | ConvertTo-Json -Depth 8 | Set-Content "$root\config.json" -Encoding UTF8
$script = @'
$ErrorActionPreference='Stop'
try {
    $configuration=Get-Content C:\tds-run\config.json -Raw | ConvertFrom-Json
    if (Test-Path C:\tds-run\use-rust) {
        Get-Content C:\tds-run\config.json -Raw | & C:\tds-run\login_probe.exe 2>C:\tds-run\stderr.txt | Set-Content C:\tds-run\stdout.txt -Encoding UTF8
        $code=$LASTEXITCODE
    } elseif (Test-Path C:\tds-run\use-python) {
        $env:PYTHONPATH='C:\tds\source\clients\python'
        Get-Content C:\tds-run\config.json -Raw | & C:\tds\python\python.exe C:\tds-run\python-probe.py 2>C:\tds-run\stderr.txt | Set-Content C:\tds-run\stdout.txt -Encoding UTF8
        $code=$LASTEXITCODE
    } else {
        $connection=[System.Data.SqlClient.SqlConnection]::new('Data Source=tcp:tdssql.tds.test,1433;Integrated Security=True;Encrypt=True;TrustServerCertificate=False;Initial Catalog=master')
        $connection.Open()
        try {
            $command=$connection.CreateCommand()
            $command.CommandText='SELECT SUSER_SNAME(), ORIGINAL_LOGIN(), DB_NAME(), net_transport, auth_scheme, encrypt_option, @@SPID FROM sys.dm_exec_connections WHERE session_id=@@SPID AND parent_connection_id IS NULL'
            $reader=$command.ExecuteReader()
            if (-not $reader.Read()) { throw 'Session evidence missing' }
            @{principal=$reader.GetString(0);original_login=$reader.GetString(1);database=$reader.GetString(2);transport=$reader.GetString(3);auth_scheme=$reader.GetString(4);encrypted=$reader.GetString(5);spid=$reader.GetInt16(6)} | ConvertTo-Json -Compress | Set-Content C:\tds-run\stdout.txt -Encoding UTF8
            $code=0
        } finally { $connection.Dispose() }
    }
    Set-Content C:\tds-run\exit.txt $code
} catch {
    # Exception messages are protected, never emitted to an unredacted console.
    $_ | Out-String | Set-Content C:\tds-run\stderr.txt -Encoding UTF8
    Set-Content C:\tds-run\exit.txt 1
}
'@
Set-Content "$root\run.ps1" $script -Encoding UTF8
Remove-Item "$root\exit.txt","$root\stdout.txt","$root\stderr.txt","$root\use-rust","$root\use-python","$root\progress.jsonl" -Force -ErrorAction SilentlyContinue
if ($p.client -eq 'rust') { Set-Content "$root\use-rust" '1' }
if ($p.client -eq 'python') { Set-Content "$root\use-python" '1' }
$task='TdsAuthenticationProbe'
try {
    $action=New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File C:\tds-run\run.ps1'
    $settings=New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
    Register-ScheduledTask -TaskName $task -Action $action -Settings $settings -User 'TDS\tdsuser' -Password $p.user_password -Force | Out-Null
    Start-ScheduledTask -TaskName $task
    for ($i=0;$i -lt 90 -and -not (Test-Path "$root\exit.txt");$i++) { Start-Sleep -Seconds 1 }
    if (-not (Test-Path "$root\exit.txt")) {
        $info=Get-ScheduledTaskInfo -TaskName $task
        $result=@{exit=124;stdout='';stderr='Domain-user task timed out';last_task_result=$info.LastTaskResult;progress=''}
        if (Test-Path "$root\progress.jsonl") {$result.progress=[IO.File]::ReadAllText("$root\progress.jsonl")}
        $result | ConvertTo-Json -Compress
        return
    }
    $result=@{exit=[int](Get-Content "$root\exit.txt");stdout='';stderr=''}
    if (Test-Path "$root\stdout.txt") {$result.stdout=[IO.File]::ReadAllText("$root\stdout.txt")}
    if (Test-Path "$root\stderr.txt") {$result.stderr=[IO.File]::ReadAllText("$root\stderr.txt")}
    $result | ConvertTo-Json -Compress
} finally {
    Stop-ScheduledTask -TaskName $task -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item "$root\config.json" -Force -ErrorAction SilentlyContinue
}
