# Permit only the disposable test user to run a batch task on this runner.
# Preserve existing rights; no administrator-group membership is granted.
$ErrorActionPreference='Stop'
$sid=([System.Security.Principal.NTAccount]'TDS\tdsuser').Translate([System.Security.Principal.SecurityIdentifier]).Value
$file='C:\tds\batch-rights.inf'
secedit /export /cfg $file /areas USER_RIGHTS /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not read local user rights' }
$lines=Get-Content $file
$found=$false
$lines=@($lines | ForEach-Object {
    if ($_ -match '^SeBatchLogonRight\s*=') {
        $found=$true
        if ($_ -notmatch [regex]::Escape($sid)) { $_+',*'+$sid } else { $_ }
    } else { $_ }
})
if (-not $found) {
    $lines=@($lines | ForEach-Object { $_; if ($_ -eq '[Privilege Rights]') { 'SeBatchLogonRight = *'+$sid } })
}
Set-Content $file $lines -Encoding Unicode
secedit /configure /db C:\tds\batch-rights.sdb /cfg $file /areas USER_RIGHTS /quiet | Out-Null
if ($LASTEXITCODE -ne 0) { throw 'Could not grant test-user batch logon' }
'Test-user batch logon configured'
