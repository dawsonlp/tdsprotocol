param([Parameter(Mandatory=$true)][ValidateSet('off','allowed','required')][string]$Policy)
$ErrorActionPreference='Stop'
$key='HKLM:\SOFTWARE\Microsoft\Microsoft SQL Server\MSSQL16.MSSQLSERVER\MSSQLServer\SuperSocketNetLib'
$before=(Get-ItemProperty $key).ExtendedProtection
$value=if ($Policy -eq 'required') {2} elseif ($Policy -eq 'allowed') {1} else {0}
Set-ItemProperty $key -Name ExtendedProtection -Value $value
Restart-Service MSSQLSERVER -Force
@{before=$before;after=(Get-ItemProperty $key).ExtendedProtection;force_encryption=(Get-ItemProperty $key).ForceEncryption;service=(Get-Service MSSQLSERVER).Status.ToString()} | ConvertTo-Json -Compress
