# Follow-up C: a throwaway Windows account for the password-rotation tests: local (on the SQL VM) or in the domain (on
# the domain controller). Action create, set or remove. Callers use a new name each run: SQL Server on a domain member
# can resolve a reused name to the deleted account's cached SID. Never prints the password.
param([string]$Action, [string]$Scope, [string]$Name, [string]$Password)
$ErrorActionPreference = "Stop"
$name = $Name
$secure = if ($Password) { ConvertTo-SecureString $Password -AsPlainText -Force } else { $null }
if ($Scope -eq "domain") {
    Import-Module ActiveDirectory
    $user = Get-ADUser -Filter "SamAccountName -eq '$name'"
    switch ($Action) {
        "create" {
            if ($user) { Set-ADAccountPassword $name -Reset -NewPassword $secure }
            else { New-ADUser -Name $name -SamAccountName $name -Enabled $true -PasswordNeverExpires $true -AccountPassword $secure }
        }
        "set" { Set-ADAccountPassword $name -Reset -NewPassword $secure }
        "remove" { if ($user) { Remove-ADUser $name -Confirm:$false } }
    }
} else {
    $user = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
    switch ($Action) {
        "create" {
            if ($user) { Set-LocalUser -Name $name -Password $secure }
            else { New-LocalUser -Name $name -Password $secure -PasswordNeverExpires | Out-Null }
        }
        "set" { Set-LocalUser -Name $name -Password $secure }
        "remove" { if ($user) { Remove-LocalUser -Name $name } }
    }
}
"$Scope account ${name}: $Action done"
