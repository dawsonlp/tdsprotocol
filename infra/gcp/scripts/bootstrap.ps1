# Public bootstrap only. Authentication is by the ephemeral public SSH key.
$ErrorActionPreference = 'Stop'
if (-not (Get-Service sshd -ErrorAction SilentlyContinue)) {
    Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0 | Out-Null
}
if ((Get-CimInstance Win32_ComputerSystem).DomainRole -lt 4) {
    $administrator = Get-LocalUser | Where-Object { $_.SID.Value.EndsWith('-500') }
    if (-not $administrator.Enabled) {
        $random = New-Object byte[] 48
        $generator = [System.Security.Cryptography.RandomNumberGenerator]::Create()
        $generator.GetBytes($random)
        $temporary = ConvertTo-SecureString ('Boot!' + [Convert]::ToBase64String($random)) -AsPlainText -Force
        Set-LocalUser -Name $administrator.Name -Password $temporary
        $temporary.Dispose(); [Array]::Clear($random, 0, $random.Length); $generator.Dispose()
    }
    Enable-LocalUser -Name $administrator.Name
    if ($administrator.Name -ne 'Administrator') { throw 'Unexpected bootstrap administrator name' }
}
# No password is returned or used for bootstrap access. The configure step sets
# a protected campaign password before domain creation.
$keyfile = 'C:\ProgramData\ssh\administrators_authorized_keys'
New-Item -ItemType Directory -Force 'C:\ProgramData\ssh' | Out-Null
Set-Content -Path $keyfile -Value '${public_key}' -Encoding ascii
icacls $keyfile /inheritance:r /grant '*S-1-5-18:F' '*S-1-5-32-544:F' | Out-Null
Set-Service sshd -StartupType Automatic
Start-Service sshd
if (-not (Get-NetFirewallRule -Name 'tds-ssh' -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -Name 'tds-ssh' -DisplayName 'TDS private SSH' -Direction Inbound -Action Allow -Protocol TCP -LocalPort 22 -RemoteAddress 10.43.1.0/24 | Out-Null
}
$hostkey = Get-Content 'C:\ProgramData\ssh\ssh_host_ed25519_key.pub' -Raw
Invoke-RestMethod -Method Put -Headers @{'Metadata-Flavor'='Google'} -Body $hostkey `
    -Uri 'http://metadata.google.internal/computeMetadata/v1/instance/guest-attributes/tds/hostkey' | Out-Null
