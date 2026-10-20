# Follow-up G1, on the SQL VM: Rust's native signed-in Windows provider. run-command runs as SYSTEM, whose network
# identity is the machine account TDS\TDSSQL$. Uses the sources and build directory windows-tests.ps1 left.
# Observed 2026-10-20: Kerberos succeeds; Negotiate as SYSTEM to its own machine chooses NTLM (loopback), which Rust
# refuses unless allow_ntlm_fallback is set, and with it set logs in by NTLM.
$ErrorActionPreference = "Stop"
Set-Location C:\tds\clients\rust
$env:CARGO_TARGET_DIR = "C:\tds-target"
$vcvars = "C:\Program Files (x86)\Microsoft Visual Studio\2022\BuildTools\VC\Auxiliary\Build\vcvars64.bat"
$cargo = "$env:USERPROFILE\.cargo\bin\cargo.exe"
$cases = @(
    @{ label = "kerberos 7.4"; method = "kerberos"; version = "7.4"; fallback = "false" },
    @{ label = "kerberos 8.0"; method = "kerberos"; version = "8.0"; fallback = "false" },
    @{ label = "negotiate 8.0 (NTLM fallback not allowed: expect refusal)"; method = "negotiate"; version = "8.0"; fallback = "false" },
    @{ label = "negotiate 8.0 (NTLM fallback allowed)"; method = "negotiate"; version = "8.0"; fallback = "true" }
)
foreach ($case in $cases) {
    $config = '{"host":"tdssql.tds.test","server_name":"tdssql.tds.test","ca_file":"C:\\tds-ca.pem","method":"' + $case.method + '","provider":"native","tds_version":"' + $case.version + '","allow_ntlm_fallback":' + $case.fallback + '}'
    Set-Content -Path C:\tds-probe.json -Value $config -Encoding ascii
    $out = cmd /c "call `"$vcvars`" >nul && type C:\tds-probe.json | `"$cargo`" run -q --locked --features integrated-auth --example login_probe 2>&1"
    "G1 $($case.label): " + (($out | Select-Object -Last 2) -join " | ")
}
Remove-Item C:\tds-probe.json -Force
