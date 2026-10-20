# Rust Azure integration: code-complete checkpoint (iteration 12)

**Where this sits:** closes iterations 11–12 of the [integration plan](rust-azure-integration-plan.md)
before the live Azure campaign. It maps every [parity scenario](rust-azure-parity-scenarios.md)
to tests, and records the owner-agreed exceptions.

**After reading this you can** find the test behind each scenario, see what is
left for the live campaign, and see which gaps are queued as follow-on work
rather than forgotten.

## The owner's decision, 2026-10-20

A local review found the branch's tests green but the plan's code-complete bar
unmet: no cross-feature tests, no credential inventory, and no checkpoint record.
The owner chose **Option A**:

- Before provisioning, add the cross-feature tests, the [credential inventory](rust-azure-credential-inventory.md)
  and this checkpoint with scenario-to-test traceability.
- Record the remaining edge cases as exceptions **B-1 to B-11** below. They need
  no Azure. They are the **next work after Option A**, meaning after the live
  campaign and its fixes are complete.

**Code complete** here means "every in-scope behavior is implemented, with
development evidence or a named exception". It is not live acceptance and not
publication.

## Added at this checkpoint

- **Cross-feature controlled tests** ([`azure_cross.rs`](../../../clients/rust/tests/azure_cross.rs)):
  - Entra pools: one token per physical login and none for a reused lease, with
    a deferred reset on reuse.
  - An identity or source change retires a stale returned session once a newer
    opening has read the change. There is no watcher, as agreed.
  - An Entra refusal re-reads settings once; only a changed identity reopens.
  - A refused token provider releases pool capacity.
  - One Entra login negotiates federated authentication and enclave-capable
    Always Encrypted. Key Vault keys reach the enclave package after the vault
    verifies both the enclave permission and the envelope.
  - Entra recovery requests a new token; a new wrapper re-establishes the
    enclave session and unwraps the vault key again.
- **Real-server Key Vault metadata** ([`keyvault_live.rs`](../../../clients/rust/tests/keyvault_live.rs),
  Docker): SQL Server holds an `AZURE_KEY_VAULT` master key and the
  Python-generated vault envelope. Rust encrypts, looks up and decrypts through
  the official SDK over a fake transport, across pool return, for TDS 7.4/8.0 ×
  MARS on/off.
- **Fixture:** `enclave.py` now also emits `description_vault`, the same
  description with the vault-wrapped key and vault metadata signature.
- **Shared test fakes:** the fake vault and enclave peer moved to
  `tests/support/{vault,enclave}.rs` and are reused by `keyvault.rs` and `enclave_connection.rs`.
- **Test-harness fixes:**
  - Four fake servers dropped their socket before the client closed, so
    `close()` could correctly see `Closed`. Two in `enclave_connection.rs` failed
    about 1 in 30 parallel runs; one in `cancellation.rs` failed about 1 in 10,
    on `main` too. All now wait for the client's EOF. A 20-run full-suite hunt
    found no others.
  - `check_rust.py --live` stopped on the Windows-only certificate-store test on
    other hosts, so no Docker test had run since `6270814`. It is now skipped
    outside Windows.
- **Tooling:** `check_rust_azure.py` gained a `rust-cross-feature` group.

## Scenario traceability

"Covered" means a test exists that fails if the behavior regresses. Test names
are in `clients/rust/tests/` unless prefixed with a module path.

| ID | Status | Evidence | Remaining |
|---|---|---|---|
| A01 | Covered | `azure_wire::federated_feature_and_token_messages_match_python`, `::supplementary_unicode_counts_utf16_bytes_and_nonce_has_no_length_prefix`, `azure_login::both_entra_paths_echo_nonce_and_use_sql_across_versions_and_mars` | Live |
| A02 | Covered | `azure_login::routing_requests_the_source_for_each_physical_attempt_and_refuses_a_second_route`, `::recovery_gets_a_new_token_without_replaying_application_sql`, `azure_cross::entra_pool_requests_a_token_per_physical_login_not_per_lease`, `::entra_recovery_gets_a_new_token_and_a_new_wrapper_unwraps_vault_keys_again` | Live |
| A03 | Covered, with exceptions | `entra::azure::tests` (4); [credential inventory](rust-azure-credential-inventory.md) | E-CRED-1, E-CRED-2; live: CLI, service principal, managed identity |
| A04 | Partial | `azure_wire::fedauthinfo_fields_match_python_at_every_fragment_boundary` | B-1 |
| A05 | Partial | `azure_login::provider_deadline_and_caller_cancellation_retire_the_candidate_and_future`, `::provider_errors_hide_sensitive_causes_and_unbound_sources_fail_before_tcp`, `::driver_token_bound_and_explicit_expiry_fail_without_sending_login`, `azure_cross::entra_provider_refusal_in_a_pool_releases_capacity_for_the_next_opening` | B-2 |
| A06 | Partial | `azure_login::routing_…_refuses_a_second_route`, `azure_cross::entra_identity_change_retires_returned_sessions_once_a_new_login_reads_it`, `::entra_refusal_rereads_settings_once_and_only_a_changed_identity_reopens` | B-3 |
| A07 | Covered | `azure_login::both_entra_paths_…` (capture, Full inspection, replay), `::provider_errors_hide_…` | Live: real tokens absent from captures |
| K01–K03 | Covered | `keyvault::sdk_requests_preserve_version_verify_order_and_python_envelopes`; runner `python-read-rust-keys`; verify-before-unwrap order in `azure_cross::entra_login_negotiates_enclaves_and_key_vault_keys_reach_the_package` and `keyvault_live` | Vault path/provider tampering: B-4; live |
| K04 | Partial | `keyvault::vault_denial_keeps_protected_diagnostic_out_of_normal_errors`, tampered envelope in K01 test | B-4 |
| K05 | Covered for local and vault keys | `key_providers::async_provider_preserves_every_master_column_retention_combination`, `keyvault_live::key_vault_column_keys_encrypt_read_and_reunwrap_after_pool_return`, `azure_cross::entra_recovery_…` | Certificate keys across pool: live (C02) |
| C01 | Partial | `encryption::certstore` unit tests `python_certificate_paths`, `unavailable_platform_is_explicit` | B-5; live |
| C02 | Live only | `certstore_native::native_non_exportable_certificate_mutually_wraps_and_signs_with_python` (Windows) | Windows VM in the campaign |
| E01–E03 | Covered | `encryption::enclave` P-384 unit tests, `enclave_wire::version_two_batch_and_rpc_packages_match_python_and_roundtrip_inspection`, runner `python-read-rust-enclave` | Live |
| E04 | Partial | `encryption::enclave` malformed-point/tamper/counter-exhaustion unit test | B-6 |
| E05–E06 | Covered | `enclave_connection::facade_authorizes_keys_shares_counter_and_recreates_session_after_invalidation`, `enclave_wire`, `azure_cross::entra_login_negotiates_enclaves_…` | Live: LIKE/range rows |
| E07 | Covered | `enclave_connection::unsigned_enclave_key_is_refused_before_application_sql` | — |
| E08 | Covered | `enclave_connection::enclave_stale_refusal_is_redescribed_once_and_second_refusal_is_returned` | Live |
| E09 | Covered for recovery | `encryption::tests` session-authority retirement, `azure_cross::entra_recovery_…` | Enclave across pool return: B-6 |
| W01 | Partial | `tds-native-gssapi` system tests (6), `auth::gssapi` tests | B-7; live ticket login |
| Windows/Browser baseline | Regression | `authentication.rs`, `browser.rs` | B-8; live NTLM, wrong password and Browser |
| Azure-only features | Covered, agreed divergence | `azure_features` (4) | Live: Rust refuses where Python's test passed (PY-AZ-06) |
| Iteration 11, cross-feature | Covered | `azure_cross` (6), `keyvault_live` (4 combinations) | Entra × MARS × pool and Entra × AE against real Azure: live |
| Iteration 5, CLI | Partial | — | B-9 |

## Exceptions: the queued follow-on work (Option B)

These need no Azure. Owner direction: work on them next, after Option A's
development, live testing and fixes are complete.

| ID | Scenario | Missing tests |
|---|---|---|
| B-1 | A04 | FEDAUTHINFO arriving unexpectedly or after LOGINACK, more than the round limit, the 64 KiB message bound |
| B-2 | A05 | Empty token, provider result without expiry, late provider completion after cancellation |
| B-3 | A06 | TLS or certificate refusal at the redirect target; pool closed during an Entra opening |
| B-4 | K01, K04 | Vault: wrong provider or path, missing key, changed key version, wrong algorithm, malformed signature, timeout, canceled late unwrap |
| B-5 | C01 | Wrong or missing certificate; a controlled fake for the native layer |
| B-6 | E04, E09 | Concurrent enclave requests, wrong session or statement, enclave session across pool return |
| B-7 | W01 | Expired and absent ticket classification |
| B-8 | Baseline | Controlled wrong-Windows-password refusal |
| B-9 | Iteration 5 | `tds --auth entra-*` CLI tests |
| B-10 | A02 | Controlled Entra × MARS × pool |
| B-11 | Iteration 10 | Enclave SQL with certificate-store keys (controlled) |

## Not claimed

Azure interoperability is unproven until the live campaign. A skipped Windows
test is not a passing native-provider check. The credential modes without
environment evidence are listed in the inventory, not claimed. Rust remains
unpublished.

## Verification, 2026-10-20

Run on macOS (Apple silicon) with Rust 1.99.1, the crate's minimum. The local
toolchain was 1.99.0 and had to be updated before anything compiled. Logs stay
outside Git, under `~/tds-evidence/checkpoint-20261020T1803Z/`.

| Check | Result |
|---|---|
| `python3 tools/check_rust_azure.py` | Passed: 104 Rust tests in 11 groups, all Python vector and cross-read steps; 183 source files hashed, unchanged during the run |
| `python3 tools/check_rust.py --live` | Passed: formatting; tests 241 default / 103 core / 304 all-features, 0 failed; strict Clippy for all three feature sets; rustdoc; 62/62 Docker SQL Server live tests |
| `cargo test --workspace --all-features` | 310 passed, 0 failed, 63 ignored (environment-dependent) |
| Windows companion crates, `x86_64-pc-windows-gnu` Clippy | Clean. This is compilation only, not CNG runtime |
| New and repaired tests repeated | 40/40 runs (`azure_cross`, `enclave_connection`, `keyvault`, `cancellation`) |
| Mutation check | Wrong token expectation and wrong vault operation order each fail their test |

The full client's Windows build needs a MinGW C compiler for `aws-lc-sys` and is
not checked here. It is built natively on the campaign's Windows VM.
