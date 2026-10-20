# Rust Azure unsupported-feature policy

**Where this sits:** the four optional Azure feature switches exercised by Python's Azure campaign.

**After reading this you can** distinguish a diagnostic request, a server response and an implemented capability, and predict when an opening must stop.

Status: owner approved the warning/error policy on 2026-10-19, replacing the
proposal to retain enabled probe ACKs and continue. Implemented in Rust;
Python's correction is [backlogged as PY-AZ-06](python-azure-review-backlog.md).

## Intent and representation

An explicit request is configuration. An acknowledgement is evidence about one
physical server response. Neither supplies an absent driver implementation.
`AzureFeatureProbes` selects diagnostic requests, all off by default:

| Setting | Feature ID | Python request payload | Missing driver behavior |
|---|---|---|---|
| `azure_sql_support` | 8 | `01` | Failover-partner login with read-only intent |
| `dns_caching` | 11 | empty | Driver-managed endpoint/IP caching |
| `enhanced_routing` | 15 | empty | Acting on enhanced-routing ENVCHANGE 21 |
| `global_transactions` | 5 | empty | Distributed/elastic transaction coordination |

Existing ordinary Azure routing and local SQL transactions are separate and
retain their supported behavior.

## Approved rule

| Event | Driver action |
|---|---|
| Explicit unsupported request | Warning naming the feature; send the selected diagnostic request |
| No ACK | Keep warning; infer no enabled support; permit otherwise valid login |
| Valid disabled ACK (`0`) | Retain disabled evidence; permit otherwise valid login |
| Valid enabled ACK (`1`) | Typed `ErrorKind::UnsupportedFeatureEnabled(feature)`; stop opening, close/discard the physical connection before application SQL or pool admission |
| Malformed/duplicate/unrequested ACK | Protocol error; stop opening |

There is no permissive test override and no automatic flag removal/retry. A test
that elicits an enabled ACK asserts the error and socket close. No successful
connection carries an enabled acknowledgement for these unimplemented features.

The protocol core enforces the rule for initial login, routed targets and
recovery. Each physical opening negotiates afresh. Comparable configuration
includes probe selection; changing it retires incompatible pool sessions.

## Warning and evidence surfaces

`ConnectOptions`, `ConnectionConfig` and low-level `login7::Login` carry
`azure_feature_probes`. Its `warnings()` method exposes typed warnings before
opening without requiring an observer. Successful sessions retain warnings as
`Session::feature_warnings`, even with observation off. Observation emits
`warning` events before the first flight; Full includes
`Inspection::FeatureWarning`. Disabled replies remain in `Session::features`;
absence is distinct from `[0]`. Enabled replies identify the feature in the
error. The library does not implicitly write process stderr.

CLI flags: `--azure-sql-support`, `--azure-dns-caching`, `--enhanced-routing`,
`--global-transactions`. The CLI prints request warnings even with
`--observe off`. These switches are for deliberate diagnostic tests, and do
not implement or enable the missing driver behavior.

## Tradeoff

This uniform rule is conservative, not a protocol requirement that every
server-capability ACK must terminate a connection. DNS caching is the strongest
counterexample: an enabled ACK permits caching, so ignoring the permission can
be harmless. Enhanced routing advertises an ability to act on instructions;
continuing without its handler creates a stronger mismatch.

A server upgrade that starts enabling a requested unsupported feature can
therefore turn a previously successful diagnostic login into a refusal. This
is intentional. Ordinary defaults do not request these features. Applications
can explicitly remove the request; the driver must not hide the mismatch.
Calling the requests probes does not make them passive capability queries.

Sources: Microsoft [LOGIN7](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/773a62b6-ee89-4c02-9e5e-344882630aac)
and [FEATUREEXTACK](https://learn.microsoft.com/en-us/openspecs/windows_protocols/ms-tds/2eb82f8e-11f0-46dc-b42d-27302fa4701a).

## Development acceptance

Python's production encoder supplies retained request vectors. Controlled
verified-TLS peers exercise four requests with absent/0/1 ACKs under TDS 7.4/8.0
and plain/MARS (48 combinations), typed warnings/refusals, malformed/duplicate/
unrequested ACKs, no SQL on enabled ACK, pool refusal and no silent retry.
Actual Azure interoperability remains a later gate. The recorded Python
1/1/0/1 response would now produce a refusal for its enabled unsupported
features, as intended. Existing source-hash reports are historical snapshots;
use the latest feature-policy check report for the current source.

The [current retained report](rust-azure-feature-policy-checks.json) records 15
passing paired comparisons against an unchanged snapshot of 179 source files.
The final all-feature workspace regression passes 304 tests with 62 explicit
environment-dependent tests ignored; ignored tests are not runtime acceptance.
Strict workspace Clippy/rustdoc, protocol-only compilation, formatting and diff
checks also pass. Source snapshots in older authentication/key/ticket reports
remain historical; they are not assertions about the newer feature-policy code.
