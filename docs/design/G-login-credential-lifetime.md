# Credential lifetime: server changes and pool configuration

**Where this sits:** The distinction between a server password change, current pool credentials and a one-time password-changing login.
**After reading this you can** reproduce the recovery defect and understand the shared configuration design that replaces the earlier pool-password question.

**Intent:** server password changes belong to an explicit database/login operation.
A pool reads current credentials from its configuration service when opening a
connection. Authentication rejection does not establish that a password changed.
The pool object remains usable after an operator corrects the source.

The user approved the shared design on 2026-10-17. Both clients implement the
[configuration snapshot and lifetime policies](H-pool-configuration.md). The earlier choice
between changing a password through a pool or constructing a replacement pool
did not describe the required scenario and is superseded.

## Evidence

A disposable login on the local Docker SQL Server successfully connected through
Python with `password=old, new_password=new`, ran SELECT 1, then lost its transport
through a local relay cut. Explicit session recovery failed with
`SessionNotRecovered` caused by `LoginRejected`. No credentials were printed and
the login was dropped afterwards. Before the correction, Python retained the original connection options
and reconstructed recovery LOGIN7 from them, including the old password and the
password-change request. This does not reflect the accepted credential change.

Reproduction from the repository root:

```sh
clients/python/.venv/bin/python tools/probe_password_change_recovery.py
```

The probe creates only one generated login and prints type-level results, not
credentials or SQL packet bodies. It uses the existing Docker test endpoint and
ignored administrator configuration. The original probe reported successful password change followed by
`SessionNotRecovered` / `LoginRejected`; rerunning it with the corrected client
now reports successful recovery.

## Implemented direct-login correction

Only a successful, fully completed LOGINACK/DONE/EOM commits a changed credential.
Before that, keep the original pair for the current login attempt. A routing
reply is not a successful final login. After success, replace the reconnect
password with the new password and clear `new_password`; recovery sends a normal
login with the accepted credential and the recovery snapshots. Keep both
password fields redacted in observation and saved recordings. Changing a
password does not grant data permissions or alter channel ownership.

If the server changes the password but the login completion is lost, the client
cannot know whether A or B is now accepted. Report that uncertainty; do not
automatically replay the one-time change or claim that A still works. The live success/recovery path passes under both TDS versions. Controlled TLS
peers test interrupted completion, an explicit uncertain outcome and no retry in
both languages; they do not claim an actual server-side password change.

## Pool configuration is a separate operation

The current abstraction is a pool constructed from connection settings. Rust's
`Pool::new(ConnectOptions, capacity)` retains settings, including SQL credentials,
and clones them into `Connection::connect` for each physical opening. Python's
`Pool` likewise retains keyword options and passes them to `connect`. This is
credential pass-through, not password management.

An operator or application changes the server password from A to B independently.
The application's configuration service must then supply usable credentials.
The pool reads a complete immutable snapshot for an opening and compares values
with its own last accepted configuration. It does not need a hash, timestamp,
global change flag, watcher or notification task.

Both pools now expose `from_config` and carry independent configuration access
into recovery. Existing SQL constructors adapt fixed values through `StaticConfig`.
H gives the public interfaces, compatibility rules and tested lifecycle.

## Observed rotation and reset boundary

An isolated Docker observation used a disposable SQL login with policy checking
off. The administrator changed its password while a pooled connection was lent.
The current borrower continued to run SELECT. A further opening using A failed;
a fresh explicit connection using B succeeded. On return/reborrow, the original
connection's first request, carrying the normal session-reset flag, failed with
18456 and fatal 596. A second run omitted all intervening login attempts and
observed the same reset failure. Closing the old connection and asking the
unchanged pool for a replacement also failed with retained A. Disposable logins
were removed after the observations.

These are local observations against SQL Server 17.0.5015, not a claim that every
server deployment behaves identically. They explain why merely keeping an open
socket cannot guarantee successful reuse after a password change. Reading only
on opening deliberately does not guarantee seamless rotation; H preserves the
deferred-reset failure and prohibition on SQL replay.

## The special `new_password` setting

`connect(password=A, new_password=B)` requests a password change within LOGIN7.
It permits a login that cannot first establish an ordinary SQL session, such as
an expired password or MUST_CHANGE login. It is not a notification that another
party already changed the password.

Previously Python forwarded a pool's generic `new_password` argument into every
opening; Rust had codec-only support. Both clients now exclude this field from
reusable configuration and reject it at pool construction. Both retain the
explicit direct-connection operation. A successful direct change updates
only that connection's owned reconnect credential; it does not write to the
application's configuration source or attempt to notify pools.
