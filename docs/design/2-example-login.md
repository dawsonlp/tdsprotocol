# 2 · Worked Example: a Login

**Where this sits:** the *connect* conversation from [the Model](1-model.md), traced byte by byte.
**After reading this you can** read a TDS login capture: find each message, split it into packets and fields, and say what each one does.

The bytes come from MS-TDS's own samples (§4.1, §4.2, §4.4), so you can check them against the official document. Only the client's host name differs. They were captured from an older (TDS 7.2) client, so [what the driver sends differently](#what-the-driver-sends-differently) is listed at the end. MS-TDS has no sample reply to the hello, so that one is **constructed** and labeled as such.

```
client                                   server
  │ ── 1 hello (PRELOGIN) ───────────────►  │
  │ ◄─────────────── 2 hello reply ──────── │
  │ ◄══════ 3 secure (TLS handshake) ═════► │
  │ ── 4 log in (LOGIN7) ────────────────►  │   from here on, everything is inside TLS
  │ ◄────────────── 5 login reply ───────── │
  ready
```

---

## 1 · Hello — the client introduces itself

```
packet header   12 01 00 2F 00 00 01 00
directory       00 00 1A 00 06  01 00 20 00 01  02 00 21 00 01  03 00 22 00 04  04 00 26 00 01  FF
data            09 00 00 00 00 00  01  00  B8 0D 00 00  01
```

**Packet header.** Every packet starts with these 8 bytes.

| Bytes | Field | Value |
|-------|-------|-------|
| `12` | type | PRELOGIN |
| `01` | status | last packet of this message |
| `00 2F` | length | 47 bytes, header included (big-endian) |
| `00 00` | session id | none yet |
| `01` | packet number | 1 |
| `00` | (unused) | |

**Directory.** This is a list of *(option, offset, length)* entries, ending in `FF`. Offsets count from the start of the body, which is the first byte after the header.

| At | Bytes | Option | Data at | Length |
|----|-------|--------|---------|--------|
| 00 | `00 00 1A 00 06` | version | 0x1A | 6 |
| 05 | `01 00 20 00 01` | encryption | 0x20 | 1 |
| 0A | `02 00 21 00 01` | instance | 0x21 | 1 |
| 0F | `03 00 22 00 04` | thread id | 0x22 | 4 |
| 14 | `04 00 26 00 01` | MARS | 0x26 | 1 |
| 19 | `FF` | end of directory | | |

**Data.** The directory's entries point here.

| At | Bytes | Meaning |
|----|-------|---------|
| 1A | `09 00 00 00` `00 00` | client library version 9.0.0, sub-build 0 |
| 20 | `01` | encryption: **on** |
| 21 | `00` | instance name: empty (the default instance) |
| 22 | `B8 0D 00 00` | client thread id 3512 (for debugging only) |
| 26 | `01` | MARS: on |

> **Notice:** the directory and the version use big-endian numbers. This is one of the few places in TDS that does.

## 2 · Hello reply — the server agrees on terms *(constructed example)*

```
packet header   04 01 00 2B 00 34 01 00
directory       00 00 1A 00 06  01 00 20 00 01  02 00 21 00 01  03 00 22 00 00  04 00 22 00 01  FF
data            10 00 03 E8 00 00  01  00  00
```

The reply has **the same structure** as the hello, with three differences:
- The packet type is `04`. Every server message uses that type.
- The session id is now set (`00 34`, session 52).
- The values are the server's: version 16.0.1000, encryption **on**, instance `00` meaning "yes, that's me", thread id empty, MARS off.

Both sides said encryption *on*, so the next step is TLS.

## 3 · Secure — the TLS handshake, carried inside TDS

```
12 01 00 4E 00 00 00 00 │ 16 03 01 00 …
└─ PRELOGIN packet header ┘ └─ a TLS record (16 = handshake) ─┘
```

TLS handshake records travel as the payload of PRELOGIN packets, in both directions, until the handshake completes. After that, the arrangement is reversed: **whole TDS packets, headers included, travel inside TLS.** The next two messages are shown as they look after decryption.

## 4 · Log in — who the client is, and what it wants

The packet is 144 bytes: an 8-byte header (`10 01 00 90 00 00 01 00`: LOGIN7, last packet, 144 bytes), then a 136-byte body in three parts.

**Fixed part.** These fields are always present, in this order.

| At | Bytes | Field | Meaning |
|----|-------|-------|---------|
| 00 | `88 00 00 00` | length | body is 136 bytes |
| 04 | `02 00 09 72` | TDS version | 7.2 |
| 08 | `00 10 00 00` | packet size | asks for 4096 |
| 0C | `00 00 00 07` | client library version | |
| 10 | `00 01 00 00` | client process id | 256 |
| 14 | `00 00 00 00` | connection id | 0 |
| 18 | `E0` | option flags 1 | report database changes; initial database must succeed; report language changes |
| 19 | `03` | option flags 2 | initial language must succeed; client is ODBC |
| 1A | `00` | type flags | default SQL dialect |
| 1B | `00` | option flags 3 | none |
| 1C | `00 00 00 00` | time zone | unused |
| 20 | `09 04 00 00` | locale | 0x0409, en-US |

**Pointer table.** Each entry is an *(offset, length in characters)* pair that points into the data part below.

| At | Bytes | Points to | Length |
|----|-------|-----------|--------|
| 24 | `5E 00 08 00` | host name | 8 |
| 28 | `6E 00 02 00` | user name | 2 |
| 2C | `72 00 00 00` | password | 0 |
| 30 | `72 00 07 00` | application name | 7 |
| 34 | `80 00 00 00` | server name | 0 |
| 38 | `80 00 00 00` | extension | 0 |
| 3C | `80 00 04 00` | client library name | 4 |
| 40 | `88 00 00 00` | language | 0 |
| 44 | `88 00 00 00` | database | 0 |
| 48 | `00 50 8B E2 B7 8F` | *client id (inline, not a pointer: a MAC address)* | |
| 4E | `88 00 00 00` | Windows auth data | 0 |
| 52 | `88 00 00 00` | database file to attach | 0 |
| 56 | `88 00 00 00` | new password | 0 |
| 5A | `00 00 00 00` | *large Windows auth length (inline)* | |

**Data part.** The strings are UTF-16LE, one after another, with no gaps between them.

| At | Bytes | Text |
|----|-------|------|
| 5E | `6C 00 70 00 64 00 74 00 65 00 73 00 74 00 31 00` | `lpdtest1` |
| 6E | `73 00 61 00` | `sa` |
| 72 | `4F 00 53 00 51 00 4C 00 2D 00 33 00 32 00` | `OSQL-32` |
| 80 | `4F 00 44 00 42 00 43 00` | `ODBC` |

> **Notice:** empty fields still have an offset. It points to where the next string *would* go. The password here is empty. A real password is lightly scrambled. For example, `a` (`61 00`) is sent as `B3 A5`. The scrambling does not provide security; TLS does.

## 5 · Login reply — the server accepts, and describes the session

The reply is a single 353-byte packet (`04 01 01 61 00 00 01 00`). Its body is a **token stream** of eight tokens:

| At | Starts with | Token | Says |
|----|-------------|-------|------|
| 000 | `E3 1B 00 01 …` | ENVCHANGE | database is now `master` |
| 01E | `AB 58 00 45 16 …` | INFO | #5701 "Changed database context to 'master'." |
| 079 | `E3 08 00 07 …` | ENVCHANGE | collation is now `09 04 D0 00 34` (en-US, case-insensitive, sort order 52) |
| 084 | `E3 17 00 02 …` | ENVCHANGE | language is now `us_english` |
| 09E | `E3 13 00 04 …` | ENVCHANGE | packet size is now `4096` (sent as text) |
| 0B4 | `AB 5C 00 47 16 …` | INFO | #5703 "Changed language setting to us_english." |
| 113 | `AD 36 00 01 72 09 00 02 …` | **LOGINACK** | **login accepted**: T-SQL, TDS 7.2, "Microsoft SQL Server" |
| 14C | `FD 00 00 …` | DONE | end of reply, nothing more follows |

Here is one token in full, the first ENVCHANGE:

```
E3          tag: ENVCHANGE
1B 00       length of what follows: 27 bytes
01          kind: database
06  6D 00 61 00 73 00 74 00 65 00 72 00      new value: 6 characters, "master"
06  6D 00 61 00 73 00 74 00 65 00 72 00      old value: 6 characters, "master"
```

> **Notice:** success is signaled by **LOGINACK being present**, not by its position. Here it comes near the end. A failed login has an `ERROR` token and no LOGINACK. The new packet size takes effect from the **next** message.

---

## What just happened

1. The client and server **agreed on terms** (hello), turned on **TLS** (secure), and then the client **identified itself** (log in).
2. The server answered with **announcements** that set up the session state, a **LOGINACK** accepting the login, and a **DONE** ending the reply.
3. The client is now **ready** to send requests.

**In TDS 8.0**, step 3 moves to the start. TLS is set up directly on TCP, before the hello. Steps 1, 2, 4 and 5 are identical.

## What the driver sends differently

Each difference is a decision in [Decisions](4-decisions.md).
- TDS version `04 00 00 74` (7.4) instead of `02 00 09 72` (D-2).
- MARS **off** (`00`), unless `connect(mars=True)` asks for several serial channels (D-18).
- The ODBC flag, unless `connect(odbc=False)` turns it off (D-9).
- A feature list, pointed to by the *extension* entry. By default it asks for JSON support, vector support, UTF-8 support, data classification and session recovery (D-8).

---

**Next:** [Reference](3-reference/packet.md) · **Source:** MS-TDS §4.1, §4.2, §4.4, §2.2.6.5
