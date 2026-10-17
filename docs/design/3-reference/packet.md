# Packet

**Where this sits:** connection › **packet** › message.
**Use this page to** read or build any packet header, and to split a message into packets or join packets back into one.

## Purpose

A packet is the unit written to the wire. Its header tells the receiver what kind of message the packet belongs to, whether more packets follow, and where this packet ends.

## Shape

```
offset  0      1        2  3      4  5         6          7
        type   status   length    session id   packet #   (unused)
        u8     u8       u16 BE    u16 BE       u8         u8
```

| Field | Size | Meaning | MS-TDS name |
|-------|------|---------|-------------|
| type | 1 | Kind of message (table below) | Type |
| status | 1 | Flags (table below) | Status |
| length | 2, **big-endian** | Whole packet, header included | Length |
| session id | 2, **big-endian** | Server's id for this session; the client sends `00 00` | SPID |
| packet # | 1 | Increases by 1 for each packet and wraps at 256; receivers ignore it | PacketID |
| (unused) | 1 | Always `00` | Window |

**Types**

| Value | Message | Sent by |
|-------|---------|---------|
| `01` | SQL batch | client |
| `03` | remote procedure call | client |
| `04` | **every server message** | server |
| `06` | cancel | client (header only, no payload) |
| `07` | bulk load data | client |
| `08` | federated auth token | client |
| `0E` | transaction manager request | client |
| `10` | login | client |
| `11` | Windows auth continuation | client |
| `12` | hello; also carries the TLS handshake in 7.4 | client (and server, during the handshake) |

**Status flags**

| Bit | Meaning |
|-----|---------|
| `01` | **end**: this is the last packet of the message |
| `02` | ignore: abandon this partly sent message (sent together with `01`) |
| `08` | reset the session before running this request (first packet only) |
| `10` | as `08`, but keep the current transaction (first packet only) |

## Rules

- **One message, one or more packets.** All of a message's packets share its type, and only the last one has *end* set.
- **A new message always starts a new packet.**
- **Packet size** is the maximum packet length. It is 4096 until the server announces a new value in the login reply, and is always between 512 and 32767.
- **Splitting:** every client packet except the last in a message is exactly the packet size.
- **Unknown or unexpected type:** close the connection.

## Example

The hello packet header `12 01 00 2F 00 00 01 00` means: hello, last packet, 47 bytes, no session yet, packet 1. See [Worked Example §1](../2-example-login.md#1--hello--the-client-introduces-itself).

## Edge cases

- **Packet # start value:** implementations start at 0 or 1. Either is valid.
- **TLS in 7.4:**
  - During the handshake, TLS records are the payload of type `12` packets.
  - After the handshake, the packets themselves, headers included, travel inside TLS.
  - **Encrypt packet by packet:** each TLS record must carry whole packets. If a multi-packet message is encrypted in one piece, TLS splits it into records at arbitrary points, and SQL Server closes the connection. MS-TDS doesn't say this. It was observed with SQL Server 2025, and Microsoft's drivers write packets the same way.

---

**Source:** MS-TDS §2.2.3
