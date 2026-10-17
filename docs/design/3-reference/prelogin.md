# PRELOGIN (hello)

**Where this sits:** the first message of the *connect* conversation. Its body is a **structure**. Its packet type is `12`, and the server's reply has packet type `04`.
**Use this page to** read or build a hello or a hello reply, and to determine the encryption outcome.

## Purpose

Before logging in, the two sides exchange versions and agree on encryption. The client also says which server instance it expects.

## Shape

```
directory   (option, offset, length) × n      then FF
data        the option values, at the offsets the directory gives
```

| Directory entry field | Size | Meaning |
|-----------------------|------|---------|
| option | 1 | Which option (table below) |
| offset | 2, **big-endian** | Where its value starts, counted from the start of the body |
| length | 2, **big-endian** | Value length in bytes |

The directory ends with a single `FF` byte, which has no offset or length.

**Options**

| Value | Option | Value layout | Notes | MS-TDS name |
|-------|--------|--------------|-------|-------------|
| `00` | version | major u8, minor u8, build u16 BE, sub-build u16 | **Must be first** | VERSION |
| `01` | encryption | u8: `00` off · `01` on · `02` not supported · `03` required | Ignored in 8.0 | ENCRYPTION |
| `02` | instance | client: instance name + `00`; server: `00` match · `01` mismatch | | INSTOPT |
| `03` | thread id | u32 (client); empty from server | Debugging only | THREADID |
| `04` | MARS | u8: `00` off · `01` on | | MARS |
| `05` | trace id | 16-byte connection id, 16-byte activity id, u32 sequence | Optional | TRACEID |
| `06` | fed auth required | u8 | Only for choosing between Windows and federated auth | FEDAUTHREQUIRED |
| `07` | nonce | 32 bytes | Only for some federated auth | NONCEOPT |
| `FF` | end of directory | — | **Must be last** | TERMINATOR |

## Rules

- **Version first, end marker last.** A server closes the connection if version isn't the first option.
- **Instance check.** If the reply's instance value is `01`, the client reached the wrong instance and should close the connection.
- **Encryption outcome (7.4).** It depends on what each side says:

  | Client says | Server says | Result |
  |-------------|-------------|--------|
  | on | on / required | **whole connection encrypted** |
  | on | not supported | server closes the connection |
  | off | off | only the login packet is encrypted |
  | off | required | whole connection encrypted |
  | off / not supported | not supported | no encryption |
  | not supported | required | server closes the connection |

  The driver accepts only an outcome that encrypts the whole connection. Any other outcome fails, with an explanation (D-10).

- **After the reply (7.4):** if encryption was agreed, the TLS handshake follows immediately, carried in type `12` packets. See [Packet › Edge cases](packet.md#edge-cases).
- **In 8.0**, TLS is already established, so the encryption option is ignored.

## Example

The [Worked Example §1–§2](../2-example-login.md#1--hello--the-client-introduces-itself) gives a hello with five options, and a reply that agrees to encrypt.

## Edge cases

- Options the receiver doesn't know about are skipped using their offset and length.
- Unlike almost everything else in TDS, the directory offsets, lengths and version are **big-endian**. The thread id is little-endian.
- A client that asks for certificate login sets `80` together with an encryption value. The driver doesn't offer certificate login.

---

**Source:** MS-TDS §2.2.6.5, §3.2.5.2
