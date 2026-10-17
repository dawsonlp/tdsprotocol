# 1 · The Model

**After reading this you can** name every layer of a TDS conversation, say what each layer is for, and place any byte you see into one of them.

---

## TDS on one page

A client and a database server hold a **conversation** over a **connection**. Everything they say to each other nests like this:

```
connection             TCP, usually wrapped in TLS
 └─ serial channel     one ordered request-and-response path; a connection has one, or several with MARS
     └─ packet         ≤ packet size; an 8-byte header + payload
         └─ message    one or more packets of the same type; the last one is marked "end"
             └─ body   either a STRUCTURE (fixed layout)  or  a TOKEN STREAM (tagged items)
                 └─ field      a named, typed value: a number, a string, a list, a flag set
                     └─ bytes
```

The **conversation** is the order in which the two sides send messages:

```
 CONNECT, once per connection                   then, on a serial channel, repeatedly    at any time
 hello ──► secure ──► log in ──► ready  ──────► request ──► response  (an exchange)        cancel
```

MS-TDS defines **nine conversations in three families**:
- **connecting**: four ways to log in;
- **requests**: SQL batch, remote procedure call, bulk load, transaction-manager request;
- **control**: cancel.

[Conversations](3-reference/conversations.md) lists them all.

## Rules that hold everywhere

1. **On a serial channel, the client speaks, then the server answers.** Only one exchange runs at a time. The only interruption allowed is *cancel*.
2. **Every packet starts with the same 8-byte header.** It says what kind of message the packet carries, whether it's the last packet, and how long it is.
3. **Every server message has packet type `04`.** Apart from the hello reply, every server message is a token stream that ends with `DONE`. A `DONE` marked "more" means another one follows.
4. **Session settings change by announcement.** When the database, language or packet size changes, the server sends an `ENVCHANGE` token and the client updates its copy of the session state.
5. **Numbers are little-endian**, except in a few marked places: the packet header and PRELOGIN's directory are big-endian. **Text is UTF-16LE.**

## Where TLS and MARS fit

```
TDS 7.4    TCP ─► hello (plain) ─► TLS handshake carried INSIDE TDS packets ─► then TDS carried INSIDE TLS
TDS 8.0    TCP ─► TLS handshake first ─────────────────────────────────────► all TDS carried INSIDE TLS
MARS       a thin framing layer between TLS and packets that splits one connection into several serial channels
```

TDS 7.4 and 8.0 share every message and token. They differ only in **when TLS starts**.

MARS doesn't add parallelism. Serial channels on one connection **take turns** on the server and share its transaction and settings. Only separate connections run in parallel.

## Vocabulary

| Term | Meaning |
|------|---------|
| **connection** | One TCP link to the server, with its own login, transaction and settings. A session lives exactly as long as its connection. |
| **pool** | A set of connections. Each one is lent, whole, to one borrower at a time, and is reset when it is returned. |
| **serial channel** | An ordered path that carries one exchange at a time. A connection has one, or several with MARS, which take turns on the server. |
| **exchange** | One request and its complete response. |
| **packet** | The unit written to the wire. It is an 8-byte header plus up to *packet size − 8* bytes of payload. |
| **packet size** | The largest packet allowed. It is 4096 until the server announces another value during login. |
| **message** | One complete thing that one side sends, such as a login, a query or a result. It spans one or more packets. |
| **body** | A message's content once its packets are joined. |
| **structure** | A body with a fixed layout determined by the message type, such as PRELOGIN or LOGIN7. |
| **token stream** | A body made of tokens, one after another, with no separators. |
| **token** | A 1-byte tag followed by that tag's fields. Examples are `LOGINACK`, `ENVCHANGE` and `DONE`. |
| **result set** | Columns, then rows, inside a response. COLMETADATA opens it, and the next completion closes it. |
| **completion** | A DONE, DONEINPROC or DONEPROC token. It reports that a statement or procedure call ended, with its row count when the server sends one. |
| **field** | A named, typed value inside a structure or token. |
| **conversation** | The ordered sequence of messages between client and server: first connecting, then requests. |
| **step** | One named stage of a conversation, such as hello, secure, log in or ready. |
| **session state** | What the client knows about the session: its database, language, packet size, collation and transaction. Only announcements change it. |

---

**Next:** [Worked Example: a Login](2-example-login.md) · **Source:** MS-TDS §1.3, §1.4, §2.1–§2.2.4
