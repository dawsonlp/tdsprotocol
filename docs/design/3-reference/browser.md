# Browser (reference)

**Where this sits:** before connecting, and outside TDS. The SQL Server Browser answers on UDP port 1434, saying where a machine's instances listen. The client then connects with TDS as usual.
**Use this page to** find a named instance's port, list a machine's or a network's instances, or find an instance's DAC port, and to read or build the datagrams that do it.

## Purpose

A default instance listens on TCP 1433. A named instance listens on a port of its own, often a new one each time it starts, so a client that knows only the instance's name must ask for it. The Browser is the Windows service that knows these ports. Its protocol is MC-SQLR, the SQL Server Resolution Protocol, a separate Microsoft specification beside MS-TDS (`docs/specification/mc-sqlr_v20251031.pdf`, fetched by `tools/fetch_specifications.py`).

## Shape

One request datagram; one reply datagram from each machine that answers. Integers are little-endian. Text is in the code page the client and server share.

| First byte | Request | Then | Sent to | Answered with |
|---|---|---|---|---|
| `02` | every instance on the network (CLNT_BCAST_EX) | — | a broadcast address (IPv4) or multicast (IPv6) | each machine's instances, as text |
| `03` | every instance on one machine (CLNT_UCAST_EX) | — | the machine | its instances, as text |
| `04` | one instance (CLNT_UCAST_INST) | the instance name, ended by `00` (at most 32 bytes) | the machine | that instance, as text |
| `0F` | one instance's DAC port (CLNT_UCAST_DAC) | protocol version `01`, then the instance name, ended by `00` | the machine | the DAC port |

Every reply (SVR_RESP) starts with `05`:

| Reply to | Bytes |
|---|---|
| `02`, `03`, `04` | `05`, the text's length (u16), the text |
| `0F` | `05`, the reply's whole length (u16, always `06 00`), protocol version `01`, the DAC port (u16) |

The text describes one or more instances. Each is a list of `;`-separated name–value pairs, ending in `;;`:

```
ServerName;ILSUNG1;InstanceName;YUKONSTD;IsClustered;No;Version;9.00.1399.06;tcp;57137;;
```

The first four pairs are always *ServerName*, *InstanceName*, *IsClustered* (`Yes` or `No`) and *Version*. Then come the endpoints the instance listens on, in any order, each at most once:

| Name | Value |
|---|---|
| `tcp` | the TCP port, in decimal |
| `np` | the named pipe, such as `\\ILSUNG1\pipe\sql\query` |
| `via` | a NetBIOS name, then `,nic:port` pairs (VIA, retired) |
| `rpc` | a computer name (multiprotocol, retired) |
| `spx` | a service name (SPX, retired) |
| `adsp` | an AppleTalk object name (retired) |
| `bv` | Banyan VINES item, group and organization names, several `;`-separated parts (retired) |

## Rules

- **The Browser sends no reply when it has no answer.** A request it doesn't understand, or for an instance it doesn't have, is ignored, because MC-SQLR has no negative reply. The client waits until its timer ends, and can't distinguish those cases from a machine with no Browser.
- **The client's timer:** MC-SQLR suggests 1 second for an instance or DAC request, and leaves the others to the client. The driver waits 1000 ms for every request unless `timeout_ms=…` says otherwise (D-59).
- **A broadcast collects replies until the timer ends,** because every machine that receives it may answer. A reply that can't be read is ignored, as MC-SQLR requires; for a request sent to one machine, it is an error.
- **Words aren't case-sensitive:** `ServerName`, `SERVERNAME` and `servername` are the same.
- **The DAC reply's length is counted differently.** It is the length of the whole reply (6), whereas every other reply's length counts only the text after it.
- **Text is in a shared code page, never named on the wire.** MC-SQLR assumes the client's and the server's are the same. The driver uses ASCII unless told to use another code page (D-59). A name that ASCII can't encode is refused before it is sent, and a reply that ASCII can't decode is reported with the byte that failed. The driver never guesses. [Another code page](#another-code-page) says how to use one.
- **Limits:** an instance name sent is at most 32 bytes; a longer one is refused. A reply's text is at most 1,024 bytes per instance; MC-SQLR says a client *should* reject an endpoint value over 255 bytes. The driver doesn't reject it, and shows what arrived.

## Example

Asking a machine for its instance YUKONSTD (MC-SQLR §4.2):

| Bytes | Meaning |
|---|---|
| `04` | one instance |
| `59 55 4B 4F 4E 53 54 44 00` | “YUKONSTD”, ended by `00` |

The reply:

| Bytes | Meaning |
|---|---|
| `05` | SVR_RESP |
| `58 00` | 88 bytes of text follow |
| `53 65 72 76 …  3B 3B` | `ServerName;ILSUNG1;InstanceName;YUKONSTD;IsClustered;No;Version;9.00.1399.06;tcp;57137;;` |

The client then connects with TDS to ILSUNG1, port 57137.

Asking for YUKONSTD's DAC port (§4.3) sends `0F 01 59 55 4B 4F 4E 53 54 44 00` and receives `05 06 00 01 32 DF`: port `0xDF32`, 57138.

In code:

```python
instance = await tds.browser.instance("db.example.com", "SALES")     # one instance; .tcp_port, .protocols, .address
found = await tds.browser.machine("db.example.com")                  # every instance on that machine
found = await tds.browser.broadcast()                                # every instance that answers 255.255.255.255
port = await tds.browser.dac_port("db.example.com", "SALES")         # the DAC port
```

A failure is a `BrowserError` that names the request, the machine and the port, and what may explain it: no reply in time, nothing listening (the machine refused the port), or a reply that can't be read, with its bytes.

Every call takes `port=` (default 1434), `timeout_ms=` (default 1000) and `encoding=` (default `"ascii"`).

**Then connect.** The Browser gives a port, and connecting to it is the application's next step: `tds.connect(host, instance.tcp_port, …)`. The driver doesn't combine the two steps. A connector that combines them is a convenience, in a layer around the driver (D-39, D-59).

### Another code page

The Browser runs on Windows, and writes its text in the machine's ANSI code page. To find it, run this in PowerShell on that machine:

```powershell
(Get-ItemProperty HKLM:\SYSTEM\CurrentControlSet\Control\Nls\CodePage).ACP      # for example, 1252
```

Then pass the matching Python codec, which is `cp` followed by the number:

| ACP | Used for | `encoding=` |
|---|---|---|
| 1252 | Western European languages | `"cp1252"` |
| 1250 | Central European | `"cp1250"` |
| 1251 | Cyrillic | `"cp1251"` |
| 932 | Japanese | `"cp932"` |
| 936 | Simplified Chinese | `"cp936"` |
| 949 | Korean | `"cp949"` |
| 950 | Traditional Chinese | `"cp950"` |

```python
instance = await tds.browser.instance("db.example.com", "VERKÄUFE", encoding="cp1252")
```

ASCII is the same in each of these code pages, so ASCII names work with any of them. A name with other characters needs the right code page. With the wrong one, a character may be refused before sending (*can't be written in…*), or a byte of a reply may fail to decode (*the text isn't ascii: byte 0xe9…*). Worse, both code pages may contain the bytes but map them to different characters, and nothing can detect it. The Browser then doesn't recognize the name, and doesn't answer.

## Edge cases

- **The default instance is named `MSSQLSERVER`.** Ask for it by that name.
- **SQL Server on Linux has no Browser.** A Linux server, like the test container, is reached by its port. The Browser was tested live in M17, on Windows.
- **A firewall usually blocks UDP 1434.** When it does, every request goes unanswered, and the error says so.
- **Knowing the DAC port doesn't mean the DAC accepts the connection.** From another machine, the DAC needs *remote admin connections* on, as in the test container ([Connect](connect.md)).

**What MC-SQLR doesn't state clearly.**
- **Banyan VINES:** its grammar names the item and group twice (`bv;item;group;item;group;org`). The driver takes every part up to the next endpoint's name as the value, as sent.
- **IPv6:** MC-SQLR sends the broadcast request by multicast over IPv6, but names no multicast group. The driver broadcasts over IPv4 only.

---

**Source:** MC-SQLR §2.1, §2.2.1–§2.2.6, §3.1.5.2, §3.2.2, §3.2.5, §4
