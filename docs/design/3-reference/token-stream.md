# Token Stream

**Where this sits:** message › **body** (when the body is a token stream) › token › field.
**Use this page to** read any token stream: find where each token ends, and know which tokens can appear.

## Purpose

Most server messages are token streams: tokens one after another, with no separators. To read the next token, a reader must know where the current one ends. Each token has its own rule for that.

## Shape

```
tag (1 byte) │ body ─ length found by the tag's rule ─ │ tag │ body │ … │ DONE
```

Every tag uses one of four **length rules**:

| Rule | How the body's end is found | Tokens |
|------|-----------------------------|--------|
| **fixed** | The body is always the same size. | DONE, DONEPROC, DONEINPROC (12 bytes) · RETURNSTATUS (4) |
| **length-prefixed** | A u16 (or u32) after the tag gives the body size. | ENVCHANGE, ERROR, INFO, LOGINACK, ORDER, TABNAME, COLINFO, SSPI · *u32:* SESSIONSTATE, FEDAUTHINFO |
| **counted** | A u16 count of columns follows, and each column is walked. | COLMETADATA, ALTMETADATA |
| **walked** | There is no size field. The body is read field by field, up to a terminator or as the column metadata says. | FEATUREEXTACK, DATACLASSIFICATION, RETURNVALUE · *against the last COLMETADATA:* ROW, NBCROW · *against the ALTMETADATA with its id:* ALTROW |

**Tags**

| Tag | Token | Rule | Seen in |
|-----|-------|------|---------|
| `81` | COLMETADATA | counted | results |
| `88` | ALTMETADATA | counted | results with `COMPUTE`, which SQL Server no longer supports |
| `A3` | DATACLASSIFICATION | walked | results, when the login asked for data classification |
| `A4` | TABNAME | u16 | results in browse mode, and from server cursors |
| `A5` | COLINFO | u16 | results in browse mode, and from server cursors |
| `A9` | ORDER | u16 | results |
| `AA` | ERROR | u16 | any reply |
| `AB` | INFO | u16 | any reply |
| `AC` | RETURNVALUE | walked | procedure results |
| `AD` | LOGINACK | u16 | login reply |
| `AE` | FEATUREEXTACK | walked | login reply |
| `D1` | ROW | walked | results |
| `D2` | NBCROW | walked | results |
| `D3` | ALTROW | walked | as ALTMETADATA |
| `E3` | ENVCHANGE | u16 | any reply |
| `E4` | SESSIONSTATE | u32 | any reply, when the login asked for session recovery |
| `ED` | SSPI | u16 | login reply (Windows auth) |
| `EE` | FEDAUTHINFO | u32 | login reply (federated auth) |
| `79` | RETURNSTATUS | fixed 4 | procedure results |
| `FD` | DONE | fixed 12 | any reply, always last |
| `FE` | DONEPROC | fixed 12 | procedure results |
| `FF` | DONEINPROC | fixed 12 | procedure results |

## Rules

- **Each definition declares its length rule.** MS-TDS says certain bits of the tag encode its length rule. Several tags contradict that:
  - DONE's bits claim 8 bytes, but it has been 12 since TDS 7.2.
  - FEATUREEXTACK, DATACLASSIFICATION and RETURNVALUE sit in the length-prefixed group, but have no length field.

  So the bits are never used. Each token's definition states its rule.
- **An unknown tag ends the connection.** Without its rule there is no way to find where the token ends, so the message is malformed. The driver defines every tag TDS 7.4 defines (M11). OFFSET (`78`) was removed in TDS 7.2, so a 7.4 server never sends it.
- **A reply ends at a DONE-family token whose "more" bit is clear.** See [Login Response › DONE](login-response.md#fd-done--end-of-the-reply).

## Example

The [Worked Example §5](../2-example-login.md#5--login-reply--the-server-accepts-and-describes-the-session) reads an eight-token login reply that uses two of the rules: length-prefixed (ENVCHANGE, INFO, LOGINACK) and fixed (DONE).

## Edge cases

- TVP_ROW (`01`) appears only inside client RPC requests, never in server messages.

**Where SQL Server differs from MS-TDS.** Observed from SQL Server 2025 (17.0.5015).
- **A *promote transaction* ENVCHANGE runs past its length.** MS-TDS says the length is that of everything after it. SQL Server writes `E3 01 00 0F`: a length of 1, covering only the kind. Then come the coordinator's token (a u32 length, then that many bytes) and the empty old value (`00`). A reader that trusts the length reads the token's first byte as the next tag. The driver's ENVCHANGE definition reads this kind by its fields, not its length.

---

**Source:** MS-TDS §2.2.4, §2.2.5.8, §2.2.7
