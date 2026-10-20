//! Federated authentication's wire definitions, independent of OAuth providers.
//!
//! Python's `tds.logins` is the behavioral reference. These encoders do not
//! authorize a login or establish that a token is acceptable to Azure. Callers
//! own negotiation, provider selection and the authentication state machine.
//! MS-TDS: LOGIN7 FEDAUTH (§2.2.6.4) and token message (§2.2.6.3).
use crate::{Error, ErrorKind, Result};
use zeroize::Zeroizing;

/// The acquisition workflow advertised by a deferred login, not a credential.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub enum Workflow {
    Password = 1,
    Integrated = 2,
    Interactive = 3,
}

/// Non-secret request evidence produced by the core after verified TLS.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Challenge {
    pub resource: String,
    pub sts_url: Option<String>,
    pub workflow: Option<Workflow>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Info {
    pub resource: String,
    pub sts_url: String,
}

/// Match Python's slicing/replacement-decoding behavior while bounding all
/// reads by this token. Duplicate known fields keep the last value; missing
/// fields remain empty. Review candidates PY-AZ-01 do not establish new policy.
pub(crate) fn read_info(bytes: &[u8]) -> Result<Info> {
    let mut reader = crate::wire::Reader::new(bytes);
    let count = usize::try_from(reader.u32()?)
        .map_err(|_| Error::new(ErrorKind::Limit("FEDAUTHINFO options")))?;
    if count > bytes.len().saturating_sub(4) / 9 {
        return Err(Error::malformed(0, "FEDAUTHINFO option count"));
    }
    let start = 4 + 9 * count;
    let data = &bytes[start..];
    let mut info = Info {
        resource: String::new(),
        sts_url: String::new(),
    };
    for _ in 0..count {
        let id = reader.u8()?;
        let length = i64::from(reader.u32()?);
        let offset = i64::from(reader.u32()?) - start as i64;
        let index = |value: i64| -> usize {
            (if value < 0 {
                data.len() as i64 + value
            } else {
                value
            })
            .clamp(0, data.len() as i64) as usize
        };
        let begin = index(offset);
        let end = index(offset + length).max(begin);
        let raw = &data[begin..end];
        let units = raw
            .as_chunks::<2>()
            .0
            .iter()
            .map(|unit| u16::from_le_bytes(*unit))
            .collect::<Vec<_>>();
        let mut text = String::from_utf16_lossy(&units);
        // Python treats a final high surrogate plus an incomplete next unit
        // as one truncated sequence. Other odd trailing bytes add U+FFFD.
        if !raw.len().is_multiple_of(2)
            && !units
                .last()
                .is_some_and(|unit| (0xd800..=0xdbff).contains(unit))
        {
            text.push('\u{fffd}');
        }
        match id {
            1 => info.sts_url = text,
            2 => info.resource = text,
            _ => {}
        }
    }
    Ok(info)
}

/// Library 2 (MSAL/ADAL), the PRELOGIN echo bit, then the acquisition workflow.
pub fn deferred_feature(workflow: Workflow, echo: bool) -> [u8; 2] {
    [2 << 1 | u8::from(echo), workflow as u8]
}

/// Library 1, echo bit, UTF-16LE token byte length, token, optional server nonce.
/// The driver-owned result erases its bytes when released; the input is borrowed.
pub fn upfront_feature(
    token: &str,
    echo: bool,
    nonce: Option<&[u8; 32]>,
) -> Result<Zeroizing<Vec<u8>>> {
    let length = token_length(token)?;
    let mut out = buffer(5, length, nonce)?;
    out.push(1 << 1 | u8::from(echo));
    out.extend(length.to_le_bytes());
    append_token(&mut out, token);
    if let Some(nonce) = nonce {
        out.extend(nonce);
    }
    Ok(out)
}

/// Packet type 0x08 body: remaining byte length, token byte length, token, nonce.
/// Neither length includes its own four-byte field.
pub fn token_message(token: &str, nonce: Option<&[u8; 32]>) -> Result<Zeroizing<Vec<u8>>> {
    let length = token_length(token)?;
    let body_length = length
        .checked_add(4 + if nonce.is_some() { 32 } else { 0 })
        .ok_or_else(|| Error::new(ErrorKind::Limit("federated token message")))?;
    let mut out = buffer(8, length, nonce)?;
    out.extend(body_length.to_le_bytes());
    out.extend(length.to_le_bytes());
    append_token(&mut out, token);
    if let Some(nonce) = nonce {
        out.extend(nonce);
    }
    Ok(out)
}

fn token_length(token: &str) -> Result<u32> {
    token
        .encode_utf16()
        .count()
        .checked_mul(2)
        .and_then(|n| u32::try_from(n).ok())
        .ok_or_else(|| Error::new(ErrorKind::Limit("federated token length")))
}

fn buffer(prefix: usize, length: u32, nonce: Option<&[u8; 32]>) -> Result<Zeroizing<Vec<u8>>> {
    let capacity = usize::try_from(length)
        .ok()
        .and_then(|n| n.checked_add(prefix))
        .and_then(|n| n.checked_add(if nonce.is_some() { 32 } else { 0 }))
        .ok_or_else(|| Error::new(ErrorKind::Limit("federated token length")))?;
    let mut bytes = Zeroizing::new(Vec::new());
    bytes
        .try_reserve_exact(capacity)
        .map_err(|_| Error::new(ErrorKind::Limit("federated token allocation")))?;
    Ok(bytes)
}

fn append_token(out: &mut Vec<u8>, token: &str) {
    // Write directly into the erasing destination; no unguarded UTF-16 copy.
    for unit in token.encode_utf16() {
        out.extend(unit.to_le_bytes());
    }
}
