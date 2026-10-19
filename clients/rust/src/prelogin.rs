//! PRELOGIN's directory uses big-endian offsets measured from the message start.
//! Reference: `docs/design/3-reference/prelogin.md`; MS-TDS v20260617 §2.2.6.5.
//! We request full encryption; MARS must be explicitly requested and accepted.

use crate::{Error, ErrorKind, Result, wire::Reader};

pub fn encode() -> Vec<u8> {
    encode_with_mars(false)
}

pub fn encode_with_mars(mars: bool) -> Vec<u8> {
    encode_options(mars, false)
}

pub fn encode_options(mars: bool, federated: bool) -> Vec<u8> {
    let mars = [u8::from(mars)];
    // VERSION, ENCRYPTION, INSTOPT, THREADID, MARS; directory + terminator = 26.
    let mut fields: Vec<(u8, &[u8])> = vec![
        (0, &[0, 1, 0, 0, 0, 0]),
        (1, &[1]),
        (2, &[0]),
        (3, &[0; 4]),
        (4, &mars),
    ];
    if federated {
        fields.push((6, &[1]));
    }
    let mut out = Vec::new();
    let mut offset = (5 * fields.len() + 1) as u16;
    for (tag, bytes) in &fields {
        out.push(*tag);
        out.extend(offset.to_be_bytes());
        out.extend((bytes.len() as u16).to_be_bytes());
        offset += bytes.len() as u16;
    }
    out.push(255);
    for (_, bytes) in fields {
        out.extend(bytes);
    }
    out
}

pub(crate) fn federation_reply(
    bytes: &[u8],
    strict: bool,
    mars: bool,
) -> Result<(bool, Option<[u8; 32]>)> {
    check_reply_with_mars(bytes, strict, mars)?;
    let mut echo = false;
    let mut nonce = None;
    // Directory order need not follow ascending data offsets. The live checker
    // has already verified every range, so read these fields by their offsets.
    let mut directory = Reader::new(bytes);
    while directory.peek() != Some(0xff) {
        let tag = directory.u8()?;
        let offset = usize::from(directory.be16()?);
        let length = usize::from(directory.be16()?);
        let data = &bytes[offset..offset + length];
        match tag {
            6 => {
                if data.len() != 1 {
                    return Err(Error::malformed(0, "FEDAUTHREQUIRED length"));
                }
                echo = data == [1];
            }
            7 => {
                nonce = Some(
                    data.try_into()
                        .map_err(|_| Error::malformed(0, "PRELOGIN nonce length"))?,
                );
            }
            _ => {}
        }
    }
    Ok((echo, nonce))
}

pub fn check_reply(bytes: &[u8], strict: bool) -> Result<()> {
    check_reply_with_mars(bytes, strict, false)
}

pub fn check_reply_with_mars(bytes: &[u8], strict: bool, mars: bool) -> Result<()> {
    let mut accepted_mars = false;
    let mut r = Reader::new(bytes);
    let mut entries = Vec::new();
    let mut seen = [false; 256];
    loop {
        let tag = r.u8()?;
        if tag == 255 {
            break;
        }
        if seen[usize::from(tag)] {
            return Err(Error::malformed(r.offset - 1, "duplicate PRELOGIN option"));
        }
        seen[usize::from(tag)] = true;
        entries.push((tag, usize::from(r.be16()?), usize::from(r.be16()?)));
    }
    let directory_end = r.offset;
    let mut ranges: Vec<_> = entries
        .iter()
        .map(|(_, offset, n)| (*offset, offset.saturating_add(*n)))
        .collect();
    ranges.sort_unstable();
    if ranges.windows(2).any(|pair| pair[0].1 > pair[1].0) {
        return Err(Error::malformed(
            directory_end,
            "overlapping PRELOGIN options",
        ));
    }
    let mut encrypted = false;
    for (tag, offset, n) in entries {
        if offset < directory_end {
            return Err(Error::malformed(offset, "PRELOGIN option offset"));
        }
        let end = offset
            .checked_add(n)
            .ok_or_else(|| Error::malformed(offset, "PRELOGIN option length"))?;
        let data = bytes
            .get(offset..end)
            .ok_or_else(|| Error::malformed(offset, "PRELOGIN option bounds"))?;
        match tag {
            0 if n != 6 => return Err(Error::malformed(offset, "PRELOGIN version")),
            // THREADID is a client field; the server can return an empty entry.
            1 => {
                if n != 1 {
                    return Err(Error::malformed(offset, "PRELOGIN encryption length"));
                }
                if !strict && data != [1] && data != [3] {
                    return Err(Error::new(ErrorKind::Unsupported(
                        "server refused full encryption",
                    )));
                }
                encrypted = true;
            }
            2 if data != [0] => {
                return Err(Error::new(ErrorKind::Unsupported(
                    "server instance mismatch",
                )));
            }
            4 => {
                if data != [0] && data != [1] {
                    return Err(Error::malformed(offset, "PRELOGIN MARS"));
                }
                accepted_mars = data == [1];
            }
            _ => {}
        }
    }
    if !strict && !encrypted {
        return Err(Error::malformed(0, "missing PRELOGIN encryption option"));
    }
    if mars != accepted_mars {
        return Err(Error::new(ErrorKind::Unsupported(if mars {
            "server refused MARS"
        } else {
            "unsolicited MARS"
        })));
    }
    Ok(())
}

/// Read the PRELOGIN directory without imposing a live negotiation policy.
pub(crate) fn read(r: &mut Reader<'_>) -> Result<Vec<(u8, Vec<u8>)>> {
    let mut entries = vec![];
    while r.peek() != Some(0xff) {
        entries.push(r.indexed("option", entries.len() + 1, |r| {
            Ok((
                r.field("tag", |r| r.u8())?,
                usize::from(r.field("offset", |r| r.be16())?),
                usize::from(r.field("length", |r| r.be16())?),
            ))
        })?);
    }
    r.field("terminator", |r| r.u8())?;
    let mut ranges = entries
        .iter()
        .map(|(_, at, n)| (*at, at + n))
        .collect::<Vec<_>>();
    ranges.sort_unstable();
    if ranges.windows(2).any(|p| p[0].1 > p[1].0) {
        return Err(Error::malformed(r.offset, "PRELOGIN overlapping options"));
    }
    let mut result = vec![];
    for (tag, at, n) in entries {
        if at < r.offset || result.iter().any(|(t, _)| *t == tag) {
            return Err(Error::malformed(at, "PRELOGIN option offset/duplicate"));
        }
        let label = match tag {
            0 => "version",
            1 => "encryption",
            2 => "instance",
            3 => "thread id",
            4 => "mars",
            _ => "option data",
        };
        let data = r.at(at, label, |r| {
            match (tag, n) {
                (0, 6) => {
                    r.field("major", |r| r.u8())?;
                    r.field("minor", |r| r.u8())?;
                    r.field("build", |r| r.be16())?;
                    r.field("sub build", |r| r.u16())?;
                }
                (1 | 4, 1) => {
                    r.field("value", |r| r.u8())?;
                }
                (3, 4) => {
                    r.field("value", |r| r.u32())?;
                }
                _ => {
                    r.take(n)?;
                }
            }
            Ok(r.bytes()[at..r.offset].to_vec())
        })?;
        result.push((tag, data));
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn federated_directory_can_list_options_in_a_different_data_order() {
        let mut bytes = encode_options(false, true);
        let first: [u8; 5] = bytes[..5].try_into().unwrap();
        let last: [u8; 5] = bytes[25..30].try_into().unwrap();
        bytes[..5].copy_from_slice(&last);
        bytes[25..30].copy_from_slice(&first);
        assert_eq!(
            federation_reply(&bytes, false, false).unwrap(),
            (true, None)
        );
    }
    #[test]
    fn directory_requires_nonoverlapping_bounded_entries_and_full_encryption() {
        let hello = encode();
        check_reply(&hello, false).unwrap();
        for n in 0..hello.len() {
            assert!(check_reply(&hello[..n], false).is_err());
        }
        let mut overlap = hello.clone();
        overlap[6..8].copy_from_slice(&26_u16.to_be_bytes());
        assert!(matches!(
            check_reply(&overlap, false).unwrap_err().kind,
            ErrorKind::Malformed { .. }
        ));
        let mut off = hello;
        off[32] = 0;
        assert!(matches!(
            check_reply(&off, false).unwrap_err().kind,
            ErrorKind::Unsupported(_)
        ));
        check_reply(&off, true).unwrap(); // 8.0 already runs inside verified TLS.
    }
}
