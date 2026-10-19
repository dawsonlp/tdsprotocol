//! A variant names its own base type and properties, then the base value without
//! its normal length prefix. Reuse scalar validation; do not invent conversions.
use super::*;
use crate::{Error, ErrorKind, SqlVariant, values::Value};
const LIMIT: usize = 8016;
fn refused() -> Error {
    Error::new(ErrorKind::Parameter(
        "sql_variant requires a supported non-NULL bounded base and at most 8016 bytes",
    ))
}

/// Base code, property bytes, TYPE_INFO byte count, ordinary value prefix count.
fn layout(sql_type: &SqlType) -> Result<(u8, Vec<u8>, usize, usize)> {
    use SqlType::*;
    Ok(match sql_type {
        Integer { size } => (
            match size {
                IntegerSize::Tiny => 0x30,
                IntegerSize::Small => 0x34,
                IntegerSize::Int => 0x38,
                IntegerSize::Big => 0x7f,
            },
            vec![],
            2,
            1,
        ),
        Bit => (0x32, vec![], 2, 1),
        Real => (0x3b, vec![], 2, 1),
        Float => (0x3e, vec![], 2, 1),
        Money => (0x3c, vec![], 2, 1),
        SmallMoney => (0x7a, vec![], 2, 1),
        DateTime => (0x3d, vec![], 2, 1),
        SmallDateTime => (0x3a, vec![], 2, 1),
        Guid => (0x24, vec![], 2, 1),
        Date => (0x28, vec![], 1, 1),
        Time { scale } | DateTime2 { scale } | DateTimeOffset { scale } => (
            match sql_type {
                Time { .. } => 0x29,
                DateTime2 { .. } => 0x2a,
                _ => 0x2b,
            },
            vec![*scale],
            2,
            1,
        ),
        Decimal {
            precision,
            scale,
            numeric,
        } => (
            if *numeric { 0x6c } else { 0x6a },
            vec![*precision, *scale],
            4,
            1,
        ),
        Binary { length, varying } => (
            if *varying { 0xa5 } else { 0xad },
            length.to_le_bytes().to_vec(),
            3,
            2,
        ),
        Character {
            length,
            varying,
            unicode,
            collation,
        } => {
            let n = length
                .checked_mul(if *unicode { 2 } else { 1 })
                .ok_or_else(refused)?;
            let mut props = collation.0.to_vec();
            props.extend(n.to_le_bytes());
            (
                match (unicode, varying) {
                    (true, true) => 0xe7,
                    (true, false) => 0xef,
                    (false, true) => 0xa7,
                    _ => 0xaf,
                },
                props,
                8,
                2,
            )
        }
        _ => return Err(refused()),
    })
}
pub(super) fn encode(value: Option<&Value>) -> Result<Vec<u8>> {
    let mut out = vec![0x62];
    out.extend((LIMIT as u32).to_le_bytes());
    let Some(Value::Variant(variant)) = value else {
        if value.is_none() {
            out.extend([0; 4]);
            return Ok(out);
        }
        return Err(refused());
    };
    let (code, props, info, prefix) = layout(&variant.sql_type)?;
    let encoded = variant.sql_type.encode_parameter(Some(&variant.value))?;
    let payload = &encoded[info + prefix..];
    let total = 2 + props.len() + payload.len();
    if total > LIMIT {
        return Err(refused());
    }
    out.extend((total as u32).to_le_bytes());
    out.extend([code, props.len() as u8]);
    out.extend(props);
    out.extend(payload);
    Ok(out)
}
pub(super) fn read(r: &mut Reader<'_>) -> Result<Option<Value>> {
    let total = r.u32()? as usize;
    if total == 0 {
        return Ok(None);
    }
    if total > LIMIT {
        return Err(Error::malformed(r.offset, "sql_variant value length"));
    }
    let data = r.take(total)?;
    decode(data).map(Some).map_err(|error| match error.kind {
        ErrorKind::Incomplete { offset, .. } => {
            Error::malformed(offset, "truncated bounded sql_variant")
        }
        _ => error,
    })
}
fn decode(data: &[u8]) -> Result<Value> {
    let mut r = Reader::new(data);
    let code = r.u8()?;
    let count = r.u8()? as usize;
    let props = r.take(count)?;
    let mut info = vec![code];
    match code {
        0x30 | 0x34 | 0x38 | 0x7f | 0x32 | 0x3b | 0x3e | 0x3c | 0x7a | 0x3d | 0x3a | 0x24
        | 0x28 => {
            if count != 0 {
                return Err(Error::malformed(0, "sql_variant property count"));
            }
            if code == 0x24 {
                info.push(16);
            }
        }
        0x29..=0x2b => {
            if count != 1 {
                return Err(Error::malformed(0, "sql_variant time properties"));
            }
            info.extend(props);
        }
        0x6a | 0x6c => {
            if count != 2 {
                return Err(Error::malformed(0, "sql_variant decimal properties"));
            }
            info.push(17);
            info.extend(props);
        }
        0xa5 | 0xad => {
            if count != 2 {
                return Err(Error::malformed(0, "sql_variant binary properties"));
            }
            info.extend(props);
        }
        0xa7 | 0xaf | 0xe7 | 0xef => {
            if count != 7 {
                return Err(Error::malformed(0, "sql_variant character properties"));
            }
            info.extend(&props[5..]);
            info.extend(&props[..5]);
        }
        _ => return Err(Error::new(ErrorKind::Unsupported("sql_variant base type"))),
    }
    let mut meta = Reader::new(&info);
    let base = codec::read_info(&mut meta)?;
    meta.end()?;
    let (_, _, _, prefix) =
        layout(&base.sql_type).map_err(|_| Error::malformed(0, "sql_variant base"))?;
    let payload = r.take(r.remaining())?;
    let fixed = [
        0x30, 0x34, 0x38, 0x7f, 0x32, 0x3b, 0x3e, 0x3c, 0x7a, 0x3d, 0x3a,
    ]
    .contains(&code);
    let mut framed = Vec::new();
    if !fixed {
        if prefix == 1 {
            framed.push(
                u8::try_from(payload.len())
                    .map_err(|_| Error::malformed(0, "sql_variant scalar width"))?,
            );
        } else {
            framed.extend((payload.len() as u16).to_le_bytes());
        }
    }
    framed.extend(payload);
    let mut value = Reader::new(&framed);
    let inner = codec::read_value(&base, &mut value)?
        .ok_or_else(|| Error::malformed(0, "NULL inside sql_variant"))?;
    value.end()?;
    Ok(Value::Variant(Box::new(SqlVariant {
        sql_type: base.sql_type,
        value: inner,
    })))
}
