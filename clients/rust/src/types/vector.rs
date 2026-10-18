//! Vector elements retain IEEE bits. Constructors and writes refuse rounding;
//! the server's element count/layout must agree with TYPE_INFO.
use super::*;
use crate::{Error, ErrorKind, SqlHalf, SqlReal, SqlVector, VectorElement};
pub(super) fn info(r: &mut Reader<'_>) -> Result<(SqlType, u16)> {
    let n = r.u16()?;
    let element = match r.u8()? {
        0 => VectorElement::Float32,
        1 => VectorElement::Float16,
        _ => return Err(Error::malformed(r.offset, "vector element")),
    };
    let bytes = element.bytes();
    if !(8 + bytes..=8000).contains(&usize::from(n)) || !(usize::from(n) - 8).is_multiple_of(bytes)
    {
        return Err(Error::malformed(r.offset, "vector TYPE_INFO width"));
    }
    Ok((
        SqlType::Vector {
            dimensions: ((usize::from(n) - 8) / bytes) as u16,
            element,
        },
        n,
    ))
}
pub(super) fn read(info: &TypeInfo, r: &mut Reader<'_>) -> Result<Option<Value>> {
    let n = r.u16()?;
    if n == u16::MAX {
        return Ok(None);
    }
    let SqlType::Vector {
        dimensions,
        element,
    } = info.sql_type
    else {
        unreachable!()
    };
    if usize::from(n) != 8 + usize::from(dimensions) * element.bytes() {
        return Err(Error::malformed(r.offset, "vector payload width"));
    }
    let b = r.take(usize::from(n))?;
    if b[..2] != [0xa9, 1]
        || u16::from_le_bytes([b[2], b[3]]) != dimensions
        || b[4] != element as u8
        || b[5..8] != [0, 0, 0]
    {
        return Err(Error::malformed(
            r.offset,
            "vector layout/count/element/reserved",
        ));
    }
    Ok(Some(Value::Vector(match element {
        VectorElement::Float32 => SqlVector::Float32(
            b[8..]
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| SqlReal::from_bits(u32::from_le_bytes(*b)))
                .collect(),
        ),
        VectorElement::Float16 => SqlVector::Float16(
            b[8..]
                .as_chunks::<2>()
                .0
                .iter()
                .map(|b| SqlHalf::from_bits(u16::from_le_bytes(*b)))
                .collect(),
        ),
    })))
}
pub(super) fn encode(
    dimensions: u16,
    element: VectorElement,
    value: Option<&Value>,
) -> Result<Vec<u8>> {
    let invalid = || {
        Error::new(ErrorKind::Parameter(
            "vector dimension/element/value mismatch, nonfinite element or size exceeds 8000",
        ))
    };
    let size = 8 + usize::from(dimensions) * element.bytes();
    if dimensions == 0 || size > 8000 {
        return Err(invalid());
    }
    let mut b = vec![0xf5];
    b.extend((size as u16).to_le_bytes());
    b.push(element as u8);
    let Some(Value::Vector(vector)) = value else {
        if value.is_none() {
            b.extend(u16::MAX.to_le_bytes());
            return Ok(b);
        }
        return Err(invalid());
    };
    let mut payload = vec![0xa9, 1];
    payload.extend(dimensions.to_le_bytes());
    payload.extend([element as u8, 0, 0, 0]);
    match (element, vector) {
        (VectorElement::Float32, SqlVector::Float32(values))
            if values.len() == usize::from(dimensions) =>
        {
            for n in values {
                if !n.to_float().is_finite() {
                    return Err(invalid());
                }
                payload.extend(n.bits().to_le_bytes());
            }
        }
        (VectorElement::Float16, SqlVector::Float16(values))
            if values.len() == usize::from(dimensions) =>
        {
            for n in values {
                if !n.is_finite() {
                    return Err(invalid());
                }
                payload.extend(n.bits().to_le_bytes());
            }
        }
        _ => return Err(invalid()),
    }
    b.extend((size as u16).to_le_bytes());
    b.extend(payload);
    Ok(b)
}
