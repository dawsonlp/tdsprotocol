//! SqlClient normalization version one, checked against the original declaration.
use super::{Error, Plaintext, Result, secret::Secret};
use crate::{IntegerSize, SqlType, TypeInfo, Value, wire::Reader};
use zeroize::Zeroizing;

fn widest(base: &SqlType) -> Result<SqlType> {
    use SqlType::*;
    Ok(match base {
        Integer { .. } | Bit => Integer {
            size: IntegerSize::Big,
        },
        Money | SmallMoney => Money,
        Decimal { scale, numeric, .. } => Decimal {
            precision: 38,
            scale: *scale,
            numeric: *numeric,
        },
        Time { .. } => Time { scale: 7 },
        DateTime2 { .. } => DateTime2 { scale: 7 },
        DateTimeOffset { .. } => DateTimeOffset { scale: 7 },
        Real
        | Float
        | Date
        | DateTime
        | SmallDateTime
        | Guid
        | Character { .. }
        | CharacterMax { .. }
        | Binary { .. }
        | BinaryMax => base.clone(),
        _ => return Err(Error::InvalidMetadata),
    })
}
/// Normalize only after validating the value's declared range, precision and scale.
/// The returned allocation and temporary serialized values are erased on Drop.
pub fn normalize(base: &SqlType, value: &Value) -> Result<Plaintext> {
    let wide = widest(base)?;
    let _validated = Zeroizing::new(
        base.encode_parameter(Some(value))
            .map_err(|_| Error::InvalidValue)?,
    );
    let bytes = match value {
        Value::Unicode(text)
            if matches!(
                base,
                SqlType::Character { .. } | SqlType::CharacterMax { .. }
            ) =>
        {
            Zeroizing::new(text.0.iter().flat_map(|u| u.to_le_bytes()).collect())
        }
        Value::Text(text)
            if matches!(
                base,
                SqlType::Character { .. } | SqlType::CharacterMax { .. }
            ) =>
        {
            Zeroizing::new(text.bytes.clone())
        }
        Value::Binary(bytes) if matches!(base, SqlType::Binary { .. } | SqlType::BinaryMax) => {
            Zeroizing::new(bytes.clone())
        }
        _ => {
            let bit = if let Value::Bit(bit) = value {
                Some(Value::Integer(i64::from(*bit)))
            } else {
                None
            };
            let encoded = Zeroizing::new(
                wide.encode_parameter(Some(bit.as_ref().unwrap_or(value)))
                    .map_err(|_| Error::InvalidValue)?,
            );
            let mut r = Reader::new(&encoded);
            TypeInfo::read_parameter(&mut r).map_err(|_| Error::InvalidValue)?;
            let n = usize::from(r.u8().map_err(|_| Error::InvalidValue)?);
            let mut bytes = Zeroizing::new(r.take(n).map_err(|_| Error::InvalidValue)?.to_vec());
            if matches!(base, SqlType::Decimal { .. }) {
                bytes.resize(17, 0);
            }
            bytes
        }
    };
    if bytes.len() > 16 * 1024 * 1024 {
        return Err(Error::ValueTooLarge);
    }
    Ok(Plaintext {
        length: bytes.len(),
        storage: Secret::copy(&bytes),
    })
}
/// Decode authenticated bytes and recheck the original declaration. Fixed text
/// and binary columns receive the same padding as unencrypted SQL results.
pub fn denormalize(base: &SqlType, plaintext: &[u8]) -> Result<Value> {
    use crate::values::{SqlText, SqlTextBytes};
    use SqlType::*;
    let wide = widest(base)?;
    let mut value = match base {
        Character { unicode: true, .. } | CharacterMax { unicode: true, .. } => {
            if !plaintext.len().is_multiple_of(2) {
                return Err(Error::InvalidValue);
            }
            Value::Unicode(SqlText(
                plaintext
                    .as_chunks::<2>()
                    .0
                    .iter()
                    .map(|b| u16::from_le_bytes(*b))
                    .collect(),
            ))
        }
        Character { collation, .. } | CharacterMax { collation, .. } => Value::Text(SqlTextBytes {
            bytes: plaintext.to_vec(),
            collation: *collation,
        }),
        Binary { .. } | BinaryMax => Value::Binary(plaintext.to_vec()),
        _ => {
            let encoded = wide
                .encode_parameter(None)
                .map_err(|_| Error::InvalidValue)?;
            let mut r = Reader::new(&encoded);
            let info = TypeInfo::read_parameter(&mut r).map_err(|_| Error::InvalidValue)?;
            let mut framed = Zeroizing::new(vec![
                u8::try_from(plaintext.len()).map_err(|_| Error::InvalidValue)?,
            ]);
            framed.extend_from_slice(plaintext);
            let mut r = Reader::new(&framed);
            let value = info
                .read_value(&mut r)
                .map_err(|_| Error::InvalidValue)?
                .ok_or(Error::InvalidValue)?;
            r.end().map_err(|_| Error::InvalidValue)?;
            if matches!(base, Bit) {
                match value {
                    Value::Integer(0) => Value::Bit(false),
                    Value::Integer(1) => Value::Bit(true),
                    _ => return Err(Error::InvalidValue),
                }
            } else {
                value
            }
        }
    };
    let _validated = Zeroizing::new(
        base.encode_parameter(Some(&value))
            .map_err(|_| Error::InvalidValue)?,
    );
    match (base, &mut value) {
        (
            Character {
                length,
                varying: false,
                unicode: true,
                ..
            },
            Value::Unicode(text),
        ) => text.0.resize(usize::from(*length), 32),
        (
            Character {
                length,
                varying: false,
                ..
            },
            Value::Text(text),
        ) => text.bytes.resize(usize::from(*length), 32),
        (
            Binary {
                length,
                varying: false,
            },
            Value::Binary(bytes),
        ) => bytes.resize(usize::from(*length), 0),
        _ => {}
    }
    Ok(value)
}
