//! Scalar RPC encoding: validate the declaration and exact payload before send.
//! Nullable RPC forms are used even when a non-NULL input was supplied. NULL and
//! DEFAULT therefore need no guessed type. No implicit rounding or text codec.
use super::*;
use crate::{Error, ErrorKind, values::*};

fn refused(reason: &'static str) -> Error {
    Error::new(ErrorKind::Parameter(reason))
}
fn exact<T>(value: std::result::Result<T, ValueError>) -> Result<T> {
    value.map_err(|e| refused(e.0))
}
fn time_size(scale: u8) -> usize {
    if scale <= 2 {
        3
    } else if scale <= 4 {
        4
    } else {
        5
    }
}
fn decimal_size(precision: u8) -> u8 {
    match precision {
        1..=9 => 5,
        10..=19 => 9,
        20..=28 => 13,
        _ => 17,
    }
}
fn low(bytes: &[u8], count: usize, output: &mut Vec<u8>) {
    output.extend_from_slice(&bytes[..count]);
}

impl SqlType {
    /// Complete TYPE_INFO and scalar value, without parameter name/status.
    /// This pure operation either succeeds in full or returns a safe reason.
    pub fn encode_parameter(&self, value: Option<&Value>) -> Result<Vec<u8>> {
        use SqlType::*;
        if let Vector {
            dimensions,
            element,
        } = self
        {
            return super::vector::encode(*dimensions, *element, value);
        }
        if matches!(self, Variant) {
            return super::variant::encode(value);
        }
        if let SqlType::Table(table) = self {
            return if value.is_none() {
                table.encode(None)
            } else {
                Err(refused("use a table-valued ParamValue for rows"))
            };
        }
        if self.is_large() {
            return large_parameter(self, value);
        }
        let mut output = Vec::new();
        let width = match *self {
            Vector { .. }
            | Table(_)
            | Json
            | Variant
            | CharacterMax { .. }
            | BinaryMax
            | Clr(_)
            | Xml { .. }
            | LegacyText { .. }
            | LegacyImage => {
                unreachable!()
            }
            Integer { size } => {
                output.extend([0x26, size.bytes()]);
                usize::from(size.bytes())
            }
            Bit => {
                output.extend([0x68, 1]);
                1
            }
            Real => {
                output.extend([0x6d, 4]);
                4
            }
            Float => {
                output.extend([0x6d, 8]);
                8
            }
            Money => {
                output.extend([0x6e, 8]);
                8
            }
            SmallMoney => {
                output.extend([0x6e, 4]);
                4
            }
            DateTime => {
                output.extend([0x6f, 8]);
                8
            }
            SmallDateTime => {
                output.extend([0x6f, 4]);
                4
            }
            Guid => {
                output.extend([0x24, 16]);
                16
            }
            Decimal {
                precision,
                scale,
                numeric,
            } => {
                if !(1..=38).contains(&precision) || scale > precision {
                    return Err(refused("decimal precision/scale"));
                }
                let size = decimal_size(precision);
                output.extend([if numeric { 0x6c } else { 0x6a }, size, precision, scale]);
                usize::from(size)
            }
            Date => {
                output.push(0x28);
                3
            }
            Time { scale } | DateTime2 { scale } | DateTimeOffset { scale } => {
                if scale > 7 {
                    return Err(refused("time scale exceeds 7"));
                }
                output.extend([
                    match self {
                        Time { .. } => 0x29,
                        DateTime2 { .. } => 0x2a,
                        _ => 0x2b,
                    },
                    scale,
                ]);
                time_size(scale)
                    + match self {
                        Time { .. } => 0,
                        DateTime2 { .. } => 3,
                        _ => 5,
                    }
            }
            Character {
                length,
                varying,
                unicode,
                collation,
            } => {
                if length == 0 || length > if unicode { 4000 } else { 8000 } {
                    return Err(refused("bounded character length"));
                }
                output.push(match (unicode, varying) {
                    (true, true) => 0xe7,
                    (true, false) => 0xef,
                    (false, true) => 0xa7,
                    _ => 0xaf,
                });
                output.extend((length * if unicode { 2 } else { 1 }).to_le_bytes());
                output.extend(collation.0);
                let payload = match value {
                    None => None,
                    Some(Value::Unicode(text)) if unicode => Some(
                        text.0
                            .iter()
                            .flat_map(|n| n.to_le_bytes())
                            .collect::<Vec<_>>(),
                    ),
                    Some(Value::Text(text)) if !unicode && text.collation == collation => {
                        Some(text.bytes.clone())
                    }
                    _ => {
                        return Err(refused(
                            "character value or collation differs from declared type",
                        ));
                    }
                };
                variable(
                    payload,
                    usize::from(length) * if unicode { 2 } else { 1 },
                    &mut output,
                )?;
                return Ok(output);
            }
            Binary { length, varying } => {
                if !(1..=8000).contains(&length) {
                    return Err(refused("bounded binary length"));
                }
                output.push(if varying { 0xa5 } else { 0xad });
                output.extend(length.to_le_bytes());
                let payload = match value {
                    None => None,
                    Some(Value::Binary(bytes)) => Some(bytes.clone()),
                    _ => return Err(refused("binary requires bytes")),
                };
                variable(payload, usize::from(length), &mut output)?;
                return Ok(output);
            }
        };
        let Some(value) = value else {
            output.push(0);
            return Ok(output);
        };
        output.push(width as u8);
        match (self, value) {
            (Integer { size }, Value::Integer(number)) => {
                let fits = match size {
                    IntegerSize::Tiny => u8::try_from(*number).is_ok(),
                    IntegerSize::Small => i16::try_from(*number).is_ok(),
                    IntegerSize::Int => i32::try_from(*number).is_ok(),
                    IntegerSize::Big => true,
                };
                if !fits {
                    return Err(refused("integer outside declared range"));
                }
                low(&number.to_le_bytes(), width, &mut output);
            }
            (Bit, Value::Bit(bit)) => output.push(u8::from(*bit)),
            (Real, Value::Real(number)) => {
                if !number.to_float().is_finite() {
                    return Err(refused("SQL real must be finite"));
                }
                output.extend(number.bits().to_le_bytes());
            }
            (Float, Value::Float(number)) => {
                if !number.to_float().is_finite() {
                    return Err(refused("SQL float must be finite"));
                }
                output.extend(number.bits().to_le_bytes());
            }
            (
                Decimal {
                    precision, scale, ..
                },
                Value::Decimal(number),
            ) => {
                let number = exact(number.rescale_exact(*scale))?;
                if number.magnitude() >= 10_u128.pow(u32::from(*precision)) {
                    return Err(refused("decimal exceeds declared precision"));
                }
                output.push(u8::from(!number.is_negative()));
                // TYPE_INFO advertises the precision's maximum, while each
                // value uses its smallest 4/8/12/16-byte magnitude, as Python.
                let size = [4, 8, 12, 16]
                    .into_iter()
                    .find(|n| *n == 16 || number.magnitude() < (1_u128 << (8 * n)))
                    .unwrap();
                let prefix = output.len() - 2;
                output[prefix] = (size + 1) as u8;
                low(&number.magnitude().to_le_bytes(), size, &mut output);
            }
            (Money, Value::Money(number)) => {
                output.extend(((number.0 >> 32) as i32).to_le_bytes());
                output.extend((number.0 as u32).to_le_bytes());
            }
            (SmallMoney, Value::Money(number)) => {
                let number = i32::try_from(number.0)
                    .map_err(|_| refused("smallmoney outside declared range"))?;
                output.extend(number.to_le_bytes());
            }
            (Guid, Value::Guid(guid)) => output.extend(guid.to_wire()),
            (Date, Value::Date(date)) => low(&date.days().to_le_bytes(), 3, &mut output),
            (Time { scale }, Value::Time(time)) => clock(*time, *scale, &mut output)?,
            (DateTime2 { scale }, Value::DateTime2(value)) => {
                date_time(*value, *scale, &mut output)?
            }
            (DateTimeOffset { scale }, Value::DateTimeOffset(value)) => {
                date_time(value.utc(), *scale, &mut output)?;
                output.extend(value.offset_minutes().to_le_bytes());
            }
            (DateTime, Value::DateTime(value)) => {
                output.extend(value.days().to_le_bytes());
                output.extend(value.ticks().to_le_bytes());
            }
            (SmallDateTime, Value::SmallDateTime(value)) => {
                output.extend(value.days().to_le_bytes());
                output.extend(value.minutes().to_le_bytes());
            }
            _ => return Err(refused("value does not match its declared SQL type")),
        }
        Ok(output)
    }
}
fn variable(payload: Option<Vec<u8>>, maximum: usize, output: &mut Vec<u8>) -> Result<()> {
    match payload {
        None => output.extend(0xffff_u16.to_le_bytes()),
        Some(bytes) => {
            if bytes.len() > maximum {
                return Err(refused("value exceeds declared maximum length"));
            }
            output.extend((bytes.len() as u16).to_le_bytes());
            output.extend(bytes);
        }
    }
    Ok(())
}
fn clock(time: SqlTime, scale: u8, output: &mut Vec<u8>) -> Result<()> {
    low(
        &exact(time.at_scale(scale))?.to_le_bytes(),
        time_size(scale),
        output,
    );
    Ok(())
}
fn date_time(value: SqlDateTime2, scale: u8, output: &mut Vec<u8>) -> Result<()> {
    clock(value.time, scale, output)?;
    low(&value.date.days().to_le_bytes(), 3, output);
    Ok(())
}

/// PLP declarations, shared by owned and incremental request encoding.
pub(crate) fn large_info(sql_type: &SqlType) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    match sql_type {
        SqlType::Json => bytes.push(0xf4),
        SqlType::BinaryMax => bytes.extend([0xa5, 0xff, 0xff]),
        SqlType::Clr(name) => {
            bytes.push(0xf0);
            for part in [&name.database, &name.schema, &name.name] {
                bytes.push(
                    u8::try_from(part.0.len())
                        .map_err(|_| refused("CLR name exceeds 255 UTF-16 units"))?,
                );
                bytes.extend(part.0.iter().flat_map(|n| n.to_le_bytes()));
            }
        }
        SqlType::CharacterMax { unicode, collation } => {
            bytes.extend([if *unicode { 0xe7 } else { 0xa7 }, 0xff, 0xff]);
            bytes.extend(collation.0);
        }
        // Like Python, inputs use untyped XML text. Received schema collection
        // names remain metadata; the procedure/column enforces its schema.
        SqlType::Xml { .. } => bytes.extend([0xf1, 0]),
        _ => return Err(refused("streamed parameters require a PLP declaration")),
    }
    Ok(bytes)
}
fn large_parameter(sql_type: &SqlType, value: Option<&Value>) -> Result<Vec<u8>> {
    let legacy = matches!(sql_type, SqlType::LegacyText { .. } | SqlType::LegacyImage);
    let mut output = if legacy {
        let mut info = vec![match sql_type {
            SqlType::LegacyText { unicode: true, .. } => 0x63,
            SqlType::LegacyText { .. } => 0x23,
            _ => 0x22,
        }];
        info.extend(i32::MAX.to_le_bytes());
        if let SqlType::LegacyText { collation, .. } = sql_type {
            info.extend(collation.0);
        }
        info
    } else {
        large_info(sql_type)?
    };
    let Some(value) = value else {
        if legacy {
            output.extend(u32::MAX.to_le_bytes());
        } else {
            output.extend(u64::MAX.to_le_bytes());
        }
        return Ok(output);
    };
    let bytes: Vec<u8> = match (sql_type, value) {
        (SqlType::Json, Value::Unicode(text)) => json_bytes(text)?,
        (t, Value::Unicode(text)) if t.is_unicode() => {
            text.0.iter().flat_map(|n| n.to_le_bytes()).collect()
        }
        (
            SqlType::CharacterMax {
                unicode: false,
                collation,
            }
            | SqlType::LegacyText {
                unicode: false,
                collation,
            },
            Value::Text(text),
        ) if *collation == text.collation => text.bytes.clone(),
        (SqlType::BinaryMax | SqlType::LegacyImage | SqlType::Clr(_), Value::Binary(bytes)) => {
            bytes.clone()
        }
        _ => {
            return Err(refused(
                "large value does not match declared type/collation",
            ));
        }
    };
    if legacy {
        let count = i32::try_from(bytes.len())
            .map_err(|_| refused("legacy value exceeds signed 32-bit length"))?;
        output.extend(count.to_le_bytes());
        output.extend(bytes);
    } else {
        output.extend((bytes.len() as u64).to_le_bytes());
        for part in bytes.chunks(65536) {
            output.extend((part.len() as u32).to_le_bytes());
            output.extend(part);
        }
        output.extend(0_u32.to_le_bytes());
    }
    Ok(output)
}

/// JSON parameters use strict UTF-8 even on a UTF-16 result connection.
pub(crate) fn json_bytes(text: &crate::SqlText) -> Result<Vec<u8>> {
    text.to_string()
        .map(String::into_bytes)
        .map_err(|_| refused("JSON input cannot hold unpaired UTF-16 surrogates"))
}
