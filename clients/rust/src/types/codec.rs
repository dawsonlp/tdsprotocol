//! Scalar TYPE_INFO and row payloads, read transactionally by the token decoder.
//! Mirrors Python `tds.types`: length-prefixed scalars use zero for NULL;
//! bounded text/binary use FFFF, and NBCROW omits NULL payloads altogether.
use super::*;
use crate::{Error, ErrorKind, values::*};

fn malformed(r: &Reader<'_>, field: &'static str) -> Error {
    Error::malformed(r.offset, field)
}
fn width(r: &mut Reader<'_>, allowed: &[u8]) -> Result<u8> {
    let n = r.u8()?;
    if !allowed.contains(&n) {
        return Err(malformed(r, "TYPE_INFO width"));
    }
    Ok(n)
}
fn integer(n: u8) -> IntegerSize {
    match n {
        1 => IntegerSize::Tiny,
        2 => IntegerSize::Small,
        4 => IntegerSize::Int,
        8 => IntegerSize::Big,
        _ => unreachable!("checked width"),
    }
}
pub(super) fn read_info(r: &mut Reader<'_>) -> Result<TypeInfo> {
    read_info_for(r, false)
}
pub(super) fn read_info_for(r: &mut Reader<'_>, parameter: bool) -> Result<TypeInfo> {
    let code = r.u8()?;
    let mut max_length = None;
    let mut legacy = None;
    let mut clr_assembly = None;
    let mut sized = |r: &mut Reader<'_>, allowed: &[u8]| -> Result<u8> {
        let n = width(r, allowed)?;
        max_length = Some(u16::from(n));
        Ok(n)
    };
    let sql_type = match code {
        0xf4 => SqlType::Json,
        0x30 | 0x34 | 0x38 | 0x7f => SqlType::Integer {
            size: integer(match code {
                0x30 => 1,
                0x34 => 2,
                0x38 => 4,
                _ => 8,
            }),
        },
        0x26 => SqlType::Integer {
            size: integer(sized(r, &[1, 2, 4, 8])?),
        },
        0x32 => SqlType::Bit,
        0x68 => {
            sized(r, &[1])?;
            SqlType::Bit
        }
        0x3b => SqlType::Real,
        0x3e => SqlType::Float,
        0x6d => {
            if sized(r, &[4, 8])? == 4 {
                SqlType::Real
            } else {
                SqlType::Float
            }
        }
        0x3c => SqlType::Money,
        0x7a => SqlType::SmallMoney,
        0x6e => {
            if sized(r, &[4, 8])? == 4 {
                SqlType::SmallMoney
            } else {
                SqlType::Money
            }
        }
        0x3d => SqlType::DateTime,
        0x3a => SqlType::SmallDateTime,
        0x6f => {
            if sized(r, &[4, 8])? == 4 {
                SqlType::SmallDateTime
            } else {
                SqlType::DateTime
            }
        }
        0x6a | 0x6c => {
            sized(r, &[5, 9, 13, 17])?;
            let (precision, scale) = (r.u8()?, r.u8()?);
            if !(1..=38).contains(&precision) || scale > precision {
                return Err(malformed(r, "decimal precision/scale"));
            }
            SqlType::Decimal {
                precision,
                scale,
                numeric: code == 0x6c,
            }
        }
        0x28 => SqlType::Date,
        0x29..=0x2b => {
            let scale = r.u8()?;
            if scale > 7 {
                return Err(malformed(r, "time scale"));
            }
            match code {
                0x29 => SqlType::Time { scale },
                0x2a => SqlType::DateTime2 { scale },
                _ => SqlType::DateTimeOffset { scale },
            }
        }
        0x24 => {
            sized(r, &[16])?;
            SqlType::Guid
        }
        0xa5 | 0xad | 0xa7 | 0xaf | 0xe7 | 0xef => {
            let length = r.u16()?;
            if length > 8000 && (length != 0xffff || ![0xa5, 0xa7, 0xe7].contains(&code)) {
                return Err(malformed(r, "character/binary maximum length"));
            }
            max_length = Some(length);
            if [0xa5, 0xad].contains(&code) {
                if length == 0xffff {
                    SqlType::BinaryMax
                } else {
                    SqlType::Binary {
                        length,
                        varying: code == 0xa5,
                    }
                }
            } else {
                let unicode = code == 0xe7 || code == 0xef;
                if unicode && length != 0xffff && !length.is_multiple_of(2) {
                    return Err(malformed(r, "Unicode maximum byte length"));
                }
                let collation = Collation(r.take(5)?.try_into().expect("five bytes"));
                if length == 0xffff {
                    SqlType::CharacterMax { unicode, collation }
                } else {
                    SqlType::Character {
                        length: if unicode { length / 2 } else { length },
                        varying: code == 0xa7 || code == 0xe7,
                        unicode,
                        collation,
                    }
                }
            }
        }
        0xf5 => {
            let (sql_type, n) = super::vector::info(r)?;
            max_length = Some(n);
            sql_type
        }
        0x62 => {
            let n = r.u32()?;
            if n > 8016 {
                return Err(malformed(r, "sql_variant maximum length"));
            }
            max_length = Some(n as u16);
            SqlType::Variant
        }
        0xf0 => {
            if !parameter {
                max_length = Some(r.u16()?);
            }
            let name = ClrType {
                database: sql_text(r, false)?,
                schema: sql_text(r, false)?,
                name: sql_text(r, false)?,
            };
            if !parameter {
                clr_assembly = Some(sql_text(r, true)?);
            }
            SqlType::Clr(Box::new(name))
        }
        0xf1 => {
            let schema = match r.u8()? {
                0 => None,
                1 => Some(XmlSchema {
                    database: sql_text(r, false)?,
                    owner: sql_text(r, false)?,
                    collection: sql_text(r, true)?,
                }),
                _ => return Err(malformed(r, "XML schema presence")),
            };
            SqlType::Xml { schema }
        }
        0x22 | 0x23 | 0x63 => {
            let maximum = r.u32()?;
            let collation = if code == 0x22 {
                None
            } else {
                Some(Collation(r.take(5)?.try_into().unwrap()))
            };
            let count = if parameter { 0 } else { r.u8()? };
            let mut table = Vec::new();
            for _ in 0..count {
                table.push(sql_text(r, true)?);
            }
            legacy = Some(LegacyMetadata {
                max_length: maximum,
                table,
            });
            if let Some(collation) = collation {
                SqlType::LegacyText {
                    unicode: code == 0x63,
                    collation,
                }
            } else {
                SqlType::LegacyImage
            }
        }
        _ => return Err(Error::new(ErrorKind::Unsupported("result TYPE_INFO"))),
    };
    Ok(TypeInfo {
        sql_type,
        code,
        max_length,
        legacy,
        clr_assembly,
        json_utf8: parameter && code == 0xf4,
    })
}
fn sql_text(r: &mut Reader<'_>, long: bool) -> Result<SqlText> {
    let count = if long {
        usize::from(r.u16()?)
    } else {
        usize::from(r.u8()?)
    };
    Ok(SqlText(
        r.take(count * 2)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect(),
    ))
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
fn unsigned(r: &mut Reader<'_>, n: usize) -> Result<u64> {
    let mut bytes = [0; 8];
    bytes[..n].copy_from_slice(r.take(n)?);
    Ok(u64::from_le_bytes(bytes))
}
fn checked<T>(value: std::result::Result<T, ValueError>, r: &Reader<'_>) -> Result<T> {
    value.map_err(|e| malformed(r, e.0))
}
fn date(r: &mut Reader<'_>) -> Result<SqlDate> {
    let n = unsigned(r, 3)?;
    checked(SqlDate::from_days(n as u32), r)
}
fn clock(r: &mut Reader<'_>, scale: u8) -> Result<SqlTime> {
    let ticks = unsigned(r, time_size(scale))? * 10_u64.pow(u32::from(7 - scale));
    checked(SqlTime::from_ticks(ticks), r)
}
pub(super) fn read_value(info: &TypeInfo, r: &mut Reader<'_>) -> Result<Option<Value>> {
    use SqlType::*;
    let expected = match &info.sql_type {
        Table(_) => {
            return Err(Error::new(ErrorKind::Unsupported(
                "table parameters cannot be result cells",
            )));
        }
        Vector { .. } => return super::vector::read(info, r),
        Variant => return super::variant::read(r),
        Integer { size } => usize::from(size.bytes()),
        Bit => 1,
        Real | SmallMoney | SmallDateTime => 4,
        Float | Money | DateTime => 8,
        Guid => 16,
        Date => 3,
        Time { scale } => time_size(*scale),
        DateTime2 { scale } => time_size(*scale) + 3,
        DateTimeOffset { scale } => time_size(*scale) + 5,
        Decimal { .. } => 0,
        Json
        | CharacterMax { .. }
        | BinaryMax
        | Clr(_)
        | Xml { .. }
        | LegacyText { .. }
        | LegacyImage => {
            return Err(Error::new(ErrorKind::Unsupported(
                "large value requires incremental reader",
            )));
        }
        Character { .. } | Binary { .. } => {
            let n = r.u16()?;
            if n == 0xffff {
                return Ok(None);
            }
            if Some(n) > info.max_length {
                return Err(malformed(r, "value exceeds TYPE_INFO length"));
            }
            let data = r.take(usize::from(n))?;
            return Ok(Some(match &info.sql_type {
                Character { unicode: true, .. } => {
                    if !data.len().is_multiple_of(2) {
                        return Err(malformed(r, "odd Unicode byte length"));
                    }
                    Value::Unicode(SqlText(
                        data.as_chunks::<2>()
                            .0
                            .iter()
                            .map(|b| u16::from_le_bytes(*b))
                            .collect(),
                    ))
                }
                Character { collation, .. } => Value::Text(SqlTextBytes {
                    bytes: data.to_vec(),
                    collation: *collation,
                }),
                _ => Value::Binary(data.to_vec()),
            }));
        }
    };
    let fixed = [
        0x30, 0x34, 0x38, 0x7f, 0x32, 0x3b, 0x3e, 0x3c, 0x7a, 0x3d, 0x3a,
    ]
    .contains(&info.code);
    let n = if fixed {
        expected
    } else {
        usize::from(r.u8()?)
    };
    if n == 0 && !fixed {
        return Ok(None);
    }
    if let Decimal {
        precision, scale, ..
    } = info.sql_type
    {
        if ![5, 9, 13, 17].contains(&n) || n > usize::from(info.max_length.unwrap_or(0)) {
            return Err(malformed(r, "decimal value length"));
        }
        let sign = r.u8()?;
        if sign > 1 {
            return Err(malformed(r, "decimal sign"));
        }
        let mut bytes = [0; 16];
        bytes[..n - 1].copy_from_slice(r.take(n - 1)?);
        let magnitude = u128::from_le_bytes(bytes);
        if magnitude >= 10_u128.pow(u32::from(precision)) {
            return Err(malformed(r, "decimal value exceeds precision"));
        }
        return Ok(Some(Value::Decimal(checked(
            SqlDecimal::new(sign == 0, magnitude, scale),
            r,
        )?)));
    }
    if n != expected {
        return Err(malformed(r, "scalar value length"));
    }
    let value = match info.sql_type {
        Integer { size } => {
            let bytes = r.take(n)?;
            let value = if size == IntegerSize::Tiny {
                i64::from(bytes[0])
            } else {
                let mut signed = if bytes[n - 1] & 0x80 != 0 {
                    [0xff; 8]
                } else {
                    [0; 8]
                };
                signed[..n].copy_from_slice(bytes);
                i64::from_le_bytes(signed)
            };
            Value::Integer(value)
        }
        Bit => Value::Bit(r.u8()? != 0),
        Real => Value::Real(SqlReal::from_bits(r.u32()?)),
        Float => Value::Float(SqlFloat::from_bits(unsigned(r, 8)?)),
        SmallMoney => Value::Money(SqlMoney(i64::from(r.u32()? as i32))),
        Money => {
            let high = i64::from(r.u32()? as i32);
            let low = i64::from(r.u32()?);
            Value::Money(SqlMoney((high << 32) | low))
        }
        Guid => Value::Guid(SqlGuid::from_wire(
            r.take(16)?.try_into().expect("sixteen bytes"),
        )),
        Date => Value::Date(date(r)?),
        Time { scale } => Value::Time(clock(r, scale)?),
        DateTime2 { scale } => {
            let time = clock(r, scale)?;
            Value::DateTime2(SqlDateTime2 {
                date: date(r)?,
                time,
            })
        }
        DateTimeOffset { scale } => {
            let time = clock(r, scale)?;
            let date = date(r)?;
            let offset = r.u16()? as i16;
            Value::DateTimeOffset(checked(
                SqlDateTimeOffset::new(SqlDateTime2 { date, time }, offset),
                r,
            )?)
        }
        DateTime => {
            let days = r.u32()? as i32;
            let ticks = r.u32()?;
            Value::DateTime(checked(SqlDateTime::new(days, ticks), r)?)
        }
        SmallDateTime => {
            let days = r.u16()?;
            let minutes = r.u16()?;
            Value::SmallDateTime(checked(SqlSmallDateTime::new(days, minutes), r)?)
        }
        _ => unreachable!("variable-width types returned above"),
    };
    Ok(Some(value))
}
