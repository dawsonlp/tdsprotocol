//! CLI text conversion is explicit about SQL types. The library still performs
//! its own complete declaration/value validation before sending any request.
use super::Result;
use tds_client::{Collation, IntegerSize, Param, SqlType, Value, values::*};

pub(super) fn parse(kind: &str, spec: &str, collation: Collation) -> Result<Param> {
    let (head, value) = match kind {
        "--param" | "--output" => {
            let (head, value) = spec
                .split_once('=')
                .ok_or("parameter requires NAME:TYPE=VALUE")?;
            (head, Some(value))
        }
        _ => (spec, None),
    };
    let (name, declaration) = head.split_once(':').ok_or("parameter requires NAME:TYPE")?;
    let (base, args) = if let Some((base, tail)) = declaration.split_once('(') {
        (
            base,
            tail.strip_suffix(')')
                .ok_or("type declaration requires closing parenthesis")?
                .split(',')
                .map(str::trim)
                .collect::<Vec<_>>(),
        )
    } else {
        (declaration, Vec::new())
    };
    // SQL keywords are insensitive; CLR database/schema/type identities need
    // their original spelling on a case-sensitive server.
    let base = base.to_ascii_lowercase();
    let base = base.as_str();
    let one = |default: u8| -> Result<u8> {
        if args.len() > 1 {
            return Err("type takes one scale".into());
        }
        Ok(if args.is_empty() {
            default
        } else {
            args[0].parse()?
        })
    };
    let length = || -> Result<u16> {
        if args.len() != 1 {
            return Err("type requires one bounded length".into());
        }
        Ok(args[0].parse()?)
    };
    let sql_type = match base {
        "tinyint" => SqlType::Integer {
            size: IntegerSize::Tiny,
        },
        "smallint" => SqlType::Integer {
            size: IntegerSize::Small,
        },
        "int" => SqlType::Integer {
            size: IntegerSize::Int,
        },
        "bigint" => SqlType::Integer {
            size: IntegerSize::Big,
        },
        "bit" => SqlType::Bit,
        "vector" if (1..=2).contains(&args.len()) => SqlType::Vector {
            dimensions: args[0].parse()?,
            element: if args.len() == 1 || args[1].eq_ignore_ascii_case("float32") {
                tds_client::VectorElement::Float32
            } else if args[1].eq_ignore_ascii_case("float16") {
                tds_client::VectorElement::Float16
            } else {
                return Err("vector element is float32 or float16".into());
            },
        },
        "real" => SqlType::Real,
        "float" => SqlType::Float,
        "money" => SqlType::Money,
        "smallmoney" => SqlType::SmallMoney,
        "decimal" | "numeric" => {
            if args.len() != 2 {
                return Err("decimal requires precision,scale".into());
            }
            SqlType::Decimal {
                precision: args[0].parse()?,
                scale: args[1].parse()?,
                numeric: base == "numeric",
            }
        }
        "clr" if args.len() == 1 => {
            let mut parts = args[0].split('.').collect::<Vec<_>>();
            if parts.len() == 2 {
                parts.insert(0, "");
            }
            if parts.len() != 3 || parts[1..].iter().any(|p| p.is_empty()) {
                return Err("CLR type requires schema.name or database.schema.name".into());
            }
            SqlType::Clr(Box::new(tds_client::ClrType {
                database: parts[0].into(),
                schema: parts[1].into(),
                name: parts[2].into(),
            }))
        }
        "nvarchar" if args.len() == 1 && args[0].eq_ignore_ascii_case("max") => {
            SqlType::CharacterMax {
                unicode: true,
                collation,
            }
        }
        "varbinary" if args.len() == 1 && args[0].eq_ignore_ascii_case("max") => SqlType::BinaryMax,
        "varchar" if args.len() == 1 && args[0].eq_ignore_ascii_case("max") => {
            SqlType::CharacterMax {
                unicode: false,
                collation,
            }
        }
        "xml" => SqlType::Xml { schema: None },
        "json" => SqlType::Json,
        "nvarchar" | "nchar" | "varchar" | "char" => SqlType::Character {
            length: length()?,
            varying: matches!(base, "nvarchar" | "varchar"),
            unicode: matches!(base, "nvarchar" | "nchar"),
            collation,
        },
        "varbinary" | "binary" => SqlType::Binary {
            length: length()?,
            varying: base == "varbinary",
        },
        "date" => SqlType::Date,
        "time" => SqlType::Time { scale: one(7)? },
        "datetime2" => SqlType::DateTime2 { scale: one(7)? },
        "datetimeoffset" => SqlType::DateTimeOffset { scale: one(7)? },
        "datetime" => SqlType::DateTime,
        "smalldatetime" => SqlType::SmallDateTime,
        "uniqueidentifier" => SqlType::Guid,
        _ => return Err("unsupported CLI parameter type; use --help".into()),
    };
    if !args.is_empty()
        && !matches!(
            base,
            "clr"
                | "vector"
                | "varchar"
                | "char"
                | "decimal"
                | "numeric"
                | "nvarchar"
                | "nchar"
                | "varbinary"
                | "binary"
                | "time"
                | "datetime2"
                | "datetimeoffset"
        )
    {
        return Err("this type takes no size/scale arguments".into());
    }
    let value = value.map(|text| parse_value(&sql_type, text)).transpose()?;
    let parameter = if kind == "--default" {
        Param::default_value(name, sql_type)
    } else {
        Param::new(name, sql_type, value)
    };
    Ok(if matches!(kind, "--output" | "--out-null") {
        parameter.output()
    } else {
        parameter
    })
}
fn parse_value(sql_type: &SqlType, text: &str) -> Result<Value> {
    Ok(match sql_type {
        SqlType::Json | SqlType::CharacterMax { unicode: true, .. } | SqlType::Xml { .. } => {
            Value::Unicode(text.into())
        }
        SqlType::BinaryMax | SqlType::Clr(_) => Value::Binary(unhex(text)?),
        SqlType::Vector { element, .. } => Value::Vector(vector(text, *element)?),
        SqlType::Table(_) => return Err("table parameters use the typed library input API".into()),
        SqlType::Variant => return Err("use a typed library SqlVariant for variant inputs".into()),
        SqlType::CharacterMax { collation, .. }
        | SqlType::Character {
            unicode: false,
            collation,
            ..
        } => Value::Text(tds_client::SqlTextBytes::from_text(
            *collation,
            &text.into(),
        )?),
        SqlType::LegacyText { .. } | SqlType::LegacyImage => {
            return Err("raw collated/legacy input is not a CLI literal type".into());
        }
        SqlType::Integer { .. } => Value::Integer(text.parse()?),
        SqlType::Bit => Value::Bit(match text {
            "1" | "true" => true,
            "0" | "false" => false,
            _ => return Err("bit is 0/1 or false/true".into()),
        }),
        SqlType::Real => Value::Real(SqlReal::from_float(text.parse()?)),
        SqlType::Float => Value::Float(SqlFloat::from_float(text.parse()?)),
        SqlType::Decimal { .. } => Value::Decimal(decimal(text)?),
        SqlType::Money | SqlType::SmallMoney => {
            let number = decimal(text)?.rescale_exact(4)?;
            let signed = if number.is_negative() {
                -(number.magnitude() as i128)
            } else {
                number.magnitude() as i128
            };
            Value::Money(SqlMoney(i64::try_from(signed)?))
        }
        SqlType::Character { .. } => Value::Unicode(text.into()),
        SqlType::Binary { .. } => Value::Binary(unhex(text)?),
        SqlType::Guid => Value::Guid(SqlGuid(
            unhex(&text.replace('-', ""))?
                .try_into()
                .map_err(|_| "GUID requires 16 bytes")?,
        )),
        SqlType::Date => Value::Date(date(text)?),
        SqlType::Time { .. } => Value::Time(clock(text)?),
        SqlType::DateTime2 { .. } => Value::DateTime2(date_time(text)?),
        SqlType::DateTimeOffset { .. } => {
            let split = text
                .char_indices()
                .rev()
                .find(|(i, c)| *i > 10 && matches!(c, '+' | '-'))
                .map(|(i, _)| i)
                .ok_or("datetimeoffset requires a signed HH:MM offset")?;
            let (local, zone) = text.split_at(split);
            let sign = if zone.starts_with('-') { -1 } else { 1 };
            let (hours, minutes) = zone[1..].split_once(':').ok_or("offset must be HH:MM")?;
            let minutes: i16 = minutes.parse()?;
            if !(0..60).contains(&minutes) {
                return Err("offset minute outside 0..59".into());
            }
            let hours: i16 = hours.parse()?;
            if !(0..=14).contains(&hours) {
                return Err("offset hour outside 0..14".into());
            }
            let offset = sign * (hours * 60 + minutes);
            let local = date_time(local)?;
            let ticks =
                local.time.ticks() as i64 - i64::from(offset) * 60 * TICKS_PER_SECOND as i64;
            let days = i64::from(local.date.days()) + ticks.div_euclid(TICKS_PER_DAY as i64);
            let utc = SqlDateTime2 {
                date: SqlDate::from_days(u32::try_from(days)?)?,
                time: SqlTime::from_ticks(ticks.rem_euclid(TICKS_PER_DAY as i64) as u64)?,
            };
            Value::DateTimeOffset(SqlDateTimeOffset::new(utc, offset)?)
        }
        SqlType::DateTime => {
            let (days, ticks) = text
                .split_once(',')
                .ok_or("datetime uses days,ticks since 1900")?;
            Value::DateTime(SqlDateTime::new(days.parse()?, ticks.parse()?)?)
        }
        SqlType::SmallDateTime => {
            let (days, minutes) = text
                .split_once(',')
                .ok_or("smalldatetime uses days,minutes since 1900")?;
            Value::SmallDateTime(SqlSmallDateTime::new(days.parse()?, minutes.parse()?)?)
        }
    })
}
fn vector(text: &str, element: tds_client::VectorElement) -> Result<tds_client::SqlVector> {
    let body = text
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .ok_or("vector uses [1,2.5,3] syntax")?;
    let mut numbers = Vec::new();
    for item in body.split(',') {
        let n: f64 = item.trim().parse()?;
        let exact = n as f32;
        if !n.is_finite() || f64::from(exact) != n {
            return Err("vector element has no exact finite float32 representation".into());
        }
        numbers.push(exact);
    }
    Ok(match element {
        tds_client::VectorElement::Float32 => tds_client::SqlVector::Float32(
            numbers
                .into_iter()
                .map(tds_client::SqlReal::from_float)
                .collect(),
        ),
        tds_client::VectorElement::Float16 => tds_client::SqlVector::Float16(
            numbers
                .into_iter()
                .map(tds_client::SqlHalf::from_float_exact)
                .collect::<std::result::Result<_, _>>()?,
        ),
    })
}
fn unhex(text: &str) -> Result<Vec<u8>> {
    let text = text.strip_prefix("0x").unwrap_or(text);
    if !text.is_ascii() || !text.len().is_multiple_of(2) {
        return Err("hex requires complete byte pairs".into());
    }
    (0..text.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&text[i..i + 2], 16).map_err(Into::into))
        .collect()
}
fn decimal(text: &str) -> Result<SqlDecimal> {
    let negative = text.starts_with('-');
    let digits = text.strip_prefix(['-', '+']).unwrap_or(text);
    let (whole, fraction) = digits.split_once('.').unwrap_or((digits, ""));
    if whole.is_empty()
        || !whole
            .bytes()
            .chain(fraction.bytes())
            .all(|b| b.is_ascii_digit())
    {
        return Err("decimal requires decimal digits".into());
    }
    Ok(SqlDecimal::new(
        negative,
        format!("{whole}{fraction}").parse()?,
        u8::try_from(fraction.len())?,
    )?)
}
fn date(text: &str) -> Result<SqlDate> {
    let parts = text.split('-').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err("date uses YYYY-MM-DD".into());
    }
    Ok(SqlDate::from_ymd(
        parts[0].parse()?,
        parts[1].parse()?,
        parts[2].parse()?,
    )?)
}
fn clock(text: &str) -> Result<SqlTime> {
    let parts = text.split(':').collect::<Vec<_>>();
    if parts.len() != 3 {
        return Err("time uses HH:MM:SS[.fffffff]".into());
    }
    let hour: u64 = parts[0].parse()?;
    let minute: u64 = parts[1].parse()?;
    let (seconds, fraction) = parts[2].split_once('.').unwrap_or((parts[2], ""));
    let second: u64 = seconds.parse()?;
    if hour >= 24
        || minute >= 60
        || second >= 60
        || fraction.len() > 7
        || !fraction.bytes().all(|b| b.is_ascii_digit())
    {
        return Err("time fields outside SQL range".into());
    }
    let fraction: u64 = if fraction.is_empty() {
        0
    } else {
        fraction.parse::<u64>()? * 10_u64.pow(7 - fraction.len() as u32)
    };
    Ok(SqlTime::from_ticks(
        (hour * 3600 + minute * 60 + second) * TICKS_PER_SECOND + fraction,
    )?)
}
fn date_time(text: &str) -> Result<SqlDateTime2> {
    let (day, time) = text
        .split_once(['T', ' '])
        .ok_or("date/time requires YYYY-MM-DDTHH:MM:SS")?;
    Ok(SqlDateTime2 {
        date: date(day)?,
        time: clock(time)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    const COLLATION: Collation = Collation([9, 4, 0xd0, 0, 0x34]);
    #[test]
    fn collated_text_and_vector_literals_refuse_substitution_or_rounding() {
        assert!(parse("--param", "@v:vector(3)=[1,2.5,3]", COLLATION).is_ok());
        assert!(parse("--param", "@v:vector(1,float16)=[65504]", COLLATION).is_ok());
        for spec in [
            "@v:vector(1)=[0.1]",
            "@v:vector(1,float16)=[65505]",
            "@v:varchar(max)=🦀",
        ] {
            assert!(parse("--param", spec, COLLATION).is_err());
        }
        let p = parse("--param", "@v:VARCHAR(MAX)=café", COLLATION).unwrap();
        let tds_client::ParamValue::Scalar(Some(Value::Text(raw))) = p.value else {
            panic!()
        };
        assert_eq!(raw.decode().unwrap(), "café".into());
    }
    #[test]
    fn keywords_are_insensitive_but_clr_type_identity_preserves_case() {
        let param = parse("--param", "@v:CLR(MyDb.dbo.MyType)=00ff", COLLATION).unwrap();
        let SqlType::Clr(identity) = param.sql_type else {
            panic!()
        };
        assert_eq!(identity.database, "MyDb".into());
        assert_eq!(identity.name, "MyType".into());
        assert_eq!(param.value.as_ref(), Some(&Value::Binary(vec![0, 255])));
        assert!(parse("--param", "@v:NVARCHAR(MAX)=hello", COLLATION).is_ok());
    }
    #[test]
    fn exact_literals_preserve_sign_scale_ticks_and_the_declared_offset() {
        let decimal = parse("--param", "@n:decimal(38,7)=-0.0000000", COLLATION).unwrap();
        let tds_client::ParamValue::Scalar(Some(Value::Decimal(number))) = decimal.value else {
            panic!("decimal")
        };
        assert!(number.is_negative());
        assert_eq!(number.scale(), 7);
        let offset = parse(
            "--param",
            "@t:datetimeoffset(7)=0001-01-01T00:00:00.0000001-14:00",
            COLLATION,
        )
        .unwrap();
        let tds_client::ParamValue::Scalar(Some(Value::DateTimeOffset(number))) = offset.value
        else {
            panic!("offset")
        };
        assert_eq!(number.offset_minutes(), -840);
        assert_eq!(number.utc().time.ticks(), 840 * 60 * TICKS_PER_SECOND + 1);
        for literal in [
            "@t:datetimeoffset(7)=0001-01-01T00:00:00+14:00",
            "@t:time(7)=24:00:00",
            "@n:binary(2)=🦀",
        ] {
            assert!(parse("--param", literal, COLLATION).is_err());
        }
    }
}
