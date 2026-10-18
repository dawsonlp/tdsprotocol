//! Exact scalar payloads, independent of a column's declared SQL type.
//!
//! NULL is `None`, outside [`Value`]. Constructors reject loss of precision;
//! no conversion silently rounds. Wire layouts live in `types::codec`.
use std::fmt;

use crate::types::Collation;

/// Exact SQL UTF-16, including code units that Rust `String` cannot represent.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SqlText(pub Vec<u16>);
impl SqlText {
    pub fn to_string(&self) -> std::result::Result<String, std::string::FromUtf16Error> {
        String::from_utf16(&self.0)
    }
}
impl From<&str> for SqlText {
    fn from(s: &str) -> Self {
        Self(s.encode_utf16().collect())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ValueError(pub &'static str);
impl fmt::Display for ValueError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}
impl std::error::Error for ValueError {}

/// IEEE bits are preserved, including signed zero and any received NaN payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlReal(u32);
impl SqlReal {
    pub const fn from_bits(bits: u32) -> Self {
        Self(bits)
    }
    pub fn from_float(value: f32) -> Self {
        Self(value.to_bits())
    }
    pub const fn bits(self) -> u32 {
        self.0
    }
    pub fn to_float(self) -> f32 {
        f32::from_bits(self.0)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlFloat(u64);
impl SqlFloat {
    pub const fn from_bits(bits: u64) -> Self {
        Self(bits)
    }
    pub fn from_float(value: f64) -> Self {
        Self(value.to_bits())
    }
    pub const fn bits(self) -> u64 {
        self.0
    }
    pub fn to_float(self) -> f64 {
        f64::from_bits(self.0)
    }
}

/// Sign is separate so that decimal negative zero survives a round trip.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlDecimal {
    negative: bool,
    magnitude: u128,
    scale: u8,
}
impl SqlDecimal {
    pub fn new(negative: bool, magnitude: u128, scale: u8) -> Result<Self, ValueError> {
        if scale > 38 || magnitude >= 10_u128.pow(38) {
            return Err(ValueError(
                "decimal requires scale 0..38 and at most 38 digits",
            ));
        }
        Ok(Self {
            negative,
            magnitude,
            scale,
        })
    }
    pub const fn is_negative(self) -> bool {
        self.negative
    }
    pub const fn magnitude(self) -> u128 {
        self.magnitude
    }
    pub const fn scale(self) -> u8 {
        self.scale
    }
    pub fn rescale_exact(self, scale: u8) -> Result<Self, ValueError> {
        if scale > 38 {
            return Err(ValueError("decimal scale exceeds 38"));
        }
        let magnitude = if scale >= self.scale {
            self.magnitude
                .checked_mul(10_u128.pow(u32::from(scale - self.scale)))
                .ok_or(ValueError("rescaled decimal exceeds 38 digits"))?
        } else {
            let divisor = 10_u128.pow(u32::from(self.scale - scale));
            if !self.magnitude.is_multiple_of(divisor) {
                return Err(ValueError("decimal conversion would round"));
            }
            self.magnitude / divisor
        };
        Self::new(self.negative, magnitude, scale)
    }
}
impl fmt::Display for SqlDecimal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.negative {
            f.write_str("-")?;
        }
        let digits = format!(
            "{:0width$}",
            self.magnitude,
            width = usize::from(self.scale) + 1
        );
        if self.scale == 0 {
            return f.write_str(&digits);
        }
        let split = digits.len() - usize::from(self.scale);
        write!(f, "{}.{}", &digits[..split], &digits[split..])
    }
}

/// Signed ten-thousandths; smallmoney's narrower range belongs to its SqlType.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlMoney(pub i64);

/// Exact bytes plus the column's collation. No guessed or replacement decoding.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlTextBytes {
    pub bytes: Vec<u8>,
    pub collation: Collation,
}

/// Canonical UUID byte order, independent of TDS's mixed-endian first groups.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlGuid(pub [u8; 16]);
impl SqlGuid {
    pub fn from_wire(mut bytes: [u8; 16]) -> Self {
        bytes[..4].reverse();
        bytes[4..6].reverse();
        bytes[6..8].reverse();
        Self(bytes)
    }
    pub fn to_wire(self) -> [u8; 16] {
        Self::from_wire(self.0).0
    }
}

pub const TICKS_PER_SECOND: u64 = 10_000_000;
pub const TICKS_PER_DAY: u64 = 86_400 * TICKS_PER_SECOND;
const LAST_DATE: u32 = 3_652_058;

/// Days since 0001-01-01, through 9999-12-31. Calendar conversion is explicit.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlDate(u32);
impl SqlDate {
    pub fn from_days(days: u32) -> Result<Self, ValueError> {
        if days > LAST_DATE {
            return Err(ValueError("date outside years 1..9999"));
        }
        Ok(Self(days))
    }
    pub fn from_ymd(year: i32, month: u8, day: u8) -> Result<Self, ValueError> {
        if !(1..=9999).contains(&year) {
            return Err(ValueError("date outside years 1..9999"));
        }
        let month =
            time::Month::try_from(month).map_err(|_| ValueError("invalid calendar month"))?;
        let date = time::Date::from_calendar_date(year, month, day)
            .map_err(|_| ValueError("invalid calendar date"))?;
        Self::from_days((date.to_julian_day() - 1_721_426) as u32)
    }
    pub const fn days(self) -> u32 {
        self.0
    }
    pub fn to_ymd(self) -> (i32, u8, u8) {
        let (year, month, day) = time::Date::from_julian_day(self.0 as i32 + 1_721_426)
            .expect("checked SQL date")
            .to_calendar_date();
        (year, month as u8, day)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlTime(u64);
impl SqlTime {
    pub fn from_ticks(ticks: u64) -> Result<Self, ValueError> {
        if ticks >= TICKS_PER_DAY {
            return Err(ValueError("time must be within one day"));
        }
        Ok(Self(ticks))
    }
    pub const fn ticks(self) -> u64 {
        self.0
    }
    pub fn at_scale(self, scale: u8) -> Result<u64, ValueError> {
        if scale > 7 {
            return Err(ValueError("time scale exceeds 7"));
        }
        let divisor = 10_u64.pow(u32::from(7 - scale));
        if !self.0.is_multiple_of(divisor) {
            return Err(ValueError("time conversion would round"));
        }
        Ok(self.0 / divisor)
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlDateTime2 {
    pub date: SqlDate,
    pub time: SqlTime,
}

/// UTC date/time plus the original offset, as in Python. Both UTC and local
/// dates must fit SQL's range. Equality retains the offset, not just the instant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlDateTimeOffset {
    utc: SqlDateTime2,
    offset_minutes: i16,
}
impl SqlDateTimeOffset {
    pub fn new(utc: SqlDateTime2, offset_minutes: i16) -> Result<Self, ValueError> {
        if !(-840..=840).contains(&offset_minutes) {
            return Err(ValueError("offset outside -14:00..+14:00"));
        }
        let value = Self {
            utc,
            offset_minutes,
        };
        value.local()?;
        Ok(value)
    }
    pub const fn utc(self) -> SqlDateTime2 {
        self.utc
    }
    pub const fn offset_minutes(self) -> i16 {
        self.offset_minutes
    }
    pub fn local(self) -> Result<SqlDateTime2, ValueError> {
        let ticks =
            self.utc.time.0 as i64 + i64::from(self.offset_minutes) * 60 * TICKS_PER_SECOND as i64;
        let day = i64::from(self.utc.date.0) + ticks.div_euclid(TICKS_PER_DAY as i64);
        let date = SqlDate::from_days(
            u32::try_from(day).map_err(|_| ValueError("local date before year 1"))?,
        )?;
        Ok(SqlDateTime2 {
            date,
            time: SqlTime(ticks.rem_euclid(TICKS_PER_DAY as i64) as u64),
        })
    }
}

/// Legacy datetime uses 1/300-second ticks, which cannot be replaced by ns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlDateTime {
    days: i32,
    ticks: u32,
}
impl SqlDateTime {
    pub fn new(days: i32, ticks: u32) -> Result<Self, ValueError> {
        if !(-53_690..=2_958_463).contains(&days) || ticks >= 300 * 86_400 {
            return Err(ValueError("datetime outside 1753..9999 or invalid ticks"));
        }
        Ok(Self { days, ticks })
    }
    pub const fn days(self) -> i32 {
        self.days
    }
    pub const fn ticks(self) -> u32 {
        self.ticks
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlSmallDateTime {
    days: u16,
    minutes: u16,
}
impl SqlSmallDateTime {
    pub fn new(days: u16, minutes: u16) -> Result<Self, ValueError> {
        if minutes >= 1440 {
            return Err(ValueError("smalldatetime minutes outside one day"));
        }
        Ok(Self { days, minutes })
    }
    pub const fn days(self) -> u16 {
        self.days
    }
    pub const fn minutes(self) -> u16 {
        self.minutes
    }
}

/// A non-NULL variant carries its declared base SQL type and exact payload.
/// SQL NULL belongs to the outer Option; nested variants/large bases are refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SqlVariant {
    pub sql_type: crate::SqlType,
    pub value: Value,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Value {
    Variant(Box<SqlVariant>),
    Vector(SqlVector),
    Integer(i64),
    Bit(bool),
    Real(SqlReal),
    Float(SqlFloat),
    Decimal(SqlDecimal),
    Money(SqlMoney),
    Unicode(SqlText),
    Text(SqlTextBytes),
    Binary(Vec<u8>),
    Guid(SqlGuid),
    Date(SqlDate),
    Time(SqlTime),
    DateTime2(SqlDateTime2),
    DateTimeOffset(SqlDateTimeOffset),
    DateTime(SqlDateTime),
    SmallDateTime(SqlSmallDateTime),
}
impl Value {
    pub fn as_integer(&self) -> Option<i64> {
        if let Self::Integer(n) = self {
            Some(*n)
        } else {
            None
        }
    }
    pub fn as_unicode(&self) -> Option<&SqlText> {
        if let Self::Unicode(s) = self {
            Some(s)
        } else {
            None
        }
    }
}
impl From<i64> for Value {
    fn from(n: i64) -> Self {
        Self::Integer(n)
    }
}

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum VectorElement {
    Float32 = 0,
    Float16 = 1,
}
impl VectorElement {
    pub const fn bytes(self) -> usize {
        match self {
            Self::Float32 => 4,
            Self::Float16 => 2,
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlVector {
    Float32(Vec<SqlReal>),
    Float16(Vec<SqlHalf>),
}
/// Exact binary16 bits, with an explicitly checked numeric constructor.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SqlHalf(u16);
impl SqlHalf {
    pub const fn from_bits(bits: u16) -> Self {
        Self(bits)
    }
    pub const fn bits(self) -> u16 {
        self.0
    }
    pub const fn is_finite(self) -> bool {
        self.0 & 0x7c00 != 0x7c00
    }
    pub fn to_float(self) -> f32 {
        let sign = u32::from(self.0 & 0x8000) << 16;
        let exponent = (self.0 >> 10) & 31;
        let fraction = self.0 & 1023;
        if exponent == 0 {
            let n = f32::from(fraction) * 2_f32.powi(-24);
            if sign == 0 { n } else { -n }
        } else {
            f32::from_bits(
                sign | ((if exponent == 31 {
                    255
                } else {
                    u32::from(exponent) + 112
                }) << 23)
                    | (u32::from(fraction) << 13),
            )
        }
    }
    pub fn from_float_exact(n: f32) -> Result<Self, ValueError> {
        let invalid = || ValueError("value has no exact finite binary16 representation");
        if !n.is_finite() {
            return Err(invalid());
        }
        let b = n.to_bits();
        let sign = ((b >> 16) & 0x8000) as u16;
        if b & 0x7fff_ffff == 0 {
            return Ok(Self(sign));
        }
        let exponent = ((b >> 23) & 255) as i32 - 112;
        let fraction = b & 0x7f_ffff;
        let bits = if exponent <= 0 {
            if exponent < -9 {
                return Err(invalid());
            }
            let mantissa = fraction | 0x80_0000;
            let shift = (14 - exponent) as u32;
            if mantissa & ((1_u32 << shift) - 1) != 0 {
                return Err(invalid());
            }
            sign | (mantissa >> shift) as u16
        } else {
            if exponent >= 31 || fraction & 0x1fff != 0 {
                return Err(invalid());
            }
            sign | ((exponent as u16) << 10) | (fraction >> 13) as u16
        };
        Ok(Self(bits))
    }
}
