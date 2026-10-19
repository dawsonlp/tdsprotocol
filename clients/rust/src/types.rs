//! Declared SQL types and their wire descriptions are separate concepts.
//!
//! INT4 and INTN(4) both mean `int`; [`TypeInfo::code`] still records which
//! arrived. Payloads are [`crate::values::Value`], and SQL NULL is `None`.
use crate::{Result, values::Value, wire::Reader};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum IntegerSize {
    Tiny,
    Small,
    Int,
    Big,
}
impl IntegerSize {
    pub const fn bytes(self) -> u8 {
        match self {
            Self::Tiny => 1,
            Self::Small => 2,
            Self::Int => 4,
            Self::Big => 8,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Collation(pub [u8; 5]);
impl Collation {
    pub fn is_utf8(self) -> bool {
        self.0[3] & 0x04 != 0
    }
    pub fn locale_id(self) -> u32 {
        u32::from_le_bytes([self.0[0], self.0[1], self.0[2], self.0[3]]) & 0x000f_ffff
    }
    pub const fn sort_id(self) -> u8 {
        self.0[4]
    }
}

/// Lengths are bytes for binary/non-Unicode text, UTF-16 units for Unicode.
/// Large declarations describe payloads independently of how they are read.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SqlType {
    Integer {
        size: IntegerSize,
    },
    Bit,
    Real,
    Float,
    Decimal {
        precision: u8,
        scale: u8,
        numeric: bool,
    },
    Money,
    SmallMoney,
    Date,
    Time {
        scale: u8,
    },
    DateTime2 {
        scale: u8,
    },
    DateTimeOffset {
        scale: u8,
    },
    DateTime,
    SmallDateTime,
    Guid,
    Variant,
    /// Input-only user-defined table declaration; never a returned cell.
    Table(Box<crate::requests::TableType>),
    Json,
    Vector {
        dimensions: u16,
        element: crate::VectorElement,
    },
    Character {
        length: u16,
        varying: bool,
        unicode: bool,
        collation: Collation,
    },
    /// PLP character data: byte collation or exact UTF-16 units.
    CharacterMax {
        unicode: bool,
        collation: Collation,
    },
    BinaryMax,
    Clr(Box<ClrType>),
    Xml {
        schema: Option<XmlSchema>,
    },
    LegacyText {
        unicode: bool,
        collation: Collation,
    },
    LegacyImage,
    Binary {
        length: u16,
        varying: bool,
    },
}

/// Catalog identity of a CLR serialization; interpreting its bytes belongs to
/// the application. Assembly and maximum size are received wire metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ClrType {
    pub database: crate::SqlText,
    pub schema: crate::SqlText,
    pub name: crate::SqlText,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct XmlSchema {
    pub database: crate::SqlText,
    pub owner: crate::SqlText,
    pub collection: crate::SqlText,
}

/// Legacy result TYPE_INFO carries provenance, separately from the SQL type.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LegacyMetadata {
    pub max_length: u32,
    pub table: Vec<crate::SqlText>,
}
impl SqlType {
    pub fn is_large(&self) -> bool {
        matches!(
            self,
            Self::CharacterMax { .. }
                | Self::BinaryMax
                | Self::Clr(_)
                | Self::Json
                | Self::Xml { .. }
                | Self::LegacyText { .. }
                | Self::LegacyImage
        )
    }
    pub(crate) fn is_unicode(&self) -> bool {
        matches!(
            self,
            Self::CharacterMax { unicode: true, .. }
                | Self::Json
                | Self::Xml { .. }
                | Self::LegacyText { unicode: true, .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TypeInfo {
    pub sql_type: SqlType,
    pub code: u8,
    /// The TYPE_INFO length exactly as received, where the layout has one.
    pub max_length: Option<u16>,
    pub legacy: Option<LegacyMetadata>,
    pub clr_assembly: Option<crate::SqlText>,
    /// Native JSON result encoding follows accepted UTF-8 negotiation. Inputs
    /// are always UTF-8; this is wire metadata, not a different SQL type.
    pub json_utf8: bool,
    /// Ciphertext framing remains in `sql_type`; this describes its plaintext.
    pub encryption: Option<Box<crypto::CryptoMetadata>>,
}
impl TypeInfo {
    /// Application value type; `sql_type` itself preserves ciphertext wire framing.
    pub fn value_type(&self) -> &SqlType {
        self.encryption
            .as_ref()
            .map_or(&self.sql_type, |crypto| &crypto.base.sql_type)
    }

    pub(crate) fn is_streaming(&self) -> bool {
        self.encryption.is_none() && self.sql_type.is_large()
    }
    pub(crate) fn read_parameter(r: &mut Reader<'_>) -> Result<Self> {
        codec::read_info_for(r, true)
    }
    pub(crate) fn read(r: &mut Reader<'_>) -> Result<Self> {
        codec::read_info(r)
    }
    pub(crate) fn read_value(&self, r: &mut Reader<'_>) -> Result<Option<Value>> {
        codec::read_value(self, r)
    }
}
mod codec;
pub(crate) mod encode;
mod variant;
mod vector;

pub mod crypto;
