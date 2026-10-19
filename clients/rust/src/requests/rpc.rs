//! RPC names/numbers, flags and typed parameters in the same order as Python.
//! BATCH separators join calls; NO_EXEC is never emitted. An RPC message is
//! encoded/validated completely before the core commits its busy state.
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # async fn example(channel: &mut tds_client::SerialChannel) -> tds_client::Result<()> {
//! use tds_client::{Call, IntegerSize, Param, SqlType, Value};
//! let call = Call::new("dbo.read_order", vec![
//!     Param::new("@order", SqlType::Integer { size: IntegerSize::Int },
//!                Some(Value::Integer(42))),
//! ]);
//! let fetched = channel.exchange(call).await?.fetch().await?;
//! for completed in fetched.returns() {
//!     println!("return {:?}, outputs {:?}", completed.status, completed.outputs);
//! }
//! # Ok(()) }
//! ```
use super::*;
use crate::{SqlText, SqlType, Value, tokens::Column};

#[repr(u16)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Builtin {
    SpCursor = 1,
    SpCursorOpen = 2,
    SpCursorPrepare = 3,
    SpCursorExecute = 4,
    SpCursorPrepExec = 5,
    SpCursorUnprepare = 6,
    SpCursorFetch = 7,
    SpCursorOption = 8,
    SpCursorClose = 9,
    SpExecuteSql = 10,
    SpPrepare = 11,
    SpExecute = 12,
    SpPrepExec = 13,
    SpPrepExecRpc = 14,
    SpUnprepare = 15,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Procedure {
    Name(SqlText),
    Builtin(Builtin),
}
impl From<&str> for Procedure {
    fn from(value: &str) -> Self {
        Self::Name(value.into())
    }
}
impl From<String> for Procedure {
    fn from(value: String) -> Self {
        Self::Name(value.as_str().into())
    }
}
impl From<SqlText> for Procedure {
    fn from(value: SqlText) -> Self {
        Self::Name(value)
    }
}
impl From<Builtin> for Procedure {
    fn from(value: Builtin) -> Self {
        Self::Builtin(value)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct CallOptions {
    pub recompile: bool,
    pub no_metadata: bool,
    pub reuse_metadata: bool,
}
/// Scalar cells and input-only table rows have distinct meanings. Neither
/// variant owns a producer; streamed sources remain unique bindings on a call.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ParamValue {
    Scalar(Option<Value>),
    Table(Option<Vec<crate::Row>>),
}
impl ParamValue {
    /// Borrow the scalar payload; table inputs have a separate representation.
    pub fn as_ref(&self) -> Option<&Value> {
        if let Self::Scalar(v) = self {
            v.as_ref()
        } else {
            None
        }
    }
    pub fn is_some(&self) -> bool {
        match self {
            Self::Scalar(v) => v.is_some(),
            Self::Table(v) => v.is_some(),
        }
    }
    pub fn take_scalar(&mut self) -> Option<Value> {
        if let Self::Scalar(value) = self {
            value.take()
        } else {
            None
        }
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Param {
    pub name: SqlText,
    pub sql_type: SqlType,
    pub value: ParamValue,
    pub output: bool,
    /// DEFAULT is separate from NULL. A default parameter sends NULL with the
    /// DEFAULT_VALUE status bit; the server chooses the procedure's default.
    pub use_default: bool,
    pub cipher: Option<CipherInfo>,
}
impl Param {
    pub fn new(name: impl Into<SqlText>, sql_type: SqlType, value: Option<Value>) -> Self {
        Self {
            name: name.into(),
            value: if matches!(sql_type, SqlType::Table(_)) && value.is_none() {
                ParamValue::Table(None)
            } else {
                ParamValue::Scalar(value)
            },
            sql_type,
            output: false,
            use_default: false,
            cipher: None,
        }
    }
    pub fn table(
        name: impl Into<SqlText>,
        declaration: super::TableType,
        rows: Option<Vec<crate::Row>>,
    ) -> Self {
        Self {
            name: name.into(),
            sql_type: SqlType::Table(Box::new(declaration)),
            value: ParamValue::Table(rows),
            output: false,
            use_default: false,
            cipher: None,
        }
    }
    pub fn output(mut self) -> Self {
        self.output = true;
        self
    }
    pub fn default_value(name: impl Into<SqlText>, sql_type: SqlType) -> Self {
        Self {
            use_default: true,
            ..Self::new(name, sql_type, None)
        }
    }
    pub(super) fn encode_header(&self, output: &mut Vec<u8>) -> Result<()> {
        let count = u8::try_from(self.name.0.len()).map_err(|_| {
            Error::new(ErrorKind::Parameter(
                "parameter name exceeds 255 UTF-16 units",
            ))
        })?;
        output.push(count);
        text(&self.name, output);
        output.push(
            u8::from(self.output)
                | if self.use_default { 2 } else { 0 }
                | if self.cipher.is_some() { 8 } else { 0 },
        );
        if self.use_default && self.value.is_some() {
            return Err(Error::new(ErrorKind::Parameter(
                "DEFAULT must not also supply a value",
            )));
        }
        Ok(())
    }
    pub(super) fn encode(&self, output: &mut Vec<u8>) -> Result<()> {
        if self.cipher.is_some()
            && (self.use_default
                || !matches!(self.sql_type, SqlType::Binary { .. } | SqlType::BinaryMax))
        {
            return Err(Error::new(ErrorKind::Parameter(
                "encrypted RPC requires binary ciphertext and no DEFAULT",
            )));
        }
        self.encode_header(output)?;
        match (&self.sql_type, &self.value) {
            (SqlType::Table(table), ParamValue::Table(rows)) => {
                output.extend(table.encode(rows.as_deref())?)
            }
            (SqlType::Table(_), _) | (_, ParamValue::Table(_)) => {
                return Err(Error::new(ErrorKind::Parameter(
                    "parameter declaration/value kind mismatch",
                )));
            }
            (_, ParamValue::Scalar(value)) => {
                output.extend(self.sql_type.encode_parameter(value.as_ref())?)
            }
        }
        if let Some(cipher) = &self.cipher {
            cipher.encode(output)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    pub target: Procedure,
    pub params: Vec<Param>,
    pub options: CallOptions,
    /// Saved columns in result-set order, required with NO_METADATA.
    pub columns: Vec<Vec<Column>>,
}
impl Call {
    pub fn new(target: impl Into<Procedure>, params: Vec<Param>) -> Self {
        Self {
            target: target.into(),
            params,
            options: CallOptions::default(),
            columns: Vec::new(),
        }
    }
    pub(super) fn encode_header(&self, output: &mut Vec<u8>) -> Result<()> {
        match &self.target {
            Procedure::Name(name) => {
                if name.0.is_empty() || name.0.len() >= 0xffff {
                    return Err(Error::new(ErrorKind::Parameter("procedure name length")));
                }
                output.extend((name.0.len() as u16).to_le_bytes());
                text(name, output);
            }
            Procedure::Builtin(number) => {
                output.extend(0xffff_u16.to_le_bytes());
                output.extend((*number as u16).to_le_bytes());
            }
        }
        if self.options.no_metadata && self.columns.is_empty() {
            return Err(Error::new(ErrorKind::Parameter(
                "NO_METADATA requires saved result columns",
            )));
        }
        let flags = u16::from(self.options.recompile)
            | if self.options.no_metadata { 2 } else { 0 }
            | if self.options.reuse_metadata { 4 } else { 0 };
        output.extend(flags.to_le_bytes());
        Ok(())
    }
    fn encode(&self, output: &mut Vec<u8>) -> Result<()> {
        self.encode_header(output)?;
        for param in &self.params {
            param.encode(output)?;
        }
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Calls(pub Vec<Call>);
fn text(value: &SqlText, output: &mut Vec<u8>) {
    output.extend(value.0.iter().flat_map(|n| n.to_le_bytes()));
}
impl Request for Call {
    fn label(&self) -> &'static str {
        "RPC"
    }
    fn encode_request(&self, context: &Context) -> Result<Encoded> {
        encode(std::slice::from_ref(self), context, true)
    }
    fn prepare(self: Box<Self>, context: &Context) -> Result<Prepared> {
        encode(std::slice::from_ref(self.as_ref()), context, false).map(Prepared::from)
    }
}
impl Request for Calls {
    fn label(&self) -> &'static str {
        "RPC"
    }
    fn encode_request(&self, context: &Context) -> Result<Encoded> {
        encode(&self.0, context, true)
    }
    fn prepare(self: Box<Self>, context: &Context) -> Result<Prepared> {
        encode(&self.0, context, false).map(Prepared::from)
    }
}
fn encode(calls: &[Call], context: &Context, bounded: bool) -> Result<Encoded> {
    if calls.is_empty() {
        return Err(Error::new(ErrorKind::Parameter(
            "Calls requires at least one call",
        )));
    }
    if !context.column_encryption
        && calls
            .iter()
            .any(|c| c.params.iter().any(|p| p.cipher.is_some()))
    {
        return Err(Error::new(ErrorKind::Parameter(
            "encrypted parameters require negotiated column encryption",
        )));
    }
    let mut body = headers(context.transaction, context.outstanding);
    for (index, call) in calls.iter().enumerate() {
        if index != 0 {
            body.push(0xff);
        }
        call.encode(&mut body)?;
        if bounded && body.len() > wire::MAX_PENDING {
            return Err(Error::new(ErrorKind::Limit("RPC message")));
        }
    }
    Ok(Encoded {
        continuation: crate::requests::Continuation::None,
        kind: crate::packet::RPC,
        body,
        metadata: calls
            .iter()
            .flat_map(|c| c.columns.iter().cloned())
            .collect(),
    })
}

/// ParamCipherInfo follows ciphertext on encrypted RPC inputs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CipherInfo {
    pub base: SqlType,
    pub key: crate::types::crypto::ColumnKey,
    pub encryption_type: u8,
    pub algorithm: u8,
    pub normalization: u8,
}
impl CipherInfo {
    fn encode(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.algorithm != 2 || self.normalization != 1 || ![1, 2].contains(&self.encryption_type)
        {
            return Err(Error::new(ErrorKind::Parameter(
                "unsupported encryption metadata",
            )));
        }
        let encoded = self.base.encode_parameter(None)?;
        let mut r = crate::wire::Reader::new(&encoded);
        crate::TypeInfo::read_parameter(&mut r)?;
        out.extend_from_slice(&encoded[..r.offset]);
        out.extend([self.algorithm, self.encryption_type]);
        out.extend(self.key.database_id.to_le_bytes());
        out.extend(self.key.key_id.to_le_bytes());
        out.extend(self.key.version.to_le_bytes());
        out.extend(self.key.metadata_version);
        out.push(self.normalization);
        Ok(())
    }
}
