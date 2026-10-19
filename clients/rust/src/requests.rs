//! Requests describe bytes and retained metadata, without interpreting SQL.
//! Reference: `docs/design/3-reference/requests.md`; MS-TDS v20260617 §§2.2.5.3, 2.2.6.7.

use crate::{Error, ErrorKind, Result, wire};

/// Resolved session inputs, never socket or connection authority.
pub struct Context {
    pub transaction: u64,
    pub outstanding: u32,
    pub column_encryption: bool,
    pub enclaves: bool,
}
/// Bulk is the one approved multi-exchange sequencing exception (D-50).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Continuation {
    #[default]
    None,
    OpensBulk,
    BulkRows,
    AbortBulk,
}
pub struct Encoded {
    pub continuation: Continuation,
    pub kind: u8,
    pub body: Vec<u8>,
    pub metadata: Vec<Vec<crate::tokens::Column>>,
}
/// A request describes one message. The connection frames/transmits the encoded
/// message and reads a response. Only explicit bulk continuation metadata adds
/// sequencing state (D-50); the connection never parses application SQL.
pub trait Request: Send {
    fn label(&self) -> &'static str;
    fn encode_request(&self, context: &Context) -> Result<Encoded>;
    /// Consume unique request/source ownership before the first request byte.
    fn prepare(self: Box<Self>, context: &Context) -> Result<Prepared> {
        self.encode_request(context).map(Prepared::from)
    }
}
pub(crate) fn headers(transaction: u64, outstanding: u32) -> Vec<u8> {
    let mut out = Vec::with_capacity(22);
    out.extend(22_u32.to_le_bytes());
    out.extend(18_u32.to_le_bytes());
    out.extend(2_u16.to_le_bytes());
    out.extend(transaction.to_le_bytes());
    out.extend(if transaction == 0 { 1 } else { outstanding }.to_le_bytes());
    out
}
impl Request for Batch {
    fn label(&self) -> &'static str {
        "SQL batch"
    }
    fn encode_request(&self, context: &Context) -> Result<Encoded> {
        let mut body = self.encode(context.transaction, context.outstanding)?;
        if context.enclaves {
            if body.len() > wire::MAX_PENDING - 2 {
                return Err(Error::new(ErrorKind::Limit("SQL batch")));
            }
            body.splice(22..22, [0, 0]);
        }
        Ok(Encoded {
            continuation: Continuation::None,
            kind: crate::packet::BATCH,
            body,
            metadata: Vec::new(),
        })
    }
}

pub struct Batch(pub String);
impl Batch {
    pub fn new(sql: impl Into<String>) -> Self {
        Self(sql.into())
    }
    pub fn with_enclave(self, package: Vec<u8>) -> EnclaveBatch {
        EnclaveBatch {
            batch: self,
            package,
        }
    }
    pub(crate) fn encode(&self, transaction: u64, outstanding: u32) -> Result<Vec<u8>> {
        if self.0.len() > (wire::MAX_PENDING - 22) / 2 {
            return Err(Error::new(ErrorKind::Limit("SQL batch")));
        }
        let mut out = headers(transaction, outstanding);
        out.extend(wire::utf16(&self.0));
        Ok(out)
    }
}

pub struct EnclaveBatch {
    batch: Batch,
    package: Vec<u8>,
}
impl Request for EnclaveBatch {
    fn label(&self) -> &'static str {
        "SQL batch"
    }
    fn encode_request(&self, context: &Context) -> Result<Encoded> {
        if !context.enclaves {
            return Err(Error::new(ErrorKind::Parameter(
                "enclave package requires version two",
            )));
        }
        let mut request = self.batch.encode_request(context)?;
        let length = u16::try_from(self.package.len())
            .map_err(|_| Error::new(ErrorKind::Limit("enclave package")))?;
        request.body[22..24].copy_from_slice(&length.to_le_bytes());
        request.body.splice(24..24, self.package.iter().copied());
        if request.body.len() > wire::MAX_PENDING {
            return Err(Error::new(ErrorKind::Limit("SQL batch")));
        }
        Ok(request)
    }
}

pub(crate) mod source;
pub use source::{Prepared, Source, SourceRead, StreamedCall, StreamedCalls};
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) mod bulk;
pub(crate) mod rows;
pub use rows::{RowRead, RowSource, Sort, TableColumn, TableType};
pub mod decode;
mod rpc;
pub use rpc::{Builtin, Call, CallOptions, Calls, CipherInfo, Param, ParamValue, Procedure};

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn autocommit_header_is_one_while_a_transaction_counts_concurrent_requests() {
        for (transaction, count) in [(0_u64, 1_u32), (17, 2)] {
            let bytes = Batch::new("SELECT 1").encode(transaction, 2).unwrap();
            assert_eq!(&bytes[..10], &[22, 0, 0, 0, 18, 0, 0, 0, 2, 0]);
            assert_eq!(&bytes[10..18], &transaction.to_le_bytes());
            assert_eq!(&bytes[18..22], &count.to_le_bytes());
        }
    }
}
