//! Bulk's two messages, with explicit continuation metadata. Only the borrowed
//! shell writer exposes this sequence; neither request generates application SQL.
use super::*;
use crate::{Row, tokens::Column};

pub(crate) struct Begin(pub String);
impl Request for Begin {
    fn label(&self) -> &'static str {
        "INSERT BULK"
    }
    fn encode_request(&self, context: &Context) -> Result<Encoded> {
        let mut encoded = Batch::new(self.0.clone()).encode_request(context)?;
        encoded.continuation = Continuation::OpensBulk;
        Ok(encoded)
    }
}
pub(crate) struct Abort;
impl Request for Abort {
    fn label(&self) -> &'static str {
        "attention"
    }
    fn encode_request(&self, _: &Context) -> Result<Encoded> {
        Ok(Encoded {
            kind: crate::packet::ATTENTION,
            body: vec![],
            metadata: vec![],
            continuation: Continuation::AbortBulk,
        })
    }
}
pub(crate) struct Rows {
    pub columns: Vec<Column>,
    pub rows: Vec<Row>,
}
impl Request for Rows {
    fn label(&self) -> &'static str {
        "bulk data"
    }
    fn encode_request(&self, _: &Context) -> Result<Encoded> {
        let mut body = rows::bulk_header(&self.columns)?;
        for row in &self.rows {
            body.extend(rows::bulk_row(&self.columns, row)?);
        }
        body.extend(rows::BULK_DONE);
        Ok(Encoded {
            kind: 0x07,
            body,
            metadata: vec![],
            continuation: Continuation::BulkRows,
        })
    }
}
pub(crate) struct Stream {
    pub columns: Vec<Column>,
    pub source: Box<dyn RowSource>,
}
impl Request for Stream {
    fn label(&self) -> &'static str {
        "bulk data"
    }
    fn encode_request(&self, _: &Context) -> Result<Encoded> {
        Err(Error::new(ErrorKind::Parameter(
            "bulk row source must be consumed",
        )))
    }
    fn prepare(self: Box<Self>, _: &Context) -> Result<Prepared> {
        let body = rows::bulk_header(&self.columns)?;
        let source = rows::stream(body.len(), rows::RowLayout::Bulk(self.columns), self.source);
        Ok(Prepared {
            encoded: Encoded {
                kind: 0x07,
                body,
                metadata: vec![],
                continuation: Continuation::BulkRows,
            },
            sources: vec![source],
        })
    }
}
