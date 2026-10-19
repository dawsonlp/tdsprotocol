//! Forward result-set views borrow the response's one advancing reader.
//!
//! Parent advancement discards unread rows, matching Python. End-of-response
//! returns require an explicit keep/discard choice. Neither API invents rows
//! that have already streamed past. Exclusive reborrows carry the same rule down
//! through streamed rows and their large values.
use super::Response;
use crate::{Error, ErrorKind, Execution, Record, Result, Step};

/// A live result set lends the response's one reader. Dropping the view alone
/// does not perform network I/O; asking for the next set drains unread rows.
///
/// ```compile_fail
/// # async fn example(response: &mut tds_client::Response<'_>) -> tds_client::Result<()> {
/// let mut first = response.next_result_set().await?.unwrap();
/// let second = response.next_result_set().await?;
/// first.next_row().await?; // Cannot advance the response behind its live set.
/// # Ok(()) }
/// ```
pub struct LiveResultSet<'response, 'connection> {
    response: &'response mut Response<'connection>,
    pub columns: Vec<crate::tokens::Column>,
    pub completion: Option<crate::tokens::Done>,
}
impl<'connection> LiveResultSet<'_, 'connection> {
    pub async fn next_row(&mut self) -> Result<Option<crate::Row>> {
        if self.completion.is_some() {
            return Ok(None);
        }
        while let Some(record) = self.response.next().await? {
            match record {
                Record::Row(row) => return Ok(Some(row)),
                Record::Done(done) => {
                    self.response.result_active = false;
                    self.completion = Some(done);
                    return Ok(None);
                }
                Record::Columns(_) => return Err(Error::malformed(0, "nested result metadata")),
                _ => {}
            }
        }
        Ok(None)
    }
    /// Lend this set's one reader down to a row. Moving to another row drains
    /// any unread cell/value tail. A scalar-only row uses the same interface.
    pub async fn streamed_row(&mut self) -> Result<Option<StreamedRow<'_, 'connection>>> {
        if self.completion.is_some() {
            return Ok(None);
        }
        self.response.drain_row().await?;
        while let Some(record) = self.response.next_event().await? {
            match record {
                Record::RowStart => {
                    return Ok(Some(StreamedRow {
                        response: self.response,
                        scalar: None,
                        ended: false,
                    }));
                }
                Record::Row(row) => {
                    return Ok(Some(StreamedRow {
                        response: self.response,
                        scalar: Some(row.into_iter()),
                        ended: false,
                    }));
                }
                Record::Done(done) => {
                    self.response.result_active = false;
                    self.completion = Some(done);
                    return Ok(None);
                }
                Record::Columns(_) => return Err(Error::malformed(0, "nested result metadata")),
                _ => {}
            }
        }
        Ok(None)
    }
    pub async fn finish(&mut self) -> Result<()> {
        self.response.drain_row().await?;
        if self.completion.is_some() {
            return Ok(());
        }
        while let Some(record) = self.response.next_event().await? {
            if let Record::Done(done) = record {
                self.response.result_active = false;
                self.completion = Some(done);
                break;
            }
        }
        Ok(())
    }
}
impl<'connection> Response<'connection> {
    /// Advance to the next result set, discarding any unread rows in the prior
    /// one as Python iteration does. Scalar rows arrive one at a time.
    pub async fn next_result_set(&mut self) -> Result<Option<LiveResultSet<'_, 'connection>>> {
        if self.result_active {
            while let Some(record) = self.next_event().await? {
                if matches!(record, Record::Done(_)) {
                    self.result_active = false;
                    break;
                }
            }
        }
        while let Some(record) = self.next_event().await? {
            if let Record::Columns(columns) = record {
                self.result_active = true;
                return Ok(Some(LiveResultSet {
                    response: self,
                    columns,
                    completion: None,
                }));
            }
        }
        Ok(None)
    }
    pub async fn returns(
        &mut self,
        unread: crate::response::Unread,
    ) -> Result<Vec<crate::response::ProcedureReturn>> {
        if !self.finished {
            match unread {
                crate::response::Unread::Refuse => {
                    return Err(Error::new(ErrorKind::NotYetRead(
                        "procedure returns require completion; choose Keep or Discard",
                    ))
                    .at(Step::Exchange, Execution::PossiblyExecuted));
                }
                crate::response::Unread::Keep => {
                    self.fetch().await?;
                }
                crate::response::Unread::Discard => {
                    self.finish().await?;
                }
            }
        }
        self.at_end()?;
        Ok(self.snapshot().returns().to_vec())
    }
}

/// A cell is either NULL, an owned scalar, or the unique borrowed large reader.
pub enum Cell<'row, 'connection> {
    Null,
    Scalar(crate::Value),
    Stream(ValueStream<'row, 'connection>),
}
/// One advancing row. Drop performs no I/O; the parent's next advance drains it.
///
/// ```compile_fail
/// # async fn example(set: &mut tds_client::LiveResultSet<'_, '_>) -> tds_client::Result<()> {
/// let mut row = set.streamed_row().await?.unwrap();
/// let cell = row.next_value().await?;
/// row.next_value().await?;
/// drop(cell); // A live value cannot be bypassed through its row.
/// # Ok(()) }
/// ```
pub struct StreamedRow<'set, 'connection> {
    response: &'set mut Response<'connection>,
    scalar: Option<std::vec::IntoIter<Option<crate::Value>>>,
    ended: bool,
}
impl<'connection> StreamedRow<'_, 'connection> {
    pub async fn next_value(&mut self) -> Result<Option<Cell<'_, 'connection>>> {
        if self.ended {
            return Ok(None);
        }
        if let Some(row) = &mut self.scalar {
            return Ok(row.next().map(|v| v.map_or(Cell::Null, Cell::Scalar)));
        }
        while self.response.value_pending {
            if self.response.next_event().await?.is_none() {
                return Err(Error::malformed(0, "unfinished streamed value"));
            }
        }
        match self.response.next_event().await? {
            Some(Record::Cell(None)) => Ok(Some(Cell::Null)),
            Some(Record::Cell(Some(value))) => Ok(Some(Cell::Scalar(value))),
            Some(Record::ValueStart {
                sql_type,
                total_length,
            }) => Ok(Some(Cell::Stream(ValueStream {
                response: self.response,
                sql_type,
                total_length,
                ended: false,
            }))),
            Some(Record::RowEnd) => {
                self.ended = true;
                Ok(None)
            }
            _ => Err(Error::malformed(0, "expected streamed cell")),
        }
    }
    pub async fn finish(&mut self) -> Result<()> {
        if let Some(row) = &mut self.scalar {
            row.by_ref().for_each(drop);
        } else {
            self.response.drain_row().await?;
        }
        self.ended = true;
        Ok(())
    }
}
/// A value borrows its row's advancing authority. Chunks are owned data. No
/// hidden whole-value assembly occurs; dropping this view defers tail draining.
pub struct ValueStream<'row, 'connection> {
    response: &'row mut Response<'connection>,
    pub sql_type: crate::SqlType,
    /// Advertised wire-byte total, if known. Native JSON's typed Unicode
    /// chunks use UTF-16 units even when these wire bytes are UTF-8.
    pub total_length: Option<u64>,
    ended: bool,
}
impl ValueStream<'_, '_> {
    pub async fn next_chunk(&mut self) -> Result<Option<crate::Chunk>> {
        if self.ended {
            return Ok(None);
        }
        match self.response.next_event().await? {
            Some(Record::ValueChunk(chunk)) => Ok(Some(chunk)),
            Some(Record::ValueEnd) => {
                self.ended = true;
                Ok(None)
            }
            _ => Err(Error::malformed(0, "expected large value chunk")),
        }
    }
    pub async fn finish(&mut self) -> Result<()> {
        while self.next_chunk().await?.is_some() {}
        Ok(())
    }
}
