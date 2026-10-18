//! The response record survives advancing the reader; ordinary rows do not.
//!
//! This follows Python's `tds.response` retention rules, not a second reading
//! policy. Fetch keeps complete result sets only. A set partly streamed before
//! fetch still has metadata and a row count, but cannot offer a complete row list.

use std::{fmt, time::Duration};

#[cfg(feature = "tokio")]
use crate::{Error, ErrorKind, Record, Result};
#[cfg(feature = "tokio")]
use std::collections::VecDeque;

#[cfg(feature = "tokio")]
use crate::tokens::DoneKind;
use crate::tokens::{Column, Done, EnvironmentChange, OutputValue, ServerMessage, SqlText};

pub type Row = Vec<Option<crate::values::Value>>;

/// Exchange milestones on a monotonic clock relative to one physical connection.
/// Collected at every observation level. `first_packet` is when the response
/// reader consumes its first complete TDS packet, not kernel arrival or server
/// execution time. Slow application consumption can delay it and `ended`.
/// Missing milestones remain unknown, including after partial sends/failures.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Timing {
    pub sent: Option<Duration>,
    pub first_packet: Option<Duration>,
    /// Terminal completion and its enclosing message have both been consumed.
    /// For cancellation this means acknowledged cleanup, not SQL success.
    pub ended: Option<Duration>,
}
impl Timing {
    pub fn until_first_packet(&self) -> Option<Duration> {
        self.first_packet?.checked_sub(self.sent?)
    }
    pub fn until_end(&self) -> Option<Duration> {
        self.ended?.checked_sub(self.sent?)
    }
    /// Presentation shared by live observation and saved recording events.
    pub fn summary(&self) -> String {
        [
            ("first packet", self.until_first_packet()),
            ("done", self.until_end()),
        ]
        .into_iter()
        .filter_map(|(label, elapsed)| {
            elapsed.map(|t| format!("{label} {:.3} ms", t.as_secs_f64() * 1000.0))
        })
        .collect::<Vec<_>>()
        .join(" · ")
    }
}

/// End-of-response access never reads ahead without the caller choosing what
/// happens to unread rows. This is Python's REFUSE/KEEP/DISCARD contract.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Unread {
    #[default]
    Refuse,
    Keep,
    Discard,
}

/// Result sets occupy one position in the ordered record, before their rows.
/// The index refers to `FetchedResponse::result_sets()`; rows are not items.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Item {
    ResultSet(usize),
    Completion(Done),
    Message(ServerMessage),
    Error(ServerMessage),
    Announcement(EnvironmentChange),
    SessionState(crate::tokens::SessionStateChange),
    ReturnStatus(i32),
    OutputValue(OutputValue),
}

/// One outermost call completed by DONEPROC. Kept independently of ordinary
/// rows, including when those rows are streamed or deliberately discarded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProcedureReturn {
    pub status: Option<i32>,
    pub outputs: Vec<OutputValue>,
    pub function_result: Option<OutputValue>,
    pub failed: bool,
    pub completion: Done,
}
impl ProcedureReturn {
    pub fn output_named(&self, name: &SqlText) -> Option<&OutputValue> {
        self.outputs.iter().find(|o| &o.name == name)
    }
    pub fn output_at(&self, ordinal: u16) -> Option<&OutputValue> {
        self.outputs.iter().find(|o| o.ordinal == ordinal)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RowsNotAvailable {
    StillArriving,
    NotRetained { rows_read: usize },
}
impl fmt::Display for RowsNotAvailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::StillArriving => f.write_str("result set is still arriving"),
            Self::NotRetained { rows_read } => write!(
                f,
                "{rows_read} rows arrived without every row being retained"
            ),
        }
    }
}
impl std::error::Error for RowsNotAvailable {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResultSet {
    pub columns: Vec<Column>,
    pub classification: Option<crate::tokens::DataClassification>,
    pub order: Option<Vec<u16>>,
    pub tables: Option<Vec<Vec<SqlText>>>,
    pub column_info: Option<Vec<crate::tokens::ColumnInfo>>,
    pub completion: Option<Done>,
    pub rows_read: usize,
    pub(crate) kept: Option<Vec<Row>>,
}
impl ResultSet {
    pub fn rows(&self) -> std::result::Result<&[Row], RowsNotAvailable> {
        if self.completion.is_none() {
            return Err(RowsNotAvailable::StillArriving);
        }
        match &self.kept {
            Some(rows) if rows.len() == self.rows_read => Ok(rows),
            _ => Err(RowsNotAvailable::NotRetained {
                rows_read: self.rows_read,
            }),
        }
    }
}

/// Owned data with no socket, channel or cancellation authority. A failure's
/// snapshot can be incomplete; a successful fetch has reached the terminal end.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct FetchedResponse {
    pub(crate) sequence: Vec<Item>,
    pub(crate) result_sets: Vec<ResultSet>,
    pub(crate) returns: Vec<ProcedureReturn>,
    pub ended: bool,
    pub canceled: bool,
    pub timing: Timing,
}
impl FetchedResponse {
    pub fn returns(&self) -> &[ProcedureReturn] {
        &self.returns
    }
    pub fn sequence(&self) -> &[Item] {
        &self.sequence
    }
    pub fn result_sets(&self) -> &[ResultSet] {
        &self.result_sets
    }
    pub fn completions(&self) -> impl Iterator<Item = &Done> {
        self.sequence.iter().filter_map(|item| {
            if let Item::Completion(done) = item {
                Some(done)
            } else {
                None
            }
        })
    }
    pub fn messages(&self) -> impl Iterator<Item = &ServerMessage> {
        self.sequence.iter().filter_map(|item| {
            if let Item::Message(message) = item {
                Some(message)
            } else {
                None
            }
        })
    }
    pub fn errors(&self) -> impl Iterator<Item = &ServerMessage> {
        self.sequence.iter().filter_map(|item| {
            if let Item::Error(error) = item {
                Some(error)
            } else {
                None
            }
        })
    }
}

/// Shared with the driver so autonomous Attention drain keeps the same record
/// as ordinary reading. Its short synchronous critical sections never await.
#[cfg(feature = "tokio")]
#[derive(Default)]
pub(crate) struct Retention {
    pub record: FetchedResponse,
    // Fetch reads ahead without consuming the live reader's position, including
    // when the driver is independently draining Attention acknowledgement.
    pub unread: VecDeque<Record>,
    current: Option<usize>,
    keep_new: bool,
    discard_new: bool,
    current_discarded: bool,
    return_status: Option<i32>,
    outputs: Vec<OutputValue>,
    function_result: Option<OutputValue>,
    row: Option<crate::Row>,
    value: Option<crate::Value>,
}
#[cfg(feature = "tokio")]
impl Retention {
    pub fn keep(&mut self) {
        self.keep_new = true;
        self.discard_new = false;
        if let Some(index) = self.current {
            let set = &mut self.record.result_sets[index];
            // Normal reads deliver one row at a time. If any row arrived before
            // keep(), it has already been handed out and cannot be reconstructed.
            if set.kept.is_none() && !self.current_discarded && set.rows_read == 0 {
                set.kept = Some(Vec::new());
            }
        }
    }
    pub fn discard(&mut self) {
        self.keep_new = false;
        self.discard_new = true;
        self.current_discarded = true;
        self.unread.clear();
        self.row = None;
        self.value = None;
    }
    pub fn take(&mut self, record: &Record) -> Result<()> {
        match record {
            Record::Columns(columns) => {
                let index = self.record.result_sets.len();
                self.record.result_sets.push(ResultSet {
                    columns: columns.clone(),
                    classification: None,
                    order: None,
                    tables: None,
                    column_info: None,
                    completion: None,
                    rows_read: 0,
                    kept: self.keep_new.then(Vec::new),
                });
                self.record.sequence.push(Item::ResultSet(index));
                self.current = Some(index);
                self.current_discarded = self.discard_new;
            }
            Record::Row(row) => {
                let keeping = !self.current_discarded;
                let set = self.current_set()?;
                set.rows_read = set
                    .rows_read
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorKind::Limit("result row count")))?;
                if keeping && let Some(rows) = &mut set.kept {
                    rows.push(row.clone());
                }
            }
            Record::RowStart => {
                self.current_set()?;
                self.row = (self.keep_new && !self.current_discarded).then(Vec::new);
            }
            Record::Cell(value) => {
                if let Some(row) = &mut self.row {
                    row.push(value.clone());
                }
            }
            Record::ValueStart { sql_type, .. } => {
                if self.row.is_some() {
                    self.value = Some(crate::large::empty(sql_type));
                }
            }
            Record::ValueChunk(chunk) => {
                if let Some(value) = &mut self.value {
                    crate::large::append(value, chunk.clone())?;
                }
            }
            Record::ValueEnd => {
                if let Some(row) = &mut self.row {
                    row.push(self.value.take());
                }
            }
            Record::RowEnd => {
                // Count complete rows, as Python does; a malformed or abandoned
                // partial value must not invent a successfully read row.
                let set = self.current_set()?;
                set.rows_read = set
                    .rows_read
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorKind::Limit("result row count")))?;
                if let Some(row) = self.row.take()
                    && let Some(rows) = &mut self.current_set()?.kept
                {
                    rows.push(row);
                }
            }
            Record::Classification(data) => self.current_set()?.classification = Some(data.clone()),
            Record::Tables(tables) => self.current_set()?.tables = Some(tables.clone()),
            Record::ColumnInfo(columns) => self.current_set()?.column_info = Some(columns.clone()),
            Record::Order(order) => self.current_set()?.order = Some(order.clone()),
            Record::Done(done) => {
                if let Some(index) = self.current.take() {
                    self.record.result_sets[index].completion = Some(done.clone());
                }
                self.record.sequence.push(Item::Completion(done.clone()));
                if done.kind == DoneKind::Procedure {
                    self.record.returns.push(ProcedureReturn {
                        status: self.return_status.take(),
                        outputs: std::mem::take(&mut self.outputs),
                        function_result: self.function_result.take(),
                        failed: done.has_error(),
                        completion: done.clone(),
                    });
                }
            }
            Record::Message(message) => self.record.sequence.push(Item::Message(message.clone())),
            Record::Error(error) => self.record.sequence.push(Item::Error(error.clone())),
            Record::Environment(change) => self
                .record
                .sequence
                .push(Item::Announcement(change.clone())),
            Record::SessionState(change) => self
                .record
                .sequence
                .push(Item::SessionState(change.clone())),
            Record::ReturnStatus(status) => {
                self.return_status = Some(*status);
                self.record.sequence.push(Item::ReturnStatus(*status));
            }
            Record::OutputValue(output) => {
                if output.function_result {
                    self.function_result = Some(output.clone());
                } else {
                    self.outputs.push(output.clone());
                }
                self.record.sequence.push(Item::OutputValue(output.clone()));
            }
            Record::LoginAck { .. } | Record::FeatureAck(_) => {
                return Err(Error::malformed(0, "LOGINACK in request response"));
            }
        }
        if self.keep_new {
            self.unread.push_back(record.clone());
        }
        Ok(())
    }
    fn current_set(&mut self) -> Result<&mut ResultSet> {
        let index = self
            .current
            .ok_or_else(|| Error::malformed(0, "result data outside a result set"))?;
        Ok(&mut self.record.result_sets[index])
    }
    pub fn end(&mut self, canceled: bool) {
        self.record.ended = true;
        self.record.canceled = canceled;
    }
}
