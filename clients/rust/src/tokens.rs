//! Tokens carry login announcements and the ordered response record.
//! Reference: `docs/design/3-reference/token-stream.md`, `login-response.md`,
//! and `response.md`; MS-TDS v20260617 §2.2.7.
//!
//! Decode one complete token before committing metadata or consuming bytes.
//! A bounded token with a truncated field is malformed, not awaiting more input.
//! Unknown tokens/types fail: guessing a length would desynchronize the stream.

use crate::{
    Error, ErrorKind, Result,
    wire::{self, Reader},
};

pub use crate::values::SqlText;
mod classification;
pub use classification::{DataClassification, Label, Sensitivity};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ServerMessage {
    pub number: i32,
    pub state: u8,
    pub severity: u8,
    pub text: SqlText,
    pub server: SqlText,
    pub procedure: SqlText,
    pub line: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnvironmentChange {
    Routing(RoutingChange),
    Text {
        kind: u8,
        new: SqlText,
        old: SqlText,
    },
    Bytes {
        kind: u8,
        new: Vec<u8>,
        old: Vec<u8>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutingChange {
    pub protocol: u8,
    pub port: u16,
    pub server: SqlText,
    pub old_length: u16,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Column {
    pub user_type: u32,
    pub flags: u16,
    pub type_info: crate::types::TypeInfo,
    pub name: SqlText,
}

/// Browse metadata numbers columns/tables from one; table zero is an expression.
/// Flags remain exact protocol bits (expression/key/hidden/different name).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ColumnInfo {
    pub column: u8,
    pub table: u8,
    pub status: u8,
    pub base_name: Option<SqlText>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DoneKind {
    Statement,
    Procedure,
    InProcedure,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Done {
    pub kind: DoneKind,
    pub status: u16,
    pub command: u16,
    pub row_count: Option<u64>,
}
impl Done {
    pub fn acknowledges_cancel(&self) -> bool {
        self.status & 0x20 != 0
    }
    pub fn is_final(&self) -> bool {
        self.status & 1 == 0 && self.kind != DoneKind::InProcedure
    }
    pub fn has_error(&self) -> bool {
        self.status & (2 | 256) != 0
    }
}

/// The first slice exposes records in wire order; it does not infer operations.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Record {
    ReturnStatus(i32),
    OutputValue(OutputValue),
    FeatureAck(Vec<(u8, Vec<u8>)>),
    SessionState(SessionStateChange),
    Environment(EnvironmentChange),
    Message(ServerMessage),
    Error(ServerMessage),
    LoginAck {
        version: u32,
        program: SqlText,
        server_version: [u8; 4],
    },
    Columns(Vec<Column>),
    Row(crate::response::Row),
    /// Incremental rows are emitted only when metadata contains a large type.
    RowStart,
    Cell(Option<crate::Value>),
    ValueStart {
        sql_type: crate::SqlType,
        total_length: Option<u64>,
    },
    ValueChunk(crate::Chunk),
    ValueEnd,
    RowEnd,
    Classification(DataClassification),
    Tables(Vec<Vec<SqlText>>),
    ColumnInfo(Vec<ColumnInfo>),
    Order(Vec<u16>),
    Done(Done),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionStateChange {
    pub sequence: u32,
    pub status: u8,
    pub states: Vec<(u8, Vec<u8>)>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OutputValue {
    pub ordinal: u16,
    pub name: SqlText,
    pub function_result: bool,
    pub user_type: u32,
    pub flags: u16,
    pub type_info: crate::TypeInfo,
    pub value: Option<crate::Value>,
}

/// State values are opaque; their length uses a byte, or FF followed by u32.
pub(crate) fn states(r: &mut Reader<'_>, length: usize) -> Result<Vec<(u8, Vec<u8>)>> {
    let end = r
        .offset
        .checked_add(length)
        .ok_or_else(|| Error::malformed(r.offset, "state length"))?;
    let mut values = Vec::new();
    while r.offset < end {
        let id = r.u8()?;
        let short = r.u8()?;
        let n = if short == 0xff {
            r.u32()? as usize
        } else {
            usize::from(short)
        };
        values.push((id, r.take(n)?.to_vec()));
    }
    if r.offset != end {
        return Err(Error::malformed(r.offset, "state boundary"));
    }
    Ok(values)
}

fn text(r: &mut Reader<'_>, n: usize) -> Result<SqlText> {
    let bytes = r.take(
        n.checked_mul(2)
            .ok_or_else(|| Error::malformed(r.offset, "UTF-16 length"))?,
    )?;
    Ok(SqlText(
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes([b[0], b[1]]))
            .collect(),
    ))
}
fn short_text(r: &mut Reader<'_>) -> Result<SqlText> {
    let n = usize::from(r.u8()?);
    text(r, n)
}
fn long_text(r: &mut Reader<'_>) -> Result<SqlText> {
    let n = usize::from(r.u16()?);
    text(r, n)
}
fn short_bytes(r: &mut Reader<'_>) -> Result<Vec<u8>> {
    let n = usize::from(r.u8()?);
    Ok(r.take(n)?.to_vec())
}

fn output_header(r: &mut Reader<'_>, utf8: bool) -> Result<OutputValue> {
    let ordinal = r.u16()?;
    let name = short_text(r)?;
    let status = r.u8()?;
    if ![1, 2].contains(&status) {
        return Err(Error::malformed(r.offset, "RETURNVALUE status"));
    }
    let user_type = r.u32()?;
    let flags = r.u16()?;
    if flags & 0x800 != 0 {
        return Err(Error::new(ErrorKind::Unsupported(
            "encrypted output parameter",
        )));
    }
    Ok(OutputValue {
        ordinal,
        name,
        function_result: status == 2,
        user_type,
        flags,
        type_info: read_info(r, utf8)?,
        value: None,
    })
}

struct RowState {
    index: usize,
    nulls: Vec<u8>,
    value: Option<crate::large::Decoder>,
}
struct OutputState {
    output: OutputValue,
    value: crate::large::Decoder,
}
#[derive(Default)]
pub struct Decoder {
    pending: Vec<u8>,
    row: Option<RowState>,
    output: Option<OutputState>,
    columns: Option<Vec<Column>>,
    metadata: std::collections::VecDeque<Vec<Column>>,
    classification_version: u8,
    utf8_support: bool,
}
impl Decoder {
    pub fn set_utf8_support(&mut self, enabled: bool) {
        self.utf8_support = enabled;
    }
    pub fn set_classification_version(&mut self, version: u8) -> Result<()> {
        if version > 2 {
            return Err(Error::new(ErrorKind::Unsupported("classification version")));
        }
        self.classification_version = version;
        Ok(())
    }
    pub(crate) fn set_metadata(&mut self, columns: Vec<Vec<Column>>) {
        self.metadata = columns.into();
    }
    pub fn feed(&mut self, bytes: &[u8]) -> Result<()> {
        wire::append(&mut self.pending, bytes)
    }
    pub fn is_empty(&self) -> bool {
        self.pending.is_empty() && self.row.is_none() && self.output.is_none()
    }
    pub(crate) fn buffered_bytes(&self) -> usize {
        self.pending.len()
    }
    pub fn next_record(&mut self) -> Result<Option<Record>> {
        if self.row.is_some() {
            return self.row_record();
        }
        if self.output.is_some() {
            return self.output_record();
        }
        let mut r = Reader::new(&self.pending);
        // Commit only the row header; cells and large payloads then advance
        // independently, rather than retaining an unbounded transactional row.
        if self
            .pending
            .first()
            .is_some_and(|tag| [0xd1, 0xd2].contains(tag))
            && self
                .columns
                .as_ref()
                .is_some_and(|cs| cs.iter().any(|c| c.type_info.sql_type.is_large()))
        {
            let tag = r.u8()?;
            let count = self.columns.as_ref().unwrap().len();
            let nulls = if tag == 0xd2 {
                match r.take(count.div_ceil(8)) {
                    Ok(bytes) => bytes.to_vec(),
                    Err(_) => return Ok(None),
                }
            } else {
                Vec::new()
            };
            self.row = Some(RowState {
                index: 0,
                nulls,
                value: None,
            });
            self.pending.drain(..r.offset);
            return Ok(Some(Record::RowStart));
        }
        if self.pending.first() == Some(&0xac) {
            r.u8()?; // RETURNVALUE
            let output = match output_header(&mut r, self.utf8_support) {
                Ok(output) => output,
                Err(Error {
                    kind: ErrorKind::Incomplete { .. },
                    ..
                }) => return Ok(None),
                Err(e) => return Err(e),
            };
            if output.type_info.sql_type.is_large() {
                let value = match crate::large::Decoder::start(&output.type_info, &mut r) {
                    Ok(value) => value,
                    Err(Error {
                        kind: ErrorKind::Incomplete { .. },
                        ..
                    }) => return Ok(None),
                    Err(e) => return Err(e),
                };
                self.pending.drain(..r.offset);
                let mut output = output;
                if let Some(value) = value {
                    output.value = Some(crate::large::empty(&output.type_info.sql_type));
                    self.output = Some(OutputState { output, value });
                    return self.output_record();
                }
                return Ok(Some(Record::OutputValue(output)));
            }
            let mut output = output;
            output.value = match output.type_info.read_value(&mut r) {
                Ok(value) => value,
                Err(Error {
                    kind: ErrorKind::Incomplete { .. },
                    ..
                }) => return Ok(None),
                Err(e) => return Err(e),
            };
            self.pending.drain(..r.offset);
            return Ok(Some(Record::OutputValue(output)));
        }
        let mut r = Reader::new(&self.pending);
        let parsed = self.decode(&mut r);
        let record = match parsed {
            Ok(record) => record,
            Err(Error {
                kind: ErrorKind::Incomplete { .. },
                ..
            }) => return Ok(None),
            Err(e) => return Err(e),
        };
        let n = r.offset;
        if let Record::Columns(columns) = &record {
            self.columns = Some(columns.clone());
            if self.pending.starts_with(&[0x81, 0xff, 0xff]) {
                self.metadata.pop_front();
            }
        }
        if let Record::Done(_) = &record {
            self.columns = None;
        }
        self.pending.drain(..n);
        Ok(Some(record))
    }
    fn row_record(&mut self) -> Result<Option<Record>> {
        let row = self.row.as_mut().unwrap();
        let columns = self.columns.as_ref().unwrap();
        if row.index == columns.len() {
            self.row = None;
            return Ok(Some(Record::RowEnd));
        }
        let mut r = Reader::new(&self.pending);
        let parsed = if let Some(value) = &mut row.value {
            // A chunk reader commits consumed framing even if the next piece
            // needs another packet. Its own state carries the exact boundary.
            let part = value.next(&mut r);
            self.pending.drain(..r.offset);
            match part {
                Ok(crate::large::Piece::Chunk(chunk)) => Ok(Record::ValueChunk(chunk)),
                Ok(crate::large::Piece::End) => {
                    row.value = None;
                    row.index += 1;
                    Ok(Record::ValueEnd)
                }
                Err(Error {
                    kind: ErrorKind::Incomplete { .. },
                    ..
                }) => return Ok(None),
                Err(e) => return Err(e),
            }
        } else {
            let sql_type = &columns[row.index].type_info.sql_type;
            let value = if !row.nulls.is_empty()
                && row.nulls[row.index / 8] & (1 << (row.index % 8)) != 0
            {
                Ok(Record::Cell(None))
            } else if sql_type.is_large() {
                crate::large::Decoder::start(&columns[row.index].type_info, &mut r).map(|value| {
                    if let Some(value) = value {
                        let total_length = value.total_length;
                        row.value = Some(value);
                        Record::ValueStart {
                            sql_type: sql_type.clone(),
                            total_length,
                        }
                    } else {
                        Record::Cell(None)
                    }
                })
            } else {
                columns[row.index]
                    .type_info
                    .read_value(&mut r)
                    .map(Record::Cell)
            };
            match value {
                Ok(record) => {
                    self.pending.drain(..r.offset);
                    if matches!(record, Record::Cell(_)) {
                        row.index += 1;
                    }
                    Ok(record)
                }
                Err(Error {
                    kind: ErrorKind::Incomplete { .. },
                    ..
                }) => return Ok(None),
                Err(e) => return Err(e),
            }
        };
        parsed.map(Some)
    }
    fn output_record(&mut self) -> Result<Option<Record>> {
        loop {
            let state = self.output.as_mut().unwrap();
            let mut r = Reader::new(&self.pending);
            let part = state.value.next(&mut r);
            self.pending.drain(..r.offset);
            match part {
                Ok(crate::large::Piece::Chunk(chunk)) => {
                    crate::large::append(state.output.value.as_mut().unwrap(), chunk)?
                }
                Ok(crate::large::Piece::End) => {
                    return Ok(Some(Record::OutputValue(
                        self.output.take().unwrap().output,
                    )));
                }
                Err(Error {
                    kind: ErrorKind::Incomplete { .. },
                    ..
                }) => return Ok(None),
                Err(e) => return Err(e),
            }
        }
    }
    fn decode(&self, r: &mut Reader<'_>) -> Result<Record> {
        let tag = r.u8()?;
        match tag {
            0xa3 => {
                classification::read(r, self.classification_version).map(Record::Classification)
            }
            0x79 => Ok(Record::ReturnStatus(r.u32()? as i32)), // RETURNSTATUS, MS-TDS §2.2.7.18
            0xae => {
                let mut features = Vec::new();
                loop {
                    let id = r.u8()?;
                    if id == 0xff {
                        break;
                    }
                    let n = r.u32()? as usize;
                    features.push((id, r.take(n)?.to_vec()));
                }
                Ok(Record::FeatureAck(features))
            }
            0xe4 => {
                let n = r.u32()? as usize;
                let start = r.offset;
                let mut body = Reader::new(r.take(n)?);
                let value = (|| {
                    let sequence = body.u32()?;
                    let status = body.u8()?;
                    if status & !1 != 0 {
                        return Err(Error::malformed(start + 4, "SESSIONSTATE status"));
                    }
                    let values = states(&mut body, n.saturating_sub(5))?;
                    body.end()?;
                    Ok(Record::SessionState(SessionStateChange {
                        sequence,
                        status,
                        states: values,
                    }))
                })();
                value.map_err(|e: Error| match e.kind {
                    ErrorKind::Incomplete { offset, .. } => {
                        Error::malformed(start + offset, "truncated SESSIONSTATE")
                    }
                    _ => e,
                })
            }
            0xfd..=0xff => {
                let status = r.u16()?;
                let command = r.u16()?;
                let count = r.u64()?;
                Ok(Record::Done(Done {
                    kind: match tag {
                        0xfd => DoneKind::Statement,
                        0xfe => DoneKind::Procedure,
                        _ => DoneKind::InProcedure,
                    },
                    status,
                    command,
                    row_count: if status & 0x10 != 0 {
                        Some(count)
                    } else {
                        None
                    },
                }))
            }
            0x81 => {
                let count = r.u16()?;
                if count == 0xffff {
                    return self
                        .metadata
                        .front()
                        .cloned()
                        .map(|mut columns| {
                            for column in &mut columns {
                                column.type_info.json_utf8 =
                                    matches!(column.type_info.sql_type, crate::SqlType::Json)
                                        && self.utf8_support;
                            }
                            Record::Columns(columns)
                        })
                        .ok_or_else(|| {
                            Error::malformed(
                                r.offset,
                                "omitted column metadata without saved columns",
                            )
                        });
                }
                if count > 4096 {
                    return Err(Error::new(ErrorKind::Limit("column count (4096)")));
                }
                let mut columns = Vec::with_capacity(usize::from(count));
                for _ in 0..count {
                    let user_type = r.u32()?;
                    let flags = r.u16()?;
                    if flags & 0x800 != 0 {
                        return Err(Error::new(ErrorKind::Unsupported("encrypted column")));
                    }
                    let type_info = read_info(r, self.utf8_support)?;
                    columns.push(Column {
                        user_type,
                        flags,
                        type_info,
                        name: short_text(r)?,
                    });
                }
                Ok(Record::Columns(columns))
            }
            0xd1 | 0xd2 => {
                let columns = self
                    .columns
                    .as_ref()
                    .ok_or_else(|| Error::malformed(r.offset, "row without metadata"))?;
                let nulls = if tag == 0xd2 {
                    r.take(columns.len().div_ceil(8))?
                } else {
                    &[]
                };
                let mut values = Vec::with_capacity(columns.len());
                for (i, column) in columns.iter().enumerate() {
                    if tag == 0xd2 && nulls[i / 8] & (1 << (i % 8)) != 0 {
                        values.push(None);
                        continue;
                    }
                    values.push(column.type_info.read_value(r)?);
                }
                Ok(Record::Row(values))
            }
            0xaa | 0xab | 0xad | 0xe3 | 0xa9 | 0xa4 | 0xa5 => {
                let n = usize::from(r.u16()?);
                let start = r.offset;
                let mut body = Reader::new(r.take(n)?);
                let record = Self::bounded(tag, &mut body).map_err(|e| match e.kind {
                    ErrorKind::Incomplete { offset, .. } => {
                        Error::malformed(start + offset, "truncated token field")
                    }
                    _ => e,
                })?;
                body.end()?;
                Ok(record)
            }
            _ => Err(Error::new(ErrorKind::Unsupported("token tag"))),
        }
    }
    fn bounded(tag: u8, r: &mut Reader<'_>) -> Result<Record> {
        match tag {
            0xa4 => {
                let mut tables = Vec::new();
                while r.remaining() != 0 {
                    let count = r.u8()?;
                    let mut table = Vec::new();
                    for _ in 0..count {
                        table.push(long_text(r)?);
                    }
                    tables.push(table);
                }
                Ok(Record::Tables(tables))
            }
            0xa5 => {
                let mut columns = Vec::new();
                while r.remaining() != 0 {
                    let column = r.u8()?;
                    let table = r.u8()?;
                    let status = r.u8()?;
                    let base_name = if status & 0x20 != 0 {
                        Some(short_text(r)?)
                    } else {
                        None
                    };
                    columns.push(ColumnInfo {
                        column,
                        table,
                        status,
                        base_name,
                    });
                }
                Ok(Record::ColumnInfo(columns))
            }
            0xaa | 0xab => {
                let message = ServerMessage {
                    number: r.u32()? as i32,
                    state: r.u8()?,
                    severity: r.u8()?,
                    text: long_text(r)?,
                    server: short_text(r)?,
                    procedure: short_text(r)?,
                    line: r.u32()?,
                };
                Ok(if tag == 0xaa {
                    Record::Error(message)
                } else {
                    Record::Message(message)
                })
            }
            0xad => {
                if r.u8()? != 1 {
                    return Err(Error::malformed(0, "LOGINACK interface"));
                }
                let version = r.be32()?;
                let program = short_text(r)?;
                let bytes = r.take(4)?;
                let mut server_version = [0; 4];
                server_version.copy_from_slice(bytes);
                Ok(Record::LoginAck {
                    version,
                    program,
                    server_version,
                })
            }
            0xe3 => {
                let kind = r.u8()?;
                let change = match kind {
                    20 => {
                        let size = usize::from(r.u16()?);
                        let mut route = Reader::new(r.take(size)?);
                        let change = RoutingChange {
                            protocol: route.u8()?,
                            port: route.u16()?,
                            server: long_text(&mut route)?,
                            old_length: r.u16()?,
                        };
                        route.end()?;
                        EnvironmentChange::Routing(change)
                    }
                    1 | 2 | 4 => EnvironmentChange::Text {
                        kind,
                        new: short_text(r)?,
                        old: short_text(r)?,
                    },
                    7..=10 | 17 | 18 => EnvironmentChange::Bytes {
                        kind,
                        new: short_bytes(r)?,
                        old: short_bytes(r)?,
                    },
                    _ => {
                        return Err(Error::new(ErrorKind::Unsupported(
                            "environment change kind",
                        )));
                    }
                };
                Ok(Record::Environment(change))
            }
            0xa9 => {
                let mut columns = Vec::new();
                while let Ok(value) = r.u16() {
                    columns.push(value);
                }
                r.end()?;
                Ok(Record::Order(columns))
            }
            _ => Err(Error::new(ErrorKind::Unsupported("bounded token"))),
        }
    }
}

fn read_info(r: &mut Reader<'_>, utf8: bool) -> Result<crate::TypeInfo> {
    let mut info = crate::TypeInfo::read(r)?;
    info.json_utf8 = matches!(info.sql_type, crate::SqlType::Json) && utf8;
    Ok(info)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn saved_json_columns_use_the_current_sessions_encoding() {
        for utf8 in [false, true] {
            let mut d = Decoder::default();
            d.set_utf8_support(utf8);
            d.set_metadata(vec![vec![Column {
                user_type: 0,
                flags: 1,
                name: "j".into(),
                type_info: crate::TypeInfo {
                    sql_type: crate::SqlType::Json,
                    code: 0xf4,
                    max_length: None,
                    legacy: None,
                    clr_assembly: None,
                    json_utf8: !utf8,
                },
            }]]);
            let text = "{\"note\":\"é🦀\"}";
            let raw = if utf8 {
                text.as_bytes().to_vec()
            } else {
                text.encode_utf16().flat_map(u16::to_le_bytes).collect()
            };
            let mut bytes = vec![0x81, 0xff, 0xff, 0xd1];
            bytes.extend((raw.len() as u64).to_le_bytes());
            bytes.extend((raw.len() as u32).to_le_bytes());
            bytes.extend(raw);
            bytes.extend([0; 4]);
            let mut units = Vec::new();
            for byte in bytes {
                d.feed(&[byte]).unwrap();
                while let Some(record) = d.next_record().unwrap() {
                    if let Record::ValueChunk(crate::Chunk::Unicode(text)) = record {
                        units.extend(text.0);
                    }
                }
            }
            assert_eq!(units, text.encode_utf16().collect::<Vec<_>>());
            assert!(d.is_empty());
        }
    }
    use crate::Value::Integer as Int;
    #[test]
    fn signed_return_status_spans_each_byte_boundary() {
        let mut bytes = vec![0x79];
        bytes.extend((-7_i32).to_le_bytes());
        for cut in 0..=bytes.len() {
            let mut decoder = Decoder::default();
            decoder.feed(&bytes[..cut]).unwrap();
            if cut != bytes.len() {
                assert!(decoder.next_record().unwrap().is_none());
            }
            decoder.feed(&bytes[cut..]).unwrap();
            assert_eq!(
                decoder.next_record().unwrap(),
                Some(Record::ReturnStatus(-7))
            );
            assert!(decoder.next_record().unwrap().is_none());
        }
    }
    #[test]
    fn recovery_tokens_cross_each_byte_boundary_and_reject_truncated_bodies() {
        let initial = include_bytes!("../tests/fixtures/recovery/initial.bin");
        let mut bytes = vec![0xae, 1];
        bytes.extend((initial.len() as u32).to_le_bytes());
        bytes.extend(initial);
        bytes.push(255);
        bytes.extend([0xe4, 11, 0, 0, 0, 6, 0, 0, 0, 0, 254, 4, 5, 0, 0, 0]);
        for cut in 0..=bytes.len() {
            let mut decoder = Decoder::default();
            let mut records = Vec::new();
            for part in [&bytes[..cut], &bytes[cut..]] {
                decoder.feed(part).unwrap();
                while let Some(record) = decoder.next_record().unwrap() {
                    records.push(record);
                }
            }
            assert!(matches!(&records[0], Record::FeatureAck(values) if values.len() == 1));
            assert_eq!(
                records[1],
                Record::SessionState(SessionStateChange {
                    sequence: 6,
                    status: 0,
                    states: vec![(254, vec![5, 0, 0, 0])]
                })
            );
        }
        for body in [
            vec![],
            vec![0; 4],
            vec![0, 0, 0, 0, 2],
            vec![0, 0, 0, 0, 1, 9, 255],
        ] {
            let mut decoder = Decoder::default();
            let mut bytes = vec![0xe4];
            bytes.extend((body.len() as u32).to_le_bytes());
            bytes.extend(body);
            decoder.feed(&bytes).unwrap();
            assert!(matches!(
                decoder.next_record().unwrap_err().kind,
                ErrorKind::Malformed { .. }
            ));
        }
    }
    fn response() -> Vec<u8> {
        let mut b = vec![0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0x38, 0, 0xd1];
        b.extend((-123_i32).to_le_bytes());
        b.extend([0xfd, 0x10, 0, 0, 0]);
        b.extend(1_u64.to_le_bytes());
        b
    }
    #[test]
    fn tokens_cross_every_boundary_without_losing_metadata() {
        let bytes = response();
        for split in 0..=bytes.len() {
            let mut decoder = Decoder::default();
            let mut items = Vec::new();
            for fragment in [&bytes[..split], &bytes[split..]] {
                decoder.feed(fragment).unwrap();
                while let Some(item) = decoder.next_record().unwrap() {
                    items.push(item);
                }
            }
            assert_eq!(items.len(), 3);
            assert_eq!(items[1], Record::Row(vec![Some(Int(-123))]));
            assert!(matches!(
                &items[2],
                Record::Done(Done {
                    row_count: Some(1),
                    ..
                })
            ));
            assert!(decoder.is_empty());
        }
    }
    #[test]
    fn exact_text_keeps_unpaired_surrogates() {
        let mut r = Reader::new(&[0, 0xd8]);
        let s = text(&mut r, 1).unwrap();
        assert_eq!(s.0, [0xd800]);
        assert!(s.to_string().is_err());
    }
    #[test]
    fn truncated_bounded_token_is_malformed_and_unknown_type_is_refused() {
        let mut d = Decoder::default();
        d.feed(&[0xab, 1, 0, 0]).unwrap();
        assert!(matches!(
            d.next_record().unwrap_err().kind,
            ErrorKind::Malformed { .. }
        ));
        let mut d = Decoder::default();
        d.feed(&[0x81, 1, 0, 0, 0, 0, 0, 0, 0, 0xf3]).unwrap(); // deliberately unknown type
        assert!(matches!(
            d.next_record().unwrap_err().kind,
            ErrorKind::Unsupported(_)
        ));
    }
}
