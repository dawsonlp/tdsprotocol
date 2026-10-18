//! Offline request reading. These definitions describe received evidence; they
//! grant no connection authority and never reconstruct executable producers.
//! Input TYPE_INFO differs from result metadata for CLR, JSON and legacy text.
use super::{ParamValue, Sort, TableColumn, TableType};
use crate::{Error, ErrorKind, Result, SqlText, SqlType, TypeInfo, Value, large, wire::Reader};

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u16,
    pub bytes: Vec<u8>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Parameter {
    pub name: SqlText,
    pub status: u8,
    pub type_info: TypeInfo,
    pub value: ParamValue,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call {
    /// Built-in numbers are kept even if this client cannot call them.
    pub procedure: Procedure,
    pub options: u16,
    pub parameters: Vec<Parameter>,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Procedure {
    Name(SqlText),
    Number(u16),
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Batch {
        headers: Vec<Header>,
        sql: SqlText,
    },
    Rpc {
        headers: Vec<Header>,
        calls: Vec<Call>,
    },
    Transaction {
        headers: Vec<Header>,
        operation: crate::Transaction,
    },
    Attention,
}
pub(crate) fn text(r: &mut Reader<'_>, count: usize) -> Result<SqlText> {
    Ok(SqlText(
        r.take(count * 2)?
            .as_chunks::<2>()
            .0
            .iter()
            .map(|b| u16::from_le_bytes(*b))
            .collect(),
    ))
}
fn short(r: &mut Reader<'_>) -> Result<SqlText> {
    let n = r.u8()?;
    text(r, usize::from(n))
}
fn headers(r: &mut Reader<'_>) -> Result<Vec<Header>> {
    let n = r.u32()? as usize;
    if n < 4 {
        return Err(Error::malformed(0, "ALL_HEADERS length"));
    }
    if n - 4 > r.remaining() {
        r.take(n - 4)?;
    }
    let mut result = vec![];
    while r.offset < n {
        let start = r.offset;
        let length = r.u32()? as usize;
        if length < 6 || length > n - start {
            return Err(Error::malformed(start, "header length"));
        }
        result.push(Header {
            kind: r.u16()?,
            bytes: r.take(length - 6)?.to_vec(),
        });
    }
    Ok(result)
}
/// Decode one complete supported request body. Errors refer to body offsets.
pub fn request(kind: u8, bytes: &[u8]) -> Result<Request> {
    if ![
        crate::packet::BATCH,
        crate::packet::RPC,
        crate::packet::TRANSACTION,
        crate::packet::ATTENTION,
    ]
    .contains(&kind)
    {
        return Err(Error::new(ErrorKind::Unsupported("request message")));
    }
    let mut r = Reader::new(bytes);
    if kind == crate::packet::ATTENTION {
        r.end()?;
        return Ok(Request::Attention);
    }
    let headers = headers(&mut r)?;
    let result = match kind {
        crate::packet::BATCH => {
            if !r.remaining().is_multiple_of(2) {
                return Err(Error::malformed(r.offset, "odd SQL text"));
            }
            let n = r.remaining() / 2;
            Request::Batch {
                headers,
                sql: text(&mut r, n)?,
            }
        }
        crate::packet::RPC => {
            let mut calls = vec![];
            loop {
                let n = r.u16()?;
                let procedure = if n == 0xffff {
                    Procedure::Number(r.u16()?)
                } else {
                    Procedure::Name(text(&mut r, usize::from(n))?)
                };
                let options = r.u16()?;
                let mut parameters = vec![];
                while r.peek().is_some_and(|b| b != 0xff && b != 0xfe) {
                    let name = short(&mut r)?;
                    let status = r.u8()?;
                    if status & !3 != 0 {
                        return Err(Error::new(ErrorKind::Unsupported(
                            "encrypted/extended RPC parameter",
                        )));
                    }
                    let (type_info, value) = parameter(&mut r)?;
                    parameters.push(Parameter {
                        name,
                        status,
                        type_info,
                        value,
                    });
                }
                calls.push(Call {
                    procedure,
                    options,
                    parameters,
                });
                if r.remaining() == 0 {
                    break;
                }
                if r.u8()? != 0xff {
                    return Err(Error::new(ErrorKind::Unsupported("NO_EXEC RPC separator")));
                }
            }
            Request::Rpc { headers, calls }
        }
        crate::packet::TRANSACTION => Request::Transaction {
            headers,
            operation: transaction(&mut r)?,
        },
        _ => return Err(Error::new(ErrorKind::Unsupported("request message"))),
    };
    r.end()?;
    Ok(result)
}
fn parameter(r: &mut Reader<'_>) -> Result<(TypeInfo, ParamValue)> {
    if r.peek() != Some(0xf3) {
        let info = TypeInfo::read_parameter(r)?;
        let value = input_value(&info, r)?;
        return Ok((info, ParamValue::Scalar(value)));
    }
    r.u8()?;
    let database = short(r)?;
    if !database.0.is_empty() {
        return Err(Error::malformed(r.offset, "TVP database must be empty"));
    }
    let mut table = TableType::new(short(r)?, short(r)?, vec![]);
    let n = r.u16()?;
    let rows = if n == 0xffff {
        if r.u8()? != 0 || r.u8()? != 0 {
            return Err(Error::malformed(r.offset, "NULL TVP terminators"));
        }
        None
    } else {
        let mut infos = vec![];
        for _ in 0..n {
            r.u32()?; // user type retained in raw packet evidence
            let flags = r.u16()?;
            if r.peek() == Some(0xf3) {
                return Err(Error::new(ErrorKind::Unsupported("nested table input")));
            }
            let info = TypeInfo::read_parameter(r)?;
            short(r)?; // unnamed TVP column
            table.columns.push(TableColumn {
                sql_type: info.sql_type.clone(),
                server_default: flags & 0x200 != 0,
            });
            infos.push(info);
        }
        let mut order_seen = false;
        let mut placement_seen = false;
        loop {
            match r.u8()? {
                0 => break,
                0x10 if !order_seen => {
                    order_seen = true;
                    for _ in 0..r.u16()? {
                        let column = r.u16()?;
                        let flags = r.u8()?;
                        if flags & !7 != 0 || flags & 3 == 3 {
                            return Err(Error::malformed(r.offset, "TVP order flags"));
                        }
                        match flags & 3 {
                            1 => table.order.push((column, Sort::Ascending)),
                            2 => table.order.push((column, Sort::Descending)),
                            _ => {}
                        }
                        if flags & 4 != 0 {
                            table.unique.push(column);
                        }
                    }
                }
                0x11 if !placement_seen => {
                    placement_seen = true;
                    for _ in 0..r.u16()? {
                        table.send_order.push(r.u16()?);
                    }
                    let mut sorted = table.send_order.clone();
                    sorted.sort_unstable();
                    if sorted != (1..=n).collect::<Vec<_>>() {
                        return Err(Error::malformed(r.offset, "TVP column placement"));
                    }
                }
                _ => return Err(Error::malformed(r.offset, "TVP metadata token")),
            }
        }
        let order = if table.send_order.is_empty() {
            (1..=n).collect::<Vec<_>>()
        } else {
            table.send_order.clone()
        };
        let mut rows = vec![];
        loop {
            match r.u8()? {
                0 => break,
                1 => {
                    let mut cells = vec![None; usize::from(n)];
                    for column in &order {
                        let i = usize::from(*column) - 1;
                        if !table.columns[i].server_default {
                            cells[i] = input_value(&infos[i], r)?;
                        }
                    }
                    rows.push(
                        cells
                            .into_iter()
                            .zip(&table.columns)
                            .filter_map(|(v, c)| (!c.server_default).then_some(v))
                            .collect(),
                    );
                }
                _ => return Err(Error::malformed(r.offset, "TVP row token")),
            }
        }
        Some(rows)
    };
    Ok((
        TypeInfo {
            sql_type: SqlType::Table(Box::new(table)),
            code: 0xf3,
            max_length: None,
            legacy: None,
            clr_assembly: None,
            json_utf8: false,
        },
        ParamValue::Table(rows),
    ))
}
/// Parameters use whole values; replay never turns bytes back into a producer.
pub(crate) fn input_value(info: &TypeInfo, r: &mut Reader<'_>) -> Result<Option<Value>> {
    if matches!(
        info.sql_type,
        SqlType::LegacyText { .. } | SqlType::LegacyImage
    ) {
        let n = r.u32()?;
        if n == u32::MAX {
            return Ok(None);
        }
        let bytes = r.take(n as usize)?;
        let mut value = large::empty(&info.sql_type);
        let chunk = match &info.sql_type {
            SqlType::LegacyText { unicode: true, .. } => {
                if !bytes.len().is_multiple_of(2) {
                    return Err(Error::malformed(r.offset, "odd legacy Unicode input"));
                }
                large::Chunk::Unicode(SqlText(
                    bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|b| u16::from_le_bytes(*b))
                        .collect(),
                ))
            }
            SqlType::LegacyText { collation, .. } => large::Chunk::Text(crate::SqlTextBytes {
                bytes: bytes.to_vec(),
                collation: *collation,
            }),
            _ => large::Chunk::Binary(bytes.to_vec()),
        };
        large::append(&mut value, chunk)?;
        return Ok(Some(value));
    }
    if !info.sql_type.is_large() {
        return info.read_value(r);
    }
    let Some(mut decoder) = large::Decoder::start(info, r)? else {
        return Ok(None);
    };
    let mut value = large::empty(&info.sql_type);
    loop {
        match decoder.next(r)? {
            large::Piece::End => return Ok(Some(value)),
            large::Piece::Chunk(chunk) => large::append(&mut value, chunk)?,
        }
    }
}
fn transaction_name(r: &mut Reader<'_>) -> Result<SqlText> {
    let n = usize::from(r.u8()?);
    if !n.is_multiple_of(2) {
        return Err(Error::malformed(r.offset, "transaction name length"));
    }
    text(r, n / 2)
}
fn begin(r: &mut Reader<'_>) -> Result<crate::transactions::Begin> {
    use crate::Isolation::*;
    let isolation = match r.u8()? {
        0 => Unchanged,
        1 => ReadUncommitted,
        2 => ReadCommitted,
        3 => RepeatableRead,
        4 => Serializable,
        5 => Snapshot,
        _ => return Err(Error::malformed(r.offset, "isolation")),
    };
    Ok(crate::transactions::Begin {
        isolation,
        name: transaction_name(r)?,
    })
}
fn transaction(r: &mut Reader<'_>) -> Result<crate::Transaction> {
    use crate::Transaction::*;
    Ok(match r.u16()? {
        0 => {
            if r.u16()? != 0 {
                return Err(Error::new(ErrorKind::Unsupported(
                    "coordinator address flags",
                )));
            }
            CoordinatorAddress
        }
        1 => {
            let n = usize::from(r.u16()?);
            Propagate(r.take(n)?.to_vec())
        }
        5 => Begin(begin(r)?),
        6 => Promote,
        code @ (7 | 8) => {
            let name = transaction_name(r)?;
            let begin = match r.u8()? {
                0 => None,
                1 => Some(begin(r)?),
                _ => return Err(Error::malformed(r.offset, "transaction end flags")),
            };
            let end = crate::transactions::End { name, begin };
            if code == 7 {
                Commit(end)
            } else {
                Rollback(end)
            }
        }
        9 => Save(transaction_name(r)?),
        _ => return Err(Error::new(ErrorKind::Unsupported("transaction operation"))),
    })
}

/// Bulk metadata has input declarations and whole-cell input payloads. A known
/// PLP length in bulk is followed by the raw bytes, without chunk headers.
pub fn bulk(bytes: &[u8]) -> Result<Vec<crate::Record>> {
    use crate::tokens::{Column, Done, DoneKind};
    let mut r = Reader::new(bytes);
    if r.u8()? != 0x81 {
        return Err(Error::malformed(0, "bulk COLMETADATA"));
    }
    let mut columns = vec![];
    for _ in 0..r.u16()? {
        let user_type = r.u32()?;
        let flags = r.u16()?;
        let type_info = TypeInfo::read_parameter(&mut r)?;
        columns.push(Column {
            user_type,
            flags,
            type_info,
            name: short(&mut r)?,
        });
    }
    let mut records = vec![crate::Record::Columns(columns.clone())];
    loop {
        match r.u8()? {
            0xd1 => {
                let mut row = vec![];
                for column in &columns {
                    let info = &column.type_info;
                    let at = r.offset;
                    if info.sql_type.is_large()
                        && !matches!(
                            info.sql_type,
                            SqlType::LegacyText { .. } | SqlType::LegacyImage
                        )
                    {
                        let total = r.u64()?;
                        if total < u64::MAX - 1 {
                            let n = usize::try_from(total)
                                .map_err(|_| Error::malformed(at, "bulk length"))?;
                            let raw = r.take(n)?;
                            // Reuse the normal PLP reader by supplying its missing
                            // chunk header; exact input encodings still apply.
                            let size = u32::try_from(n)
                                .map_err(|_| Error::malformed(at, "bulk cell length"))?;
                            let mut plp = total.to_le_bytes().to_vec();
                            if size != 0 {
                                plp.extend(size.to_le_bytes());
                                plp.extend(raw);
                            }
                            plp.extend(0_u32.to_le_bytes());
                            row.push(input_value(info, &mut Reader::new(&plp))?);
                            continue;
                        }
                        r.offset = at;
                    }
                    row.push(input_value(info, &mut r)?);
                }
                records.push(crate::Record::Row(row));
            }
            0xfd => {
                let status = r.u16()?;
                let command = r.u16()?;
                let rows = r.u64()?;
                records.push(crate::Record::Done(Done {
                    kind: DoneKind::Statement,
                    status,
                    command,
                    row_count: (status & 0x10 != 0).then_some(rows),
                }));
                r.end()?;
                return Ok(records);
            }
            _ => return Err(Error::malformed(r.offset - 1, "bulk token")),
        }
    }
}
