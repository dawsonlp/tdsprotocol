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
    pub enclave_package: Vec<u8>,
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
        enclave_package: Vec<u8>,
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
    let n = r.field("headers length", |r| r.u32())? as usize;
    if n < 4 {
        return Err(Error::malformed(0, "ALL_HEADERS length"));
    }
    if n - 4 > r.remaining() {
        r.take(n - 4)?;
    }
    let mut result = vec![];
    while r.offset < n {
        let start = r.offset;
        let length = r.field("header length", |r| r.u32())? as usize;
        if length < 6 || length > n - start {
            return Err(Error::malformed(start, "header length"));
        }
        let kind = r.field("header type", |r| r.u16())?;
        let bytes = r.field("header data", |r| {
            let start = r.offset;
            if kind == 2 && length == 18 {
                r.field("transaction descriptor", |r| r.u64())?;
                r.field("outstanding requests", |r| r.u32())?;
            } else {
                r.take(length - 6)?;
            }
            Ok(r.bytes()[start..r.offset].to_vec())
        })?;
        result.push(Header { kind, bytes });
    }
    Ok(result)
}
/// Decode one complete supported request body. Errors refer to body offsets.
pub fn request(kind: u8, bytes: &[u8]) -> Result<Request> {
    request_reader(kind, &mut Reader::new(bytes))
}
pub fn request_with_enclaves(kind: u8, bytes: &[u8], enclaves: bool) -> Result<Request> {
    request_reader_with_enclaves(kind, &mut Reader::new(bytes), enclaves)
}
pub(crate) fn request_reader(kind: u8, r: &mut Reader<'_>) -> Result<Request> {
    request_reader_with_enclaves(kind, r, false)
}
pub(crate) fn request_reader_with_enclaves(
    kind: u8,
    r: &mut Reader<'_>,
    enclaves: bool,
) -> Result<Request> {
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
    if kind == crate::packet::ATTENTION {
        r.end()?;
        return Ok(Request::Attention);
    }
    let headers = headers(r)?;
    let result = match kind {
        crate::packet::BATCH => {
            let enclave_package = package(r, enclaves)?;
            if !r.remaining().is_multiple_of(2) {
                return Err(Error::malformed(r.offset, "odd SQL text"));
            }
            let n = r.remaining() / 2;
            Request::Batch {
                headers,
                enclave_package,
                sql: r.text("sql", |r| text(r, n))?,
            }
        }
        crate::packet::RPC => {
            let mut calls = vec![];
            loop {
                calls.push(r.indexed("call", calls.len(), |r| call(r, enclaves))?);
                if r.remaining() == 0 {
                    break;
                }
                if r.field("call separator", |r| r.u8())? != 0xff {
                    return Err(Error::new(ErrorKind::Unsupported("NO_EXEC RPC separator")));
                }
            }
            Request::Rpc { headers, calls }
        }
        crate::packet::TRANSACTION => Request::Transaction {
            headers,
            operation: r.field("operation", transaction)?,
        },
        _ => return Err(Error::new(ErrorKind::Unsupported("request message"))),
    };
    r.end()?;
    Ok(result)
}
fn package(r: &mut Reader<'_>, enclaves: bool) -> Result<Vec<u8>> {
    if !enclaves {
        return Ok(Vec::new());
    }
    r.field("enclave package", |r| {
        let length = usize::from(r.u16()?);
        Ok(r.take(length)?.to_vec())
    })
}
fn call(r: &mut Reader<'_>, enclaves: bool) -> Result<Call> {
    let n = r.field("procedure name length", |r| r.u16())?;
    let procedure = if n == 0xffff {
        Procedure::Number(r.field("procedure number", |r| r.u16())?)
    } else {
        Procedure::Name(r.text("procedure name", |r| text(r, usize::from(n)))?)
    };
    let options = r.field("options", |r| r.u16())?;
    let enclave_package = package(r, enclaves)?;
    let mut parameters = vec![];
    while r.peek().is_some_and(|b| b != 0xff && b != 0xfe) {
        parameters.push(r.indexed("parameter", parameters.len(), |r| {
            let name = r.text("name", short)?;
            let status = r.field("status", |r| r.u8())?;
            if status & !11 != 0 {
                return Err(Error::new(ErrorKind::Unsupported(
                    "encrypted/extended RPC parameter",
                )));
            }
            let (mut type_info, mut value) = parameter(r)?;
            if status & 8 != 0 {
                let base = TypeInfo::read_parameter(r)?;
                let algorithm = r.u8()?;
                let algorithm_name = if algorithm == 0 {
                    Some(short(r)?)
                } else {
                    None
                };
                let encryption_type = r.u8()?;
                let database_id = r.u32()?;
                let key_id = r.u32()?;
                let version = r.u32()?;
                let metadata_version = r.take(8)?.try_into().expect("eight bytes");
                let normalization = r.u8()?;
                if ![1, 2].contains(&encryption_type) {
                    return Err(Error::malformed(r.offset, "parameter encryption type"));
                }
                type_info.encryption = Some(Box::new(crate::types::crypto::CryptoMetadata {
                    base,
                    user_type: 0,
                    algorithm,
                    algorithm_name,
                    encryption_type,
                    normalization,
                    key: Some(crate::types::crypto::ColumnKey {
                        database_id,
                        key_id,
                        version,
                        metadata_version,
                        values: vec![],
                    }),
                }));
                value = match value {
                    ParamValue::Scalar(Some(Value::Binary(bytes))) => {
                        ParamValue::Scalar(Some(Value::Encrypted(crate::values::Ciphertext(bytes))))
                    }
                    ParamValue::Scalar(None) => ParamValue::Scalar(None),
                    _ => {
                        return Err(Error::malformed(
                            r.offset,
                            "encrypted parameter must be binary",
                        ));
                    }
                };
            }
            Ok(Parameter {
                name,
                status,
                type_info,
                value,
            })
        })?);
    }
    Ok(Call {
        procedure,
        options,
        enclave_package,
        parameters,
    })
}
fn parameter(r: &mut Reader<'_>) -> Result<(TypeInfo, ParamValue)> {
    if r.peek() != Some(0xf3) {
        let info = r.field("type", TypeInfo::read_parameter)?;
        let value = r.field("value", |r| input_value(&info, r))?;
        return Ok((info, ParamValue::Scalar(value)));
    }
    r.field("table type code", |r| r.u8())?;
    let database = r.text("database", short)?;
    if !database.0.is_empty() {
        return Err(Error::malformed(r.offset, "TVP database must be empty"));
    }
    let mut table = TableType::new(
        r.text("schema", short)?,
        r.text("table type", short)?,
        vec![],
    );
    let n = r.field("column count", |r| r.u16())?;
    let rows = if n == 0xffff {
        if r.field("metadata terminator", |r| r.u8())? != 0
            || r.field("rows terminator", |r| r.u8())? != 0
        {
            return Err(Error::malformed(r.offset, "NULL TVP terminators"));
        }
        None
    } else {
        let mut infos = vec![];
        for column in 0..n {
            let (info, flags) = r.indexed("column", usize::from(column), |r| {
                r.field("user type", |r| r.u32())?;
                let flags = r.field("flags", |r| r.u16())?;
                if r.peek() == Some(0xf3) {
                    return Err(Error::new(ErrorKind::Unsupported("nested table input")));
                }
                let info = r.field("type", TypeInfo::read_parameter)?;
                r.text("name", short)?; // unnamed TVP column
                Ok((info, flags))
            })?;
            table.columns.push(TableColumn {
                sql_type: info.sql_type.clone(),
                server_default: flags & 0x200 != 0,
            });
            infos.push(info);
        }
        let mut order_seen = false;
        let mut placement_seen = false;
        loop {
            match r.field("table metadata tag", |r| r.u8())? {
                0 => break,
                0x10 if !order_seen => {
                    order_seen = true;
                    for _ in 0..r.field("order count", |r| r.u16())? {
                        let column = r.field("ordered column", |r| r.u16())?;
                        let flags = r.field("order flags", |r| r.u8())?;
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
                    for _ in 0..r.field("placement count", |r| r.u16())? {
                        table
                            .send_order
                            .push(r.field("placed column", |r| r.u16())?);
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
            match r.field("table row tag", |r| r.u8())? {
                0 => break,
                1 => {
                    let mut cells = vec![None; usize::from(n)];
                    for column in &order {
                        let i = usize::from(*column) - 1;
                        if !table.columns[i].server_default {
                            cells[i] = r.indexed("cell", i, |r| input_value(&infos[i], r))?;
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
            encryption: None,
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
        let n = r.field("length", |r| r.u32())?;
        if n == u32::MAX {
            return Ok(None);
        }
        let bytes = r.field("data", |r| r.take(n as usize))?;
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
    if info.encryption.is_some() || !info.sql_type.is_large() {
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
    let n = usize::from(r.field("name byte length", |r| r.u8())?);
    if !n.is_multiple_of(2) {
        return Err(Error::malformed(r.offset, "transaction name length"));
    }
    r.text("name", |r| text(r, n / 2))
}
fn begin(r: &mut Reader<'_>) -> Result<crate::transactions::Begin> {
    use crate::Isolation::*;
    let isolation = match r.field("isolation", |r| r.u8())? {
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
    Ok(match r.field("operation code", |r| r.u16())? {
        0 => {
            if r.field("coordinator flags", |r| r.u16())? != 0 {
                return Err(Error::new(ErrorKind::Unsupported(
                    "coordinator address flags",
                )));
            }
            CoordinatorAddress
        }
        1 => {
            let n = usize::from(r.field("propagation length", |r| r.u16())?);
            Propagate(r.field("propagation data", |r| r.take(n))?.to_vec())
        }
        5 => Begin(begin(r)?),
        6 => Promote,
        code @ (7 | 8) => {
            let name = transaction_name(r)?;
            let begin = match r.field("end flags", |r| r.u8())? {
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
    bulk_with_encryption(bytes, false)
}
pub fn bulk_with_encryption(bytes: &[u8], encrypted: bool) -> Result<Vec<crate::Record>> {
    bulk_reader(&mut Reader::new(bytes), encrypted)
}
pub(crate) fn bulk_reader(r: &mut Reader<'_>, encrypted: bool) -> Result<Vec<crate::Record>> {
    use crate::tokens::{Column, Done, DoneKind};
    if r.field("metadata tag", |r| r.u8())? != 0x81 {
        return Err(Error::malformed(0, "bulk COLMETADATA"));
    }
    let mut columns = vec![];
    let count = r.field("column count", |r| r.u16())?;
    if count > 4096 {
        return Err(Error::new(ErrorKind::Limit("bulk column count")));
    }
    let keys = if encrypted {
        crate::types::crypto::key_table(r)?
    } else {
        vec![]
    };
    for _ in 0..count {
        let user_type = r.field("user type", |r| r.u32())?;
        let flags = r.field("column flags", |r| r.u16())?;
        let mut type_info = r.field("type", TypeInfo::read_parameter)?;
        if flags & 0x800 != 0 {
            if !encrypted {
                return Err(Error::malformed(
                    r.offset,
                    "encrypted bulk without negotiation",
                ));
            }
            let ordinal = usize::from(r.u16()?);
            let key = keys
                .get(ordinal)
                .ok_or_else(|| Error::malformed(r.offset, "bulk column key ordinal"))?
                .clone();
            type_info.encryption = Some(Box::new(crate::types::crypto::CryptoMetadata::read(
                r,
                Some(key),
            )?));
        }
        columns.push(Column {
            user_type,
            flags,
            type_info,
            name: r.text("column name", short)?,
        });
    }
    let mut records = vec![crate::Record::Columns(columns.clone())];
    loop {
        match r.field("token tag", |r| r.u8())? {
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
                        let total = r.field("total length", |r| r.u64())?;
                        if total < u64::MAX - 1 {
                            let n = usize::try_from(total)
                                .map_err(|_| Error::malformed(at, "bulk length"))?;
                            let raw = r.field("data", |r| r.take(n))?;
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
                    row.push(r.indexed("cell", row.len(), |r| input_value(info, r))?);
                }
                records.push(crate::Record::Row(row));
            }
            0xfd => {
                let status = r.field("status", |r| r.u16())?;
                let command = r.field("command", |r| r.u16())?;
                let rows = r.field("row count", |r| r.u64())?;
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
