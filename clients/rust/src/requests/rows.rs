//! Whole cells form one row. A row producer is unique; it never owns channel
//! authority. TVP and bulk rows share scheduling, but have different wire tags
//! and metadata. Server semantic checks remain authoritative (D-53).
//!
//! ```no_run
//! # #[cfg(feature = "tokio")]
//! # async fn example(channel: &mut tds_client::SerialChannel) -> tds_client::Result<()> {
//! use tds_client::{Call, IntegerSize, Param, SqlType, StreamedCall, TableType, Value};
//! let table = TableType::new("dbo", "lines", vec![
//!     SqlType::Integer { size: IntegerSize::Int }.into(),
//! ]);
//! let call = Call::new("dbo.consume_lines", vec![Param::table("@lines", table, None)]);
//! let rows = vec![vec![Some(Value::Integer(42))]];
//! let request = StreamedCall::new(call).table_source(0, rows.into_iter());
//! channel.exchange(request).await?.finish().await?;
//! # Ok(()) }
//! ```
use super::*;
use crate::{Row, SqlText, SqlType, Value, tokens::Column};
use std::{future::Future, pin::Pin};

pub type RowRead<'a> = Pin<Box<dyn Future<Output = std::io::Result<Option<Row>>> + Send + 'a>>;
/// One unique producer of whole rows. `None` ends the table/upload; an empty
/// row is still a row. Implementations must yield without blocking the executor.
/// Errors use bounded partial-input cleanup, with no automatic retry.
pub trait RowSource: Send + 'static {
    fn next_row(&mut self) -> RowRead<'_>;
}
impl RowSource for std::vec::IntoIter<Row> {
    fn next_row(&mut self) -> RowRead<'_> {
        Box::pin(async { Ok(self.next()) })
    }
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableColumn {
    pub sql_type: SqlType,
    /// Omit this column's cell in every row; the server supplies its value.
    pub server_default: bool,
}
impl From<SqlType> for TableColumn {
    fn from(sql_type: SqlType) -> Self {
        Self {
            sql_type,
            server_default: false,
        }
    }
}
impl TableColumn {
    pub fn default_value(sql_type: SqlType) -> Self {
        Self {
            sql_type,
            server_default: true,
        }
    }
}
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sort {
    Ascending = 1,
    Descending = 2,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TableType {
    pub schema: SqlText,
    pub name: SqlText,
    pub columns: Vec<TableColumn>,
    /// One-based column numbers, as transmitted in TVP_ORDER_UNIQUE.
    pub order: Vec<(u16, Sort)>,
    pub unique: Vec<u16>,
    /// Empty means declaration order; otherwise place every column once,
    /// including default columns. Input row cells remain in declaration order.
    pub send_order: Vec<u16>,
}
impl TableType {
    pub fn new(
        schema: impl Into<SqlText>,
        name: impl Into<SqlText>,
        columns: Vec<TableColumn>,
    ) -> Self {
        Self {
            schema: schema.into(),
            name: name.into(),
            columns,
            order: vec![],
            unique: vec![],
            send_order: vec![],
        }
    }
    pub(crate) fn info(&self) -> Result<Vec<u8>> {
        let mut b = vec![0xf3, 0];
        short(&self.schema, &mut b)?;
        short(&self.name, &mut b)?;
        Ok(b)
    }
    pub(crate) fn header(&self, present: bool) -> Result<Vec<u8>> {
        if !present {
            return Ok(vec![0xff, 0xff, 0, 0]);
        }
        if !self.send_order.is_empty() {
            let mut order = self.send_order.clone();
            order.sort_unstable();
            if order
                != (1..=self.columns.len())
                    .map(|n| n as u16)
                    .collect::<Vec<_>>()
            {
                return Err(refused("table send_order must place every column once"));
            }
        }
        let mut b = Vec::new();
        count(self.columns.len(), &mut b)?;
        for column in &self.columns {
            b.extend([0; 4]);
            b.extend((1_u16 | if column.server_default { 0x200 } else { 0 }).to_le_bytes());
            b.extend(type_info(&column.sql_type)?);
            b.push(0);
        }
        let mut entries = self
            .order
            .iter()
            .map(|(n, sort)| {
                (
                    *n,
                    *sort as u8 | if self.unique.contains(n) { 4 } else { 0 },
                )
            })
            .collect::<Vec<_>>();
        for n in &self.unique {
            if !self.order.iter().any(|(i, _)| i == n) {
                entries.push((*n, 4));
            }
        }
        if !entries.is_empty() {
            b.push(0x10);
            count(entries.len(), &mut b)?;
            for (n, flags) in entries {
                b.extend(n.to_le_bytes());
                b.push(flags);
            }
        }
        if !self.send_order.is_empty() {
            b.push(0x11);
            count(self.send_order.len(), &mut b)?;
            for n in &self.send_order {
                b.extend(n.to_le_bytes());
            }
        }
        b.push(0);
        Ok(b)
    }
    pub(crate) fn row(&self, row: &Row) -> Result<Vec<u8>> {
        let given = self
            .columns
            .iter()
            .enumerate()
            .filter(|(_, c)| !c.server_default)
            .map(|(i, _)| i)
            .collect::<Vec<_>>();
        if row.len() != given.len() {
            return Err(refused("table row requires one value per supplied column"));
        }
        let order = if self.send_order.is_empty() {
            (1..=self.columns.len()).map(|n| n as u16).collect()
        } else {
            self.send_order.clone()
        };
        let mut b = vec![1];
        for n in order {
            let i = usize::from(n) - 1;
            if let Some(at) = given.iter().position(|g| *g == i) {
                b.extend(payload(&self.columns[i].sql_type, row[at].as_ref())?);
            }
        }
        Ok(b)
    }
    pub(crate) fn encode(&self, rows: Option<&[Row]>) -> Result<Vec<u8>> {
        let mut b = self.info()?;
        b.extend(self.header(rows.is_some())?);
        if let Some(rows) = rows {
            for row in rows {
                b.extend(self.row(row)?);
            }
            b.push(0);
        }
        Ok(b)
    }
}
fn refused(message: &'static str) -> Error {
    Error::new(ErrorKind::Parameter(message))
}
fn count(n: usize, b: &mut Vec<u8>) -> Result<()> {
    b.extend(
        u16::try_from(n)
            .map_err(|_| refused("row metadata count exceeds u16"))?
            .to_le_bytes(),
    );
    Ok(())
}
pub(crate) fn short(text: &SqlText, b: &mut Vec<u8>) -> Result<()> {
    b.push(u8::try_from(text.0.len()).map_err(|_| refused("name exceeds 255 UTF-16 units"))?);
    b.extend(text.0.iter().flat_map(|n| n.to_le_bytes()));
    Ok(())
}
fn prefix(sql_type: &SqlType) -> usize {
    match sql_type {
        SqlType::Table(_) => unreachable!(),
        SqlType::LegacyText { .. } | SqlType::LegacyImage | SqlType::Variant => 4,
        t if t.is_large() => 8,
        SqlType::Character { .. } | SqlType::Binary { .. } | SqlType::Vector { .. } => 2,
        _ => 1,
    }
}
pub(crate) fn type_info(sql_type: &SqlType) -> Result<Vec<u8>> {
    if let SqlType::Table(table) = sql_type {
        return table.info();
    }
    let mut b = sql_type.encode_parameter(None)?;
    b.truncate(b.len() - prefix(sql_type));
    Ok(b)
}
fn payload(sql_type: &SqlType, value: Option<&Value>) -> Result<Vec<u8>> {
    let info = type_info(sql_type)?;
    let b = sql_type.encode_parameter(value)?;
    Ok(b[info.len()..].to_vec())
}
pub(crate) const BULK_DONE: [u8; 13] = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) fn bulk_header(columns: &[Column], encrypted: bool) -> Result<Vec<u8>> {
    let mut b = vec![0x81];
    count(columns.len(), &mut b)?;
    let mut keys = Vec::new();
    for column in columns {
        if let Some(how) = &column.type_info.encryption {
            if !encrypted {
                return Err(refused(
                    "encrypted bulk requires negotiated column encryption",
                ));
            }
            let key = how
                .key
                .as_ref()
                .ok_or_else(|| refused("encrypted bulk lacks column key"))?;
            if !keys.contains(key) {
                keys.push(key.clone());
            }
        }
    }
    if encrypted {
        crate::types::crypto::write_key_table(&keys, &mut b)?;
    }
    for column in columns {
        if (column.flags & 0x800 != 0) != column.type_info.encryption.is_some() {
            return Err(refused("bulk encrypted flag/metadata mismatch"));
        }
        b.extend(column.user_type.to_le_bytes());
        b.extend(column.flags.to_le_bytes());
        if fixed(column.type_info.code) {
            b.push(column.type_info.code);
        } else {
            b.extend(type_info(&column.type_info.sql_type)?);
        }
        if let Some(how) = &column.type_info.encryption {
            let ordinal = keys
                .iter()
                .position(|k| Some(k) == how.key.as_ref())
                .expect("collected key");
            b.extend((ordinal as u16).to_le_bytes());
            how.write(&mut b)?;
        }
        short(&column.name, &mut b)?;
    }
    Ok(b)
}
fn fixed(code: u8) -> bool {
    [
        0x30, 0x34, 0x38, 0x7f, 0x32, 0x3b, 0x3e, 0x3c, 0x7a, 0x3d, 0x3a,
    ]
    .contains(&code)
}
pub(crate) fn bulk_row(columns: &[Column], row: &Row) -> Result<Vec<u8>> {
    if row.len() != columns.len() {
        return Err(refused("bulk row requires one value per column"));
    }
    let mut b = vec![0xd1];
    for (column, value) in columns.iter().zip(row) {
        let t = &column.type_info.sql_type;
        let mut data = payload(t, value.as_ref())?;
        if fixed(column.type_info.code) {
            if value.is_none() {
                return Err(refused("fixed-size bulk column has no NULL representation"));
            }
            data.remove(0);
        } else if t.is_large()
            && !matches!(t, SqlType::LegacyText { .. } | SqlType::LegacyImage)
            && value.is_some()
        {
            data[..8].copy_from_slice(&(u64::MAX - 1).to_le_bytes());
        }
        b.extend(data);
    }
    Ok(b)
}
pub(crate) enum RowLayout {
    Table(TableType),
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    Bulk(Vec<Column>),
}
struct RowProducer {
    layout: RowLayout,
    source: Box<dyn RowSource>,
}
impl super::source::Producer for RowProducer {
    fn next(&mut self) -> super::source::ProduceRead<'_> {
        Box::pin(async {
            self.source
                .next_row()
                .await?
                .map(|row| match &self.layout {
                    RowLayout::Table(t) => t.row(&row),
                    RowLayout::Bulk(c) => bulk_row(c, &row),
                })
                .transpose()
        })
    }
}
pub(crate) fn stream(
    offset: usize,
    layout: RowLayout,
    source: Box<dyn RowSource>,
) -> super::source::SourceAt {
    let end = match &layout {
        RowLayout::Table(_) => vec![0],
        RowLayout::Bulk(_) => BULK_DONE.to_vec(),
    };
    super::source::SourceAt {
        offset,
        source: Some(Box::new(RowProducer { layout, source })),
        end,
    }
}
