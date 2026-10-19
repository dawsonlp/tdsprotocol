//! A source owns its one producer. Preparing consumes the request; it never
//! clones a source or hides consumption rights behind a shared lock.
use super::*;
use crate::{Chunk, SqlType};
use std::{collections::BTreeMap, future::Future, pin::Pin};

pub type SourceRead<'a> = Pin<Box<dyn Future<Output = std::io::Result<Option<Chunk>>> + Send + 'a>>;
/// Produce an owned typed chunk, or None at EOF. Empty chunks are harmless;
/// they never stand for PLP EOF. Implementations must not block their executor.
/// Source failure is reported after partial-send cleanup, without replay.
pub trait Source: Send + 'static {
    fn next_chunk(&mut self) -> SourceRead<'_>;
}
// Producers return already validated/framed wire pieces. The shell schedules
// them; it does not decide which SQL type or row format those bytes describe.
pub(crate) type ProduceRead<'a> =
    Pin<Box<dyn Future<Output = Result<Option<Vec<u8>>>> + Send + 'a>>;
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) trait Producer: Send {
    fn next(&mut self) -> ProduceRead<'_>;
}
struct PlpProducer {
    sql_type: SqlType,
    source: Box<dyn Source>,
}
impl Producer for PlpProducer {
    fn next(&mut self) -> ProduceRead<'_> {
        Box::pin(async {
            self.source
                .next_chunk()
                .await?
                .map(|chunk| encode_chunk(&self.sql_type, chunk))
                .transpose()
        })
    }
}
#[cfg_attr(not(feature = "tokio"), allow(dead_code))]
pub(crate) struct SourceAt {
    pub(crate) offset: usize,
    pub(crate) source: Option<Box<dyn Producer>>,
    pub(crate) end: Vec<u8>,
}
impl SourceAt {
    fn plp(offset: usize, sql_type: SqlType, source: Box<dyn Source>) -> Self {
        Self {
            offset,
            source: Some(Box::new(PlpProducer { sql_type, source })),
            end: vec![0; 4],
        }
    }
}
pub struct Prepared {
    pub encoded: Encoded,
    #[cfg_attr(not(feature = "tokio"), allow(dead_code))]
    pub(crate) sources: Vec<SourceAt>,
}
impl From<Encoded> for Prepared {
    fn from(encoded: Encoded) -> Self {
        Self {
            encoded,
            sources: Vec::new(),
        }
    }
}
/// A non-Clone call with unique streamed parameter bindings. A bound parameter
/// declares its type and output flag in `call`, with None as its placeholder.
/// The source replaces that placeholder, not the SQL declaration or any row API.
pub struct StreamedCall {
    pub call: Call,
    sources: BTreeMap<usize, Binding>,
    duplicate: bool,
}
enum Binding {
    Value(Box<dyn Source>),
    Rows(Box<dyn super::RowSource>),
}
impl StreamedCall {
    pub fn new(call: Call) -> Self {
        Self {
            call,
            sources: BTreeMap::new(),
            duplicate: false,
        }
    }
    pub fn source(mut self, parameter_index: usize, source: impl Source) -> Self {
        self.duplicate |= self
            .sources
            .insert(parameter_index, Binding::Value(Box::new(source)))
            .is_some();
        self
    }
    pub fn table_source(mut self, parameter_index: usize, source: impl super::RowSource) -> Self {
        self.duplicate |= self
            .sources
            .insert(parameter_index, Binding::Rows(Box::new(source)))
            .is_some();
        self
    }
}
impl Request for StreamedCall {
    fn label(&self) -> &'static str {
        "RPC"
    }
    fn encode_request(&self, _: &Context) -> Result<Encoded> {
        Err(Error::new(ErrorKind::Parameter(
            "a streamed call must be prepared by consuming it",
        )))
    }
    fn prepare(self: Box<Self>, context: &Context) -> Result<Prepared> {
        StreamedCalls::prepare(StreamedCalls(vec![*self]), context)
    }
}
impl StreamedCall {
    fn append(
        self,
        body: &mut Vec<u8>,
        streams: &mut Vec<SourceAt>,
    ) -> Result<Vec<Vec<crate::tokens::Column>>> {
        let Self {
            call,
            mut sources,
            duplicate,
        } = self;
        if duplicate || sources.keys().any(|i| *i >= call.params.len()) {
            return Err(Error::new(ErrorKind::Parameter(
                "duplicate or out-of-range source binding",
            )));
        }
        call.encode_header(body)?;
        for (index, param) in call.params.iter().enumerate() {
            if let Some(source) = sources.remove(&index) {
                if param.value.is_some() || param.use_default {
                    return Err(Error::new(ErrorKind::Parameter(
                        "a source replaces a None placeholder; DEFAULT cannot have a source",
                    )));
                }
                param.encode_header(body)?;
                match source {
                    Binding::Value(source) => {
                        body.extend(crate::types::encode::large_info(&param.sql_type)?);
                        body.extend((u64::MAX - 1).to_le_bytes());
                        streams.push(SourceAt::plp(body.len(), param.sql_type.clone(), source));
                    }
                    Binding::Rows(source) => {
                        let crate::SqlType::Table(table) = &param.sql_type else {
                            return Err(Error::new(ErrorKind::Parameter(
                                "row source requires a table declaration",
                            )));
                        };
                        body.extend(table.info()?);
                        body.extend(table.header(true)?);
                        streams.push(super::rows::stream(
                            body.len(),
                            super::rows::RowLayout::Table((**table).clone()),
                            source,
                        ));
                    }
                }
            } else {
                param.encode(body)?;
            }
        }
        Ok(call.columns)
    }
}
/// One RPC message with several uniquely owned calls/producers. This is a batch
/// of calls, not a transaction: completed earlier calls are never replayed.
pub struct StreamedCalls(pub Vec<StreamedCall>);
impl StreamedCalls {
    fn prepare(self, context: &Context) -> Result<Prepared> {
        if self.0.is_empty() {
            return Err(Error::new(ErrorKind::Parameter(
                "StreamedCalls requires at least one call",
            )));
        }
        let mut body = headers(context.transaction, context.outstanding);
        let mut streams = Vec::new();
        let mut metadata = Vec::new();
        for (index, call) in self.0.into_iter().enumerate() {
            if index != 0 {
                body.push(0xff);
            }
            metadata.extend(call.append(&mut body, &mut streams)?);
        }
        Ok(Prepared {
            encoded: Encoded {
                continuation: crate::requests::Continuation::None,
                kind: crate::packet::RPC,
                body,
                metadata,
            },
            sources: streams,
        })
    }
}
impl Request for StreamedCalls {
    fn label(&self) -> &'static str {
        "RPC"
    }
    fn encode_request(&self, _: &Context) -> Result<Encoded> {
        Err(Error::new(ErrorKind::Parameter(
            "streamed calls must be prepared by consuming them",
        )))
    }
    fn prepare(self: Box<Self>, context: &Context) -> Result<Prepared> {
        (*self).prepare(context)
    }
}
/// The type/collation is checked after production too; a source may fail late.
pub(crate) fn encode_chunk(sql_type: &SqlType, chunk: Chunk) -> Result<Vec<u8>> {
    let mut bytes = match (sql_type, chunk) {
        (SqlType::Json, Chunk::Unicode(text)) => crate::types::encode::json_bytes(&text)?,
        (t, Chunk::Unicode(text)) if t.is_unicode() => {
            text.0.into_iter().flat_map(u16::to_le_bytes).collect()
        }
        (
            SqlType::CharacterMax {
                unicode: false,
                collation,
            },
            Chunk::Text(text),
        ) if *collation == text.collation => text.bytes,
        (SqlType::BinaryMax | SqlType::Clr(_), Chunk::Binary(bytes)) => bytes,
        _ => {
            return Err(Error::new(ErrorKind::Parameter(
                "source chunk differs from declared type/collation",
            )));
        }
    };
    if bytes.is_empty() {
        return Ok(Vec::new());
    }
    let length = u32::try_from(bytes.len())
        .map_err(|_| Error::new(ErrorKind::Limit("PLP source chunk exceeds u32")))?;
    let count = bytes.len();
    bytes.resize(count + 4, 0);
    bytes.copy_within(..count, 4);
    bytes[..4].copy_from_slice(&length.to_le_bytes());
    Ok(bytes)
}
