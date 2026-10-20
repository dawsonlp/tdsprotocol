//! TDS, read from the wire upward.
//!
//! Start with `wire`, then `packet`, the named message definitions, `tokens`,
//! and finally [`connection::core`]. The optional Tokio shell performs I/O;
//! protocol decisions remain in the core. See the crate README for scope.
#![forbid(unsafe_code)]

// Controlled peers are shared by integration tests and private driver tests.
#[cfg(test)]
extern crate self as tds_client;

pub mod auth;
pub mod azure_features;
pub mod browser;
pub mod capture;
pub mod config;
pub mod connection;
#[cfg(feature = "encryption")]
pub mod encryption;
pub mod entra;
pub mod error;
pub mod fedauth;
pub mod inspection;
pub mod large;
pub mod login7;
pub mod mars;
pub mod observe;
pub mod packet;
#[cfg(feature = "tokio")]
pub mod pool;
pub mod prelogin;
pub mod replay;
pub mod requests;
pub mod response;
pub mod session;
pub mod text;
pub mod tokens;
pub mod transactions;
pub mod types;
pub mod values;
pub mod wire;

pub use auth::{Authentication, SqlCredentials};
pub use config::{
    ConfigError, ConfigPhase, ConfigRead, ConfigResult, ConfigService, ConnectionConfig,
    EnclaveAttestation, StaticConfig,
};
#[cfg(feature = "tokio")]
pub use config::{ConnectionServices, PoolPolicy};
pub use connection::ProtocolVersion;
#[cfg(feature = "tokio")]
pub use connection::shell::{
    BulkWriter, CancelHandle, Cell, ChannelCloseHandle, CloseHandle, ConnectOptions, Connection,
    LiveResultSet, Response, SerialChannel, StreamedRow, ValueStream,
};
pub use error::{Error, ErrorKind, Execution, Result, Route, Step};
#[cfg(feature = "tokio")]
pub use pool::{Lease, Pool, ReleaseOutcome};
pub use requests::{
    Batch, Builtin, Call, CallOptions, Calls, Param, ParamValue, Procedure, Request, RowRead,
    RowSource, Sort, Source, SourceRead, StreamedCall, StreamedCalls, TableColumn, TableType,
};
pub use response::{
    FetchedResponse, Item, ProcedureReturn, ResultSet, Row, RowsNotAvailable, Timing, Unread,
};
pub use tokens::{OutputValue, Record, SqlText};

pub use large::Chunk;
pub use text::TextDecoder;
pub use transactions::{Isolation, Transaction};
pub use types::{ClrType, Collation, IntegerSize, LegacyMetadata, SqlType, TypeInfo, XmlSchema};
pub use values::{
    SqlDate, SqlDateTime, SqlDateTime2, SqlDateTimeOffset, SqlDecimal, SqlFloat, SqlGuid, SqlHalf,
    SqlMoney, SqlReal, SqlSmallDateTime, SqlTextBytes, SqlTime, SqlVariant, SqlVector, Value,
    ValueError, VectorElement,
};
