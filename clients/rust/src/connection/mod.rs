//! Connection procedures and the optional async shell that performs their I/O.
/// Explicit version selection. Failure never falls back to another protocol.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum ProtocolVersion {
    #[default]
    V7_4,
    V8_0,
}
pub mod core;
#[cfg(feature = "tokio")]
pub mod shell;
