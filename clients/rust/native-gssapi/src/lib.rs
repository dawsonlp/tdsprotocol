//! Narrow owned GSSAPI boundary. No cache files, passwords, environment changes
//! or `kinit` invocation. The main TDS crate remains `forbid(unsafe_code)`.
//! Native calls may block; callers must arrange cancellation and owned cleanup.

use zeroize::Zeroizing;

pub const MAX_TOKEN: usize = 48 * 1024;

/// Deliberately excludes native status messages, which may include credentials,
/// cache paths, domain configuration or server-controlled text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    InvalidInput,
    Refused,
    Mechanism,
    TokenLimit,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Kerberos,
    Negotiate,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Mechanism {
    Kerberos,
    Ntlm,
    Other,
}

/// Supplied bindings are evidence of a client input, not proof that SQL Server
/// enforced Extended Protection (which needs a different TLS binding).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Evidence {
    pub mechanism: Mechanism,
    pub channel_binding_supplied: bool,
}

pub struct Step {
    pub token: Zeroizing<Vec<u8>>,
    pub complete: bool,
    pub evidence: Option<Evidence>,
}

#[cfg(any(target_os = "linux", target_os = "macos"))]
mod system;
#[cfg(any(target_os = "linux", target_os = "macos"))]
pub use system::Context;

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub struct Context;
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl Context {
    pub fn new(_: Method, _: &str, _: Option<&str>, _: bool) -> Result<Self, Error> {
        Err(Error::Unavailable)
    }
    pub fn step(&mut self, _: Option<&[u8]>, _: &[u8]) -> Result<Step, Error> {
        Err(Error::Unavailable)
    }
}
