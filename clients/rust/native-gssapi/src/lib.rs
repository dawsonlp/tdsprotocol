//! Narrow owned GSSAPI boundary. No cache files, passwords, environment changes
//! or `kinit` invocation. The main TDS crate remains `forbid(unsafe_code)`.
//! Native calls may block; callers must arrange cancellation and owned cleanup.

use zeroize::Zeroizing;

pub const MAX_TOKEN: usize = 48 * 1024;

/// Deliberately excludes native status messages, which may include credentials,
/// cache paths, domain configuration or server-controlled text. A refusal keeps
/// only GSSAPI's status numbers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    Unavailable,
    InvalidInput,
    Refused(Status),
    Mechanism,
    TokenLimit,
}

/// The major and minor status a GSSAPI call returned. Major 0 means GSSAPI
/// reported success but this boundary refused the result (for example, a
/// missing handle or an incomplete mutual authentication). Minor statuses are
/// mechanism-specific (for Kerberos, com_err codes) and are not interpreted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Status {
    pub major: u32,
    pub minor: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StatusKind {
    /// GSS_S_NO_CRED: no usable credentials, such as no ticket cache.
    NoCredentials,
    /// GSS_S_CREDENTIALS_EXPIRED.
    CredentialsExpired,
    /// GSS_S_FAILURE: the mechanism failed; the minor status says why.
    Failure,
    Other,
}
/// Kerberos `KRB5KRB_AP_ERR_TKT_EXPIRED` ("Ticket expired") in the shared krb5
/// com_err table (MIT and Heimdal). MIT reports an expired ticket-granting
/// ticket as GSS_S_FAILURE with this minor status, not GSS_S_CREDENTIALS_EXPIRED.
pub const KERBEROS_TICKET_EXPIRED: u32 = 0x96c7_3a20;

impl Status {
    /// The routine error in bits 16-23 of the major status (RFC 2744 §3.9.1),
    /// with one mechanism case: a Kerberos expired-ticket failure is expired.
    pub fn kind(self) -> StatusKind {
        match (self.major >> 16) & 0xff {
            7 => StatusKind::NoCredentials,
            11 => StatusKind::CredentialsExpired,
            13 if self.minor == KERBEROS_TICKET_EXPIRED => StatusKind::CredentialsExpired,
            13 => StatusKind::Failure,
            _ => StatusKind::Other,
        }
    }
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
