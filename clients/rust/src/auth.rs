//! Integrated login vocabulary. Providers own security contexts; the protocol
//! core moves opaque bounded tokens and never implements NTLM/Kerberos crypto.
use std::fmt;
use zeroize::Zeroizing;

pub const MAX_TOKEN: usize = 48 * 1024;
pub const MAX_ROUNDS: u8 = 8;

#[derive(Clone, Default, PartialEq, Eq)]
pub struct Token(pub(crate) Zeroizing<Vec<u8>>);
impl Token {
    pub fn new(bytes: Vec<u8>) -> crate::Result<Self> {
        let bytes = Zeroizing::new(bytes);
        if bytes.len() > MAX_TOKEN {
            return Err(crate::Error::new(crate::ErrorKind::Limit("SSPI token")));
        }
        Ok(Self(bytes))
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for Token {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Token([redacted])")
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Method {
    Ntlm,
    Kerberos,
    Negotiate,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Provider {
    Portable,
    NativeWindows,
}

#[derive(Clone, PartialEq, Eq)]
pub enum Credentials {
    Explicit {
        username: String,
        password: Zeroizing<String>,
    },
    SignedIn,
}
impl Credentials {
    pub fn explicit(username: impl Into<String>, password: impl Into<String>) -> Self {
        Self::Explicit {
            username: username.into(),
            password: Zeroizing::new(password.into()),
        }
    }
}
impl fmt::Debug for Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Explicit { .. } => "Explicit([redacted])",
            Self::SignedIn => "SignedIn",
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WindowsAuth {
    pub method: Method,
    pub provider: Provider,
    pub credentials: Credentials,
    /// SQL service identity, independent of the TCP address and TLS hostname.
    /// None derives MSSQLSvc/target-host:port for each physical target.
    pub service_principal: Option<String>,
    /// Portable Kerberos uses explicit TCP KDC routing; never public exposure.
    pub kdc_url: Option<String>,
    /// Negotiate otherwise requires Kerberos; fallback must be deliberate.
    pub allow_ntlm_fallback: bool,
}
impl WindowsAuth {
    pub fn explicit(
        method: Method,
        username: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            method,
            provider: Provider::Portable,
            credentials: Credentials::explicit(username, password),
            service_principal: None,
            kdc_url: None,
            allow_ntlm_fallback: false,
        }
    }
    pub fn signed_in(method: Method) -> Self {
        Self {
            method,
            provider: Provider::NativeWindows,
            credentials: Credentials::SignedIn,
            service_principal: None,
            kdc_url: None,
            allow_ntlm_fallback: false,
        }
    }
    pub(crate) fn compatible_with(&self, old: &Self) -> bool {
        let mut candidate = self.clone();
        if let (
            Credentials::Explicit { password, .. },
            Credentials::Explicit {
                password: before, ..
            },
        ) = (&mut candidate.credentials, &old.credentials)
        {
            password.clone_from(before);
        }
        candidate == *old
    }
}

#[cfg(all(feature = "integrated-auth", windows))]
mod native;
#[cfg(feature = "integrated-auth")]
mod portable;
#[cfg(all(feature = "integrated-auth", windows))]
pub use native::pending_workers as pending_native_workers;
#[cfg(feature = "integrated-auth")]
pub(crate) use portable::Context;
#[cfg(feature = "integrated-auth")]
pub(crate) use portable::channel_binding;
