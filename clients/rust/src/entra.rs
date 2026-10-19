//! SDK-independent Entra configuration and asynchronous credential ownership.
//! A source binding is runtime service state; its declared identity is a value
//! in configuration. Applications must change that value when identity changes.
use crate::fedauth::Workflow;
use std::{collections::BTreeMap, fmt, future::Future, pin::Pin, sync::Arc, time::SystemTime};
use zeroize::Zeroizing;

#[cfg(feature = "azure-identity")]
pub mod azure;

pub const SQL_RESOURCE: &str = "https://database.windows.net/";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EntraMode {
    Upfront { resource: String },
    Deferred { workflow: Workflow },
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EntraLogin {
    pub source: String,
    pub identity: String,
    pub mode: EntraMode,
}
impl EntraLogin {
    pub fn upfront(source: impl Into<String>, identity: impl Into<String>) -> Self {
        Self {
            source: source.into(),
            identity: identity.into(),
            mode: EntraMode::Upfront {
                resource: SQL_RESOURCE.into(),
            },
        }
    }
    pub fn deferred(
        source: impl Into<String>,
        identity: impl Into<String>,
        workflow: Workflow,
    ) -> Self {
        Self {
            source: source.into(),
            identity: identity.into(),
            mode: EntraMode::Deferred { workflow },
        }
    }
    pub(crate) fn valid(&self) -> bool {
        !self.source.is_empty()
            && !self.identity.is_empty()
            && !matches!(&self.mode, EntraMode::Upfront { resource } if resource.is_empty())
    }
}

/// Driver-owned token bytes erase on release. SDK/OS copies are outside this
/// guarantee. Expiry is provider evidence; the driver does not decode JWTs.
pub struct AccessToken {
    secret: Zeroizing<String>,
    pub expires_at: Option<SystemTime>,
}
impl AccessToken {
    pub fn new(secret: String, expires_at: Option<SystemTime>) -> Self {
        Self {
            secret: Zeroizing::new(secret),
            expires_at,
        }
    }
    pub fn as_str(&self) -> &str {
        &self.secret
    }
}
impl fmt::Debug for AccessToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessToken([redacted])")
    }
}

#[derive(Clone, Copy, Debug)]
pub struct TokenRequest<'a> {
    pub resource: &'a str,
    pub sts_url: Option<&'a str>,
    pub host: &'a str,
    pub port: u16,
    pub workflow: Option<Workflow>,
}
pub struct ProviderError {
    cause: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl ProviderError {
    pub fn refused() -> Self {
        Self { cause: None }
    }
    pub fn with_cause(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            cause: Some(Box::new(cause)),
        }
    }
    /// Deliberate access to the possibly sensitive provider diagnostic.
    pub fn protected_cause(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.cause.as_deref()
    }
}
impl fmt::Display for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Entra credential acquisition failed")
    }
}
impl fmt::Debug for ProviderError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ProviderError {}
pub type TokenFuture<'a> =
    Pin<Box<dyn Future<Output = Result<AccessToken, ProviderError>> + Send + 'a>>;
pub trait TokenProvider: Send + Sync {
    fn acquire<'a>(&'a self, request: TokenRequest<'a>) -> TokenFuture<'a>;
}

/// Immutable source bindings copied into each pool's services owner. Renewal
/// belongs inside a bound provider; changing a binding requires a new owner.
#[derive(Clone, Default)]
pub struct TokenProviders(BTreeMap<String, Arc<dyn TokenProvider>>);
impl TokenProviders {
    pub fn new() -> Self {
        Self::default()
    }
    pub fn with(mut self, source: impl Into<String>, provider: Arc<dyn TokenProvider>) -> Self {
        self.0.insert(source.into(), provider);
        self
    }
    pub fn get(&self, source: &str) -> Option<&Arc<dyn TokenProvider>> {
        self.0.get(source)
    }
}
impl fmt::Debug for TokenProviders {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("TokenProviders([opaque bindings])")
    }
}
