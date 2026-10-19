//! Effective connection settings are values; sources perform application I/O.
//! Reference: `docs/design/H-pool-configuration.md`. No watcher, timestamp or
//! source revision is required. Each pool compares its own accepted snapshot.
use crate::ProtocolVersion;
use std::{fmt, future::Future, pin::Pin};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConfigPhase {
    Read,
    Validation,
    Superseded,
    Compatibility,
}

pub struct ConfigError {
    pub phase: ConfigPhase,
    reason: &'static str,
    source_error: Option<Box<dyn std::error::Error + Send + Sync>>,
}
impl ConfigError {
    pub fn new(phase: ConfigPhase, reason: &'static str) -> Self {
        Self {
            phase,
            reason,
            source_error: None,
        }
    }
    /// The cause is inspectable, but its possibly secret text is not formatted.
    pub fn source_failure(error: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self {
            phase: ConfigPhase::Read,
            reason: "source read failed",
            source_error: Some(Box::new(error)),
        }
    }
    pub fn source_error(&self) -> Option<&(dyn std::error::Error + Send + Sync + 'static)> {
        self.source_error.as_deref()
    }
}
impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "configuration {:?}: {}", self.phase, self.reason)
    }
}
impl fmt::Debug for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}
impl std::error::Error for ConfigError {}
pub type ConfigResult<T> = std::result::Result<T, ConfigError>;
pub type ConfigRead<'a> = Pin<Box<dyn Future<Output = ConfigResult<ConnectionConfig>> + Send + 'a>>;

pub trait ConfigService: Send + Sync {
    fn read(&self) -> ConfigRead<'_>;
}

/// Owned input values become an immutable shared snapshot on acceptance. Editing
/// an application's separate clone cannot change an accepted or opening value.
#[derive(Clone, PartialEq, Eq)]
pub struct ConnectionConfig {
    pub windows_auth: Option<crate::auth::WindowsAuth>,
    pub host: String,
    pub port: u16,
    pub user: String,
    pub password: String,
    pub database: String,
    pub version: ProtocolVersion,
    pub mars: bool,
    pub app_name: String,
    pub host_name: Option<String>,
    pub language: String,
    pub odbc: bool,
    pub read_only_intent: bool,
    pub follow_routing: bool,
    /// Enable server-reported reconstructible session state.
    pub session_recovery: bool,
    /// Request native JSON results; parameters always use strict UTF-8.
    pub json_support: bool,
    /// Zero disables; versions one/two preserve server downgrades explicitly.
    pub vector_support: u8,
    pub data_classification: u8,
    /// Advertise exact UTF-8 transport rather than server substitution.
    pub utf8_support: bool,
    /// Request Always Encrypted version one (without enclaves).
    pub column_encryption: bool,
}
impl ConnectionConfig {
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        password: impl Into<String>,
    ) -> Self {
        Self {
            host: host.into(),
            windows_auth: None,
            port,
            user: user.into(),
            password: password.into(),
            database: String::new(),
            version: ProtocolVersion::V7_4,
            mars: false,
            app_name: "tds (rust)".into(),
            host_name: None,
            language: String::new(),
            odbc: true,
            read_only_intent: false,
            follow_routing: true,
            session_recovery: true,
            json_support: true,
            vector_support: 2,
            data_classification: 2,
            utf8_support: true,
            column_encryption: false,
        }
    }
    pub fn validate(&self) -> ConfigResult<()> {
        if self.windows_auth.is_some() && (!self.user.is_empty() || !self.password.is_empty()) {
            return Err(ConfigError::new(
                ConfigPhase::Validation,
                "SQL credentials with integrated login",
            ));
        }
        if self.vector_support > 2 || self.data_classification > 2 {
            return Err(ConfigError::new(
                ConfigPhase::Validation,
                "unsupported requested feature version",
            ));
        }
        if self.host.is_empty()
            || self.port == 0
            || (self.user.is_empty() && self.windows_auth.is_none())
        {
            return Err(ConfigError::new(
                ConfigPhase::Validation,
                "host/user must be nonempty and port nonzero",
            ));
        }
        Ok(())
    }
    pub fn compatible_with(&self, previous: &Self) -> bool {
        let mut refreshed = self.clone();
        refreshed.password.clone_from(&previous.password);
        match (&self.windows_auth, &previous.windows_auth) {
            (Some(current), Some(old)) if current.compatible_with(old) => {
                refreshed.windows_auth.clone_from(&previous.windows_auth)
            }
            _ => {}
        }
        refreshed == *previous
    }
}
impl fmt::Debug for ConnectionConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectionConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[redacted]")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug)]
pub struct StaticConfig(pub ConnectionConfig);
impl ConfigService for StaticConfig {
    fn read(&self) -> ConfigRead<'_> {
        Box::pin(async { Ok(self.0.clone()) })
    }
}

#[cfg(feature = "tokio")]
mod shell;
#[cfg(feature = "tokio")]
pub(crate) use shell::{Binding, ConfigState};
#[cfg(feature = "tokio")]
pub use shell::{ConnectionServices, PoolPolicy};
