//! Only source ordering/acceptance requires async machinery. The state owns no
//! pool or connections, so borrowed recovery survives pool-owner shutdown.
use super::*;
use crate::{
    ConnectOptions, Error, ErrorKind, Execution, Result, Step, capture::Capture, observe::Observer,
};
use rustls::RootCertStore;
use std::{
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    sync::Mutex as AsyncMutex,
    time::{Instant, timeout_at},
};

#[derive(Clone)]
pub struct ConnectionServices {
    pub roots: RootCertStore,
    pub server_name: Option<String>,
    pub observe: Option<Observer>,
    pub capture_factory: Option<Arc<dyn Fn() -> std::io::Result<Capture> + Send + Sync>>,
}
impl ConnectionServices {
    pub fn new(roots: RootCertStore) -> Self {
        Self {
            roots,
            server_name: None,
            observe: None,
            capture_factory: None,
        }
    }
    pub(crate) fn options(&self, c: &ConnectionConfig, p: PoolPolicy) -> ConnectOptions {
        ConnectOptions {
            host: c.host.clone(),
            port: c.port,
            user: c.user.clone(),
            password: c.password.clone(),
            new_password: String::new(),
            database: c.database.clone(),
            version: c.version,
            mars: c.mars,
            host_name: c.host_name.clone(),
            app_name: c.app_name.clone(),
            language: c.language.clone(),
            odbc: c.odbc,
            read_only_intent: c.read_only_intent,
            follow_routing: c.follow_routing,
            session_recovery: c.session_recovery,
            json_support: c.json_support,
            vector_support: c.vector_support,
            data_classification: c.data_classification,
            utf8_support: c.utf8_support,
            roots: self.roots.clone(),
            server_name: self.server_name.clone(),
            observe: self.observe.clone(),
            capture_factory: self.capture_factory.clone(),
            timeout: p.timeout,
            cleanup_timeout: p.cleanup_timeout,
        }
    }
}
#[derive(Clone, Copy, Debug)]
pub struct PoolPolicy {
    pub timeout: Duration,
    pub cleanup_timeout: Duration,
}
impl Default for PoolPolicy {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(15),
            cleanup_timeout: Duration::from_secs(5),
        }
    }
}
impl ConnectionConfig {
    pub fn from_options(o: &ConnectOptions) -> Self {
        Self {
            host: o.host.clone(),
            port: o.port,
            user: o.user.clone(),
            password: o.password.clone(),
            database: o.database.clone(),
            version: o.version,
            mars: o.mars,
            host_name: o.host_name.clone(),
            app_name: o.app_name.clone(),
            language: o.language.clone(),
            odbc: o.odbc,
            read_only_intent: o.read_only_intent,
            follow_routing: o.follow_routing,
            session_recovery: o.session_recovery,
            json_support: o.json_support,
            vector_support: o.vector_support,
            data_classification: o.data_classification,
            utf8_support: o.utf8_support,
        }
    }
}

pub(crate) struct ConfigState {
    source: Arc<dyn ConfigService>,
    gate: AsyncMutex<()>,
    current: Mutex<Option<Arc<ConnectionConfig>>>,
}
impl ConfigState {
    pub fn new(source: Arc<dyn ConfigService>) -> Arc<Self> {
        Arc::new(Self {
            source,
            gate: AsyncMutex::new(()),
            current: Mutex::new(None),
        })
    }
    pub async fn read(&self, deadline: Instant) -> Result<Arc<ConnectionConfig>> {
        timeout_at(deadline, async {
            let _gate = self.gate.lock().await;
            let configuration = self.source.read().await.map_err(config_error)?;
            configuration.validate().map_err(config_error)?;
            let configuration = Arc::new(configuration);
            *self
                .current
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(configuration.clone());
            Ok(configuration)
        })
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout).at(Step::Configuration, Execution::NotSent))?
    }
    pub fn matches(&self, configuration: &ConnectionConfig) -> bool {
        self.current
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_deref()
            == Some(configuration)
    }
    pub fn require_current(&self, configuration: &ConnectionConfig) -> Result<()> {
        if self.matches(configuration) {
            Ok(())
        } else {
            Err(config_error(ConfigError::new(
                ConfigPhase::Superseded,
                "settings changed before opening completed",
            )))
        }
    }
}
pub(super) fn config_error(error: ConfigError) -> Error {
    Error::new(ErrorKind::Configuration(error)).at(Step::Configuration, Execution::NotSent)
}

#[derive(Clone)]
pub(crate) struct Binding {
    pub state: Arc<ConfigState>,
    actual: Arc<Mutex<Arc<ConnectionConfig>>>,
}
impl Binding {
    pub fn new(state: Arc<ConfigState>, actual: Arc<ConnectionConfig>) -> Self {
        Self {
            state,
            actual: Arc::new(Mutex::new(actual)),
        }
    }
    pub fn actual(&self) -> Arc<ConnectionConfig> {
        self.actual
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    pub fn is_current(&self) -> bool {
        self.state.matches(&self.actual())
    }
    pub fn commit(&self, configuration: Arc<ConnectionConfig>) -> Result<()> {
        self.state.require_current(&configuration)?;
        *self
            .actual
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = configuration;
        Ok(())
    }
}
