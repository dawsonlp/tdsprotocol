//! Tokio supplies sockets, scheduling, deadlines and certificate-validation time.
//! One persistent task exclusively owns each socket and `ConnectionCore`.
//!
//! The command mailbox holds one command. Each reply holds at most one record.
//! Plain connections stop socket reads without demand. MARS continues routing
//! frames, with a bounded credit window for each independently advancing reader.
//! Shutdown has its own flag/wakeup path, independent of mailbox capacity.

use rustls::RootCertStore;
mod reading;
mod sending;
use sending::{SendAbort, Sending};
mod recovery;
pub use reading::{Cell, LiveResultSet, StreamedRow, ValueStream};
use recovery::{protocol_core, recovery_error};
use std::{
    collections::BTreeMap,
    fmt,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::AsyncReadExt,
    net::TcpStream,
    sync::{Notify, mpsc, oneshot},
    task::JoinHandle,
    time::{Instant, sleep_until, timeout_at},
};

use super::{ProtocolVersion, core::ConnectionCore};
use crate::{
    Error, ErrorKind, Execution, Record, Request, Result, Step,
    capture::Capture,
    observe::{Level, Observer, Trace},
    response::{FetchedResponse, Retention},
    session::Session,
};

/// Explicit trust roots and credentials. Debug never displays the password.
#[derive(Clone)]
pub struct ConnectOptions {
    pub authentication: crate::Authentication,
    pub token_providers: crate::entra::TokenProviders,
    pub observe: Option<Observer>,
    /// New physical connection, new recording and distinct output. Never called
    /// merely because an existing transport is lent to its next borrower.
    pub capture_factory: Option<Arc<dyn Fn() -> std::io::Result<Capture> + Send + Sync>>,
    pub version: ProtocolVersion,
    /// Interleave independent serial channels on this authenticated connection.
    pub mars: bool,
    pub host: String,
    pub port: u16,
    /// One-time direct LOGIN7 operation. Pools reject it; later recovery uses
    /// the accepted new credential without repeating the change request.
    pub new_password: String,
    pub database: String,
    pub server_name: Option<String>,
    pub roots: RootCertStore,
    pub timeout: Duration,
    /// Total cancellation cleanup budget, independent of connection/query time.
    pub cleanup_timeout: Duration,
    /// None or empty uses the machine's name, matching Python's default.
    pub host_name: Option<String>,
    pub app_name: String,
    /// Empty uses the login's default language, announced by the server.
    pub language: String,
    /// Match Python/ODBC defaults; no hidden SET statements are sent.
    pub odbc: bool,
    pub read_only_intent: bool,
    pub follow_routing: bool,
    /// Ask the server to report state for eligible session recovery.
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
    /// Request version two with the explicit no-attestation trust mode.
    pub enclave_attestation: Option<crate::config::EnclaveAttestation>,
    /// Diagnostic requests: warn on request, fail login if the server enables one.
    pub azure_feature_probes: crate::azure_features::AzureFeatureProbes,
}
impl ConnectOptions {
    pub fn entra(
        host: impl Into<String>,
        port: u16,
        login: crate::entra::EntraLogin,
        provider: Arc<dyn crate::entra::TokenProvider>,
        roots: RootCertStore,
    ) -> Self {
        let mut options = Self::new(host, port, "", "", roots);
        options.token_providers =
            crate::entra::TokenProviders::new().with(login.source.clone(), provider);
        options.authentication = crate::Authentication::Entra(login);
        options
    }
    pub fn integrated(
        host: impl Into<String>,
        port: u16,
        authentication: crate::auth::WindowsAuth,
        roots: RootCertStore,
    ) -> Self {
        let mut options = Self::new(host, port, "", "", roots);
        options.authentication = crate::Authentication::Windows(authentication);
        options
    }
    pub fn new(
        host: impl Into<String>,
        port: u16,
        user: impl Into<String>,
        password: impl Into<String>,
        roots: RootCertStore,
    ) -> Self {
        Self {
            observe: None,
            authentication: crate::Authentication::sql(user, password),
            token_providers: Default::default(),
            capture_factory: None,
            version: ProtocolVersion::V7_4,
            mars: false,
            host: host.into(),
            port,
            new_password: String::new(),
            database: String::new(),
            server_name: None,
            roots,
            timeout: Duration::from_secs(15),
            cleanup_timeout: Duration::from_secs(5),
            host_name: None,
            app_name: "tds (rust)".into(),
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
            enclave_attestation: None,
            azure_feature_probes: Default::default(),
        }
    }
}
impl fmt::Debug for ConnectOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ConnectOptions")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("password", &"[redacted]")
            .finish_non_exhaustive()
    }
}

type Reply<T> = oneshot::Sender<Result<T>>;
enum Command {
    #[cfg(feature = "encryption")]
    AttachKeys(
        crate::encryption::LifecycleLink,
        oneshot::Sender<crate::encryption::Result<()>>,
    ),
    Recover(Reply<()>),
    Observe(Option<Observer>, Reply<()>),
    Capture(Option<Capture>, Reply<()>),
    Open(Reply<Arc<ChannelLife>>),
    Begin {
        channel: u64,
        exchange: u64,
        request: Box<dyn Request>,
        control: Arc<ExchangeControl>,
        complete: Reply<Completion>,
        reply: Reply<()>,
    },
    Next {
        channel: u64,
        exchange: u64,
        epoch: u64,
        reply: Reply<Record>,
    },
    Session(Reply<Session>),
    Recycle(Return),
    Checkout(Reply<()>),
}
impl Command {
    fn fail(self, endpoint: &Endpoint) {
        match self {
            #[cfg(feature = "encryption")]
            Self::AttachKeys(_, reply) => {
                let _ = reply.send(Err(crate::encryption::Error::Closed));
            }
            Self::Recover(reply) | Self::Observe(_, reply) | Self::Capture(_, reply) => {
                let _ = reply.send(Err(endpoint.closed_error()));
            }
            Self::Open(reply) => {
                let _ = reply.send(Err(endpoint.closed_error()));
            }
            Self::Begin { reply, .. } => {
                let _ = reply.send(Err(endpoint.closed_error()));
            }
            Self::Next { reply, .. } => {
                let _ = reply.send(Err(endpoint.closed_error()));
            }
            Self::Session(reply) => {
                let _ = reply.send(Err(endpoint.closed_error()));
            }
            Self::Checkout(reply) => {
                let _ = reply.send(Err(endpoint.closed_error()));
            }
            Self::Recycle(returning) => {
                let _ = returning.reply.send(Err(endpoint.closed_error()));
            }
        }
    }
}
struct Endpoint {
    #[cfg(feature = "encryption")]
    keys: Mutex<Option<crate::encryption::LifecycleLink>>,
    #[cfg(test)]
    writes: interruptions::Writes,
    observation_error: Arc<Mutex<Option<Arc<std::io::Error>>>>,
    commands: mpsc::Sender<Command>,
    revoked: AtomicBool,
    returning: AtomicBool,
    changed: Notify,
    position: Mutex<(Step, Execution)>,
    failure: Mutex<Option<Arc<Error>>>,
    cleanup_timeout: Duration,
    epoch: Mutex<u64>,
    disconnected: AtomicBool,
    recoveries: AtomicU64,
}
impl Endpoint {
    fn epoch(&self) -> u64 {
        *self
            .epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn revoke_epoch(&self, epoch: u64) {
        // Serialize comparison/revocation with epoch rotation. A separate atomic
        // load followed by revoke could close a replacement between those steps.
        let current = self
            .epoch
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *current == epoch {
            self.revoke();
        }
    }

    fn revoke(&self) {
        self.revoked.store(true, Ordering::Release);
        #[cfg(feature = "encryption")]
        self.revoke_keys();
        self.changed.notify_one();
    }
    #[cfg(feature = "encryption")]
    fn revoke_keys(&self) {
        if let Some(link) = &*self
            .keys
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            link.revoke();
        }
    }
    fn is_closed(&self) -> bool {
        self.is_revoked() || self.returning.load(Ordering::Acquire)
    }
    fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }
    fn position(&self) -> (Step, Execution) {
        *self
            .position
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn locate(&self, error: Error) -> Error {
        let (step, execution) = self.position();
        error.at(step, execution)
    }
    fn closed_error(&self) -> Error {
        if let Some(cause) = &*self
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            Error::shared(cause.clone())
        } else {
            self.locate(Error::new(ErrorKind::Closed))
        }
    }
    async fn submit(&self, command: Command) -> Result<()> {
        let permit = self
            .commands
            .reserve()
            .await
            .map_err(|_| self.closed_error())?;
        if self.is_closed() {
            return Err(self.closed_error());
        }
        permit.send(command);
        Ok(())
    }
}

/// Shareable connection-close permission; it cannot send requests or read rows.
#[derive(Clone)]
pub struct CloseHandle {
    endpoint: Arc<Endpoint>,
}
impl CloseHandle {
    /// Revoke authority immediately and wake the driver. Does not await teardown.
    pub fn close(&self) {
        self.endpoint.revoke();
    }
}

#[derive(Clone, Copy)]
struct CancelRequest {
    deadline: Option<Instant>,
}

/// One exchange's delegated permission, not a second advancing reader.
struct ExchangeControl {
    channel: u64,
    exchange: u64,
    epoch: u64,
    endpoint: Weak<Endpoint>,
    finished: AtomicBool,
    request: Mutex<Option<CancelRequest>>,
    retention: Mutex<Retention>,
}
impl ExchangeControl {
    fn retention(&self) -> std::sync::MutexGuard<'_, Retention> {
        self.retention
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn request(&self) -> Option<CancelRequest> {
        *self
            .request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

/// Shareable cancellation permission for exactly one exchange. It holds no
/// send/read authority and cannot cancel a replacement exchange or connection.
#[derive(Clone)]
pub struct CancelHandle {
    control: Arc<ExchangeControl>,
}
impl CancelHandle {
    /// Request Attention without waiting for mailbox capacity or acknowledgement.
    /// The first request starts the cleanup budget. Repeats never extend it.
    /// Completion and stale handles are no-ops. Cancellation implies no rollback.
    pub fn cancel(&self) {
        let Some(endpoint) = self.control.endpoint.upgrade() else {
            return;
        };
        let mut request = self
            .control
            .request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if endpoint.is_closed()
            || self.control.finished.load(Ordering::Acquire)
            || request.is_some()
        {
            return;
        }
        *request = Some(CancelRequest {
            deadline: Instant::now().checked_add(endpoint.cleanup_timeout),
        });
        endpoint.changed.notify_one();
    }
}

#[derive(Clone, Copy)]
enum Completion {
    Normal,
    Canceled,
}

/// Unique owner of an authenticated connection. Channels never keep it alive.
pub struct Connection {
    pub routed_from: Option<crate::Route>,
    endpoint: Arc<Endpoint>,
    task: Option<JoinHandle<()>>,
    configuration: Option<crate::config::Binding>,
}
impl Connection {
    /// 7.4: TCP → PRELOGIN → verified TLS inside PRELOGIN → LOGIN7 → ready.
    /// 8.0: TCP → verified TLS/ALPN → PRELOGIN → LOGIN7 → ready.
    /// One deadline covers all steps. Canceling this future shuts down its driver.
    pub async fn connect(options: ConnectOptions) -> Result<Self> {
        let deadline = Instant::now()
            .checked_add(options.timeout)
            .ok_or_else(|| Error::new(ErrorKind::Limit("connection timeout")))?;
        Self::connect_until(options, deadline, None).await
    }
    pub(crate) async fn connect_until(
        options: ConnectOptions,
        deadline: Instant,
        configuration: Option<crate::config::Binding>,
    ) -> Result<Self> {
        if Instant::now()
            .checked_add(options.cleanup_timeout)
            .is_none()
        {
            return Err(Error::new(ErrorKind::Limit("cancellation cleanup timeout")));
        }
        let mut target = options;
        let mut routed_from = None;
        let mut login_server_name = None;
        loop {
            let here = crate::Route {
                server: target.host.clone(),
                port: target.port,
            };
            match Self::connect_at(
                target.clone(),
                deadline,
                login_server_name.take(),
                configuration.clone(),
            )
            .await
            {
                Ok(mut connection) => {
                    connection.routed_from = routed_from;
                    return Ok(connection);
                }
                Err(mut error) => {
                    let ErrorKind::Routed(route) = &error.kind else {
                        if !target.new_password.is_empty()
                            && matches!(error.step, Step::Login | Step::Ready)
                            && !matches!(
                                error.cause().kind,
                                ErrorKind::Server(_) | ErrorKind::ServerErrors(_)
                            )
                        {
                            error.password_change_uncertain = true;
                        }
                        return Err(error);
                    };
                    if !target.follow_routing {
                        return Err(error);
                    }
                    if let Some(from) = routed_from {
                        return Err(Error::new(ErrorKind::RepeatedRoute {
                            from,
                            via: here,
                            target: route.clone(),
                        })
                        .at(Step::Login, Execution::NotSent));
                    }
                    routed_from = Some(here);
                    if target
                        .authentication
                        .windows()
                        .is_some_and(|auth| auth.service_principal.is_some())
                    {
                        return Err(Error::new(ErrorKind::Unsupported("routed integrated login with a fixed SPN requires explicit target configuration"))
                            .at(Step::Login, Execution::NotSent));
                    }
                    target.host = route.server.clone();
                    target.port = route.port;
                    target.server_name = None; // verify the routed destination's own identity
                    login_server_name = Some(format!("{},{}", route.server, route.port));
                }
            }
        }
    }
    async fn connect_at(
        options: ConnectOptions,
        deadline: Instant,
        login_server_name: Option<String>,
        configuration: Option<crate::config::Binding>,
    ) -> Result<Self> {
        let capture = options
            .capture_factory
            .as_ref()
            .map(|factory| factory())
            .transpose()
            .map_err(|e| Error::new(ErrorKind::Capture(e)))?;
        let mut core = protocol_core(&options, login_server_name.as_deref(), None)?;
        core.configure_observation(
            options.observe.as_ref().map_or(Level::Off, |o| o.level),
            capture.is_some(),
            capture.as_ref().is_some_and(|c| c.keep_password),
        )?;
        core.observe_start()?;
        let socket = timeout_at(
            deadline,
            TcpStream::connect((options.host.as_str(), options.port)),
        )
        .await
        .map_err(|_| Error::new(ErrorKind::Timeout))??;
        socket.set_nodelay(true)?;
        let (send, receive) = mpsc::channel(1);
        let endpoint = Arc::new(Endpoint {
            #[cfg(test)]
            writes: Default::default(),
            #[cfg(feature = "encryption")]
            keys: Mutex::new(None),
            observation_error: Arc::new(Mutex::new(None)),
            commands: send,
            revoked: AtomicBool::new(false),
            epoch: Mutex::new(0),
            disconnected: AtomicBool::new(false),
            recoveries: AtomicU64::new(0),
            returning: AtomicBool::new(false),
            changed: Notify::new(),
            failure: Mutex::new(None),
            position: Mutex::new((core.step(), Execution::NotSent)),
            cleanup_timeout: options.cleanup_timeout,
        });
        let (ready, reply) = oneshot::channel();
        let task = tokio::spawn(drive(
            core,
            socket,
            receive,
            endpoint.clone(),
            ready,
            DriverSettings {
                login_deadline: deadline,
                observer: options.observe.clone(),
                capture,
                reconnect: Reconnect {
                    options,
                    login_server_name,
                    configuration: configuration.clone(),
                },
            },
        ));
        let mut guard = Abandon::new(endpoint.clone());
        timeout_at(deadline, reply)
            .await
            .map_err(|_| endpoint.locate(Error::new(ErrorKind::Timeout)))?
            .map_err(|_| endpoint.closed_error())??;
        guard.disarm();
        Ok(Self {
            routed_from: None,
            endpoint,
            task: Some(task),
            configuration,
        })
    }
    pub(crate) fn configuration_is_current(&self) -> bool {
        self.configuration
            .as_ref()
            .is_none_or(crate::config::Binding::is_current)
    }
    /// Retire this borrower's endpoint without destroying its authenticated
    /// transport. Both endpoints are guarded: canceling this future must close
    /// even if the driver has already switched to the next borrower endpoint.
    pub(crate) async fn recycle(mut self) -> Result<Option<Self>> {
        if self.is_closed() {
            self.close().await?;
            return Ok(None);
        }
        let mut old_guard = Abandon::new(self.endpoint.clone());
        self.endpoint.returning.store(true, Ordering::Release);
        #[cfg(feature = "encryption")]
        self.endpoint.revoke_keys();
        let (send, commands) = mpsc::channel(1);
        let next = Arc::new(Endpoint {
            #[cfg(test)]
            writes: Default::default(),
            #[cfg(feature = "encryption")]
            keys: Mutex::new(None),
            observation_error: self.endpoint.observation_error.clone(),
            commands: send,
            revoked: AtomicBool::new(false),
            epoch: Mutex::new(0),
            disconnected: AtomicBool::new(false),
            recoveries: AtomicU64::new(0),
            returning: AtomicBool::new(false),
            changed: Notify::new(),
            position: Mutex::new((Step::Ready, Execution::NotSent)),
            failure: Mutex::new(None),
            cleanup_timeout: self.endpoint.cleanup_timeout,
        });
        let mut next_guard = Abandon::new(next.clone());
        let deadline = Instant::now()
            .checked_add(self.endpoint.cleanup_timeout)
            .ok_or_else(|| Error::new(ErrorKind::Limit("pool return timeout")))?;
        let (reply, receive) = oneshot::channel();
        let retired = timeout_at(deadline, async {
            let permit = self
                .endpoint
                .commands
                .reserve()
                .await
                .map_err(|_| self.endpoint.closed_error())?;
            if self.endpoint.is_revoked() {
                return Err(self.endpoint.closed_error());
            }
            permit.send(Command::Recycle(Return {
                endpoint: next.clone(),
                commands,
                reply,
                deadline,
            }));
            receive.await.map_err(|_| self.endpoint.closed_error())?
        })
        .await
        .map_err(|_| {
            Error::new(ErrorKind::Timeout).at(Step::Cleanup, self.endpoint.position().1)
        })??;
        if !retired {
            return Ok(None);
        }
        let connection = Self {
            routed_from: self.routed_from.clone(),
            endpoint: next,
            task: self.task.take(),
            configuration: self.configuration.take(),
        };
        old_guard.disarm();
        next_guard.disarm();
        Ok(Some(connection))
    }
    pub(crate) async fn checkout(&self) -> Result<()> {
        let mut guard = Abandon::new(self.endpoint.clone());
        let (reply, receive) = oneshot::channel();
        self.endpoint.submit(Command::Checkout(reply)).await?;
        receive.await.map_err(|_| self.endpoint.closed_error())??;
        guard.disarm();
        Ok(())
    }
    /// Explicitly recover a broken, server-recoverable session. Existing logical
    /// channels and close permissions survive; interrupted SQL is never replayed.
    /// Canceling this future discards the connection, including a replacement.
    pub async fn recover(&self) -> Result<()> {
        let mut guard = Abandon::new(self.endpoint.clone());
        let (reply, receive) = oneshot::channel();
        self.endpoint.submit(Command::Recover(reply)).await?;
        let result = receive.await.map_err(|_| self.endpoint.closed_error())?;
        guard.disarm();
        result
    }
    pub fn recoveries(&self) -> u64 {
        self.endpoint.recoveries.load(Ordering::Acquire)
    }
    /// Open one serial channel; without MARS, a second open fails immediately.
    pub async fn serial_channel(&self) -> Result<SerialChannel> {
        let (reply, receive) = oneshot::channel();
        self.endpoint.submit(Command::Open(reply)).await?;
        let life = receive.await.map_err(|_| self.endpoint.closed_error())??;
        Ok(SerialChannel {
            endpoint: self.endpoint.clone(),
            life,
            next_exchange: 0,
            closed: false,
        })
    }
    pub async fn session(&self) -> Result<Session> {
        let (reply, receive) = oneshot::channel();
        self.endpoint.submit(Command::Session(reply)).await?;
        receive.await.map_err(|_| self.endpoint.closed_error())?
    }
    /// Bind the optional byte-crypto service to this physical epoch and lease.
    /// This does not negotiate Always Encrypted SQL metadata. The caller owns
    /// an exchange guard around each manual encrypt/send/read/decrypt sequence.
    /// Only one live service may attach; dropping it permits a replacement.
    #[cfg(feature = "encryption")]
    pub async fn key_session(
        &self,
        providers: Vec<crate::encryption::LocalKeyStore>,
        policies: crate::encryption::Policies,
    ) -> crate::encryption::Result<crate::encryption::KeySession> {
        let keys = crate::encryption::KeySession::new(providers, policies)?;
        self.attach_key_session(keys).await
    }
    #[cfg(feature = "encryption")]
    pub async fn key_session_with_providers(
        &self,
        providers: Vec<Arc<dyn crate::encryption::KeyProvider>>,
        policies: crate::encryption::Policies,
        provider_timeout: Duration,
    ) -> crate::encryption::Result<crate::encryption::KeySession> {
        let keys =
            crate::encryption::KeySession::with_providers(providers, policies, provider_timeout)?;
        self.attach_key_session(keys).await
    }
    #[cfg(feature = "encryption")]
    async fn attach_key_session(
        &self,
        keys: crate::encryption::KeySession,
    ) -> crate::encryption::Result<crate::encryption::KeySession> {
        let (reply, receive) = oneshot::channel();
        self.endpoint
            .submit(Command::AttachKeys(keys.link(), reply))
            .await
            .map_err(|_| crate::encryption::Error::Closed)?;
        receive
            .await
            .map_err(|_| crate::encryption::Error::Closed)??;
        Ok(keys)
    }
    pub fn observation_error(&self) -> Option<Arc<std::io::Error>> {
        self.endpoint
            .observation_error
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
    /// Change only between exchanges. Replacing the observer clears its diagnostic.
    pub async fn set_observe(&self, observe: Option<Observer>) -> Result<()> {
        let (reply, receive) = oneshot::channel();
        self.endpoint
            .submit(Command::Observe(observe, reply))
            .await?;
        receive.await.map_err(|_| self.endpoint.closed_error())?
    }
    /// Ownership moves into this physical connection's driver. Detachment drops
    /// the writer; it cannot be returned and attached to a different transport.
    pub async fn set_capture(&self, capture: Option<Capture>) -> Result<()> {
        let (reply, receive) = oneshot::channel();
        self.endpoint
            .submit(Command::Capture(capture, reply))
            .await?;
        receive.await.map_err(|_| self.endpoint.closed_error())?
    }
    pub fn close_handle(&self) -> CloseHandle {
        CloseHandle {
            endpoint: self.endpoint.clone(),
        }
    }
    pub fn is_closed(&self) -> bool {
        self.endpoint.is_closed() || self.endpoint.disconnected.load(Ordering::Acquire)
    }
    /// Revoke descendants and await socket/task destruction. No request is retried.
    pub async fn close(mut self) -> Result<()> {
        self.endpoint.revoke();
        if let Some(task) = self.task.take() {
            task.await.map_err(|_| {
                Error::new(ErrorKind::State(
                    "connection driver terminated unexpectedly",
                ))
                .at(Step::Close, Execution::NotSent)
            })?;
        }
        Ok(())
    }
}
impl Drop for Connection {
    fn drop(&mut self) {
        self.endpoint.revoke();
    }
}

// Only the public channel owns a strong reference to its lifetime. The driver
// keeps a Weak reference; canceled open replies therefore cannot leak authority.
struct ChannelLife {
    pending_bulk: AtomicBool,
    id: u64,
    endpoint: Weak<Endpoint>,
    close_request: Mutex<Option<CancelRequest>>,
    close_result: Mutex<Option<std::result::Result<(), Arc<Error>>>>,
    released: Notify,
}
impl ChannelLife {
    fn close_request(&self) -> Option<CancelRequest> {
        *self
            .close_request
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn complete_close(&self, result: std::result::Result<(), Arc<Error>>) {
        *self
            .close_result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(result);
        self.released.notify_waiters();
    }
    fn close_result(&self) -> Option<std::result::Result<(), Arc<Error>>> {
        self.close_result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
    }
}

/// Delegated close permission for one channel lifetime. It grants no send/read
/// authority and does not keep an otherwise dropped channel alive.
#[derive(Clone)]
pub struct ChannelCloseHandle {
    life: Weak<ChannelLife>,
}
impl ChannelCloseHandle {
    /// Revoke immediately when polled. Active exchanges are canceled and drained
    /// under the first close/cancel deadline; idle channels release immediately.
    /// Repeated/stale controls cannot close a replacement channel. Dropping an
    /// in-progress close future discards the connection.
    pub async fn close(&self) -> Result<()> {
        let Some(life) = self.life.upgrade() else {
            return Ok(());
        };
        let Some(endpoint) = life.endpoint.upgrade() else {
            return Ok(());
        };
        {
            let mut request = life
                .close_request
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if request.is_none() {
                *request = Some(CancelRequest {
                    deadline: Instant::now().checked_add(endpoint.cleanup_timeout),
                });
            }
        }
        endpoint.changed.notify_one();
        let mut guard = Abandon::new(endpoint.clone());
        loop {
            let notified = life.released.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(result) = life.close_result() {
                guard.disarm();
                return result.map_err(|error| {
                    Error::cleanup(
                        Error::new(ErrorKind::Closed).at(Step::Cleanup, error.execution),
                        Error::shared(error),
                    )
                });
            }
            if endpoint.is_closed() {
                return Err(endpoint.closed_error());
            }
            notified.await;
        }
    }
}
impl Drop for ChannelLife {
    fn drop(&mut self) {
        if let Some(endpoint) = self.endpoint.upgrade() {
            endpoint.changed.notify_one();
        }
    }
}

/// Movable, non-Clone send/read authority. No task identity is recorded.
///
/// An exclusive response borrow prevents overlap:
/// ```compile_fail
/// # async fn example(ch: &mut tds_client::SerialChannel) -> tds_client::Result<()> {
/// let response = ch.exchange(tds_client::Batch::new("SELECT 1")).await?;
/// let another = ch.exchange(tds_client::Batch::new("SELECT 2")).await?;
/// drop(response);
/// # Ok(()) }
/// ```
/// Moves transfer authority; the previous owner cannot keep using the channel:
/// ```compile_fail
/// fn transfer(channel: tds_client::SerialChannel) {
///     let new_owner = channel;
///     drop(channel);
/// }
/// ```
pub struct SerialChannel {
    endpoint: Arc<Endpoint>,
    life: Arc<ChannelLife>,
    next_exchange: u64,
    closed: bool,
}
impl SerialChannel {
    /// Submit one typed request. Once submitted, canceling this future revokes
    /// the connection: the driver may already have started transmitting it.
    pub async fn exchange(&mut self, request: impl Request + 'static) -> Result<Response<'_>> {
        if self.closed || self.life.close_request().is_some() {
            return Err(self.endpoint.closed_error());
        }
        self.next_exchange = self
            .next_exchange
            .checked_add(1)
            .ok_or_else(|| Error::new(ErrorKind::Limit("exchange identity")))?;
        let exchange = self.next_exchange;
        if exchange == u64::MAX {
            return Err(Error::new(ErrorKind::Limit("exchange identity")));
        }
        // Reserving capacity is side-effect free. Arm abandonment BEFORE send,
        // with no intervening await; a dropped future cannot leave a queued SQL
        // command whose caller has silently disappeared.
        let permit = self
            .endpoint
            .commands
            .reserve()
            .await
            .map_err(|_| self.endpoint.closed_error())?;
        if self.endpoint.is_closed() || self.life.close_request().is_some() {
            return Err(self.endpoint.closed_error());
        }
        let mut guard = Abandon::for_epoch(self.endpoint.clone(), self.endpoint.epoch());
        let (reply, receive) = oneshot::channel();
        let (complete, completion) = oneshot::channel();
        let control = Arc::new(ExchangeControl {
            channel: self.life.id,
            exchange,
            epoch: guard.epoch.unwrap(),
            endpoint: Arc::downgrade(&self.endpoint),
            finished: AtomicBool::new(false),
            request: Mutex::new(None),
            retention: Mutex::new(Retention::default()),
        });
        permit.send(Command::Begin {
            channel: self.life.id,
            exchange,
            request: Box::new(request),
            control: control.clone(),
            complete,
            reply,
        });
        let result = receive.await.map_err(|_| self.endpoint.closed_error())?;
        guard.disarm();
        result?;
        Ok(Response {
            channel: Some(self),
            exchange,
            finished: false,
            control,
            completion: Some(completion),
            reported: false,
            result_active: false,
            row_pending: false,
            value_pending: false,
        })
    }
    pub fn close_handle(&self) -> ChannelCloseHandle {
        ChannelCloseHandle {
            life: Arc::downgrade(&self.life),
        }
    }
    /// Close this channel lifetime, canceling/draining an active exchange first.
    pub async fn close(mut self) -> Result<()> {
        let result = self.close_handle().close().await;
        if result.is_ok() {
            self.closed = true;
        }
        result
    }
}

/// One advancing response. Rows/metadata are owned values, independent of the
/// decoder buffer. Dropping an unfinished response closes the connection.
#[must_use = "Read through completion, finish, fetch, or explicitly close this response"]
pub struct Response<'a> {
    channel: Option<&'a mut SerialChannel>,
    exchange: u64,
    finished: bool,
    control: Arc<ExchangeControl>,
    completion: Option<oneshot::Receiver<Result<Completion>>>,
    reported: bool,
    result_active: bool,
    row_pending: bool,
    value_pending: bool,
}
impl Response<'_> {
    /// Read one ordered wire item. Final DONE precedes checked completion:
    /// SQL errors are raised once, on the following read, with the whole record.
    /// Canceling a submitted read revokes the connection, since it may already
    /// have consumed a record. No record is silently skipped on later reuse.
    pub async fn next(&mut self) -> Result<Option<Record>> {
        self.drain_row().await?;
        match self.next_event().await? {
            Some(Record::RowStart) => {
                let mut row = Vec::new();
                let mut value = None;
                loop {
                    match self.next_event().await? {
                        Some(Record::Cell(cell)) => row.push(cell),
                        Some(Record::ValueStart { sql_type, .. }) => {
                            value = Some(crate::large::empty(&sql_type))
                        }
                        Some(Record::ValueChunk(chunk)) => crate::large::append(
                            value
                                .as_mut()
                                .ok_or_else(|| Error::malformed(0, "chunk outside value"))?,
                            chunk,
                        )?,
                        Some(Record::ValueEnd) => row.push(value.take()),
                        Some(Record::RowEnd) => return Ok(Some(Record::Row(row))),
                        _ => return Err(Error::malformed(0, "incomplete streamed row")),
                    }
                }
            }
            record => Ok(record),
        }
    }
    async fn drain_row(&mut self) -> Result<()> {
        while self.row_pending {
            if self.next_event().await?.is_none() {
                return Err(Error::malformed(0, "unfinished streamed row"));
            }
        }
        Ok(())
    }
    async fn next_event(&mut self) -> Result<Option<Record>> {
        let record = self.next_event_inner().await?;
        match &record {
            Some(Record::RowStart) => self.row_pending = true,
            Some(Record::RowEnd) => {
                self.row_pending = false;
                self.value_pending = false;
            }
            Some(Record::ValueStart { .. }) => self.value_pending = true,
            Some(Record::ValueEnd) => self.value_pending = false,
            _ => {}
        }
        Ok(record)
    }
    async fn next_event_inner(&mut self) -> Result<Option<Record>> {
        if !self.finished
            && self
                .channel
                .as_ref()
                .expect("response owns its channel")
                .life
                .close_request()
                .is_some()
        {
            return self.read_record().await;
        }
        if let Some(record) = self.control.retention().unread.pop_front() {
            return Ok(Some(record));
        }
        match self.read_record().await? {
            Some(record) => {
                // A previously selected KEEP mode can also have queued this
                // item. Deliver it once, without changing row retention.
                Ok(Some(
                    self.control
                        .retention()
                        .unread
                        .pop_front()
                        .unwrap_or(record),
                ))
            }
            None => {
                self.at_end()?;
                Ok(None)
            }
        }
    }
    /// Snapshot received metadata and deliberately retained rows. It grants no
    /// authority to advance this response and does not read ahead.
    pub fn snapshot(&self) -> FetchedResponse {
        self.control.retention().record.clone()
    }
    /// Exchange timing at every observation level. Snapshot only; no read-ahead.
    pub fn timing(&self) -> crate::response::Timing {
        self.control.retention().record.timing
    }
    /// Drain normally, discarding unread rows. Metadata, messages, errors and
    /// completions remain inspectable through `snapshot()`. This sends no Attention.
    pub async fn finish(&mut self) -> Result<()> {
        self.control.retention().discard();
        while self.read_record().await?.is_some() {}
        self.row_pending = false;
        self.value_pending = false;
        self.at_end()
    }
    /// Retain complete result sets and return an independent memory-backed
    /// response. Earlier streamed rows are never reconstructed. Unread records
    /// remain readable on this live response, now from memory.
    ///
    /// ```no_run
    /// # async fn example(channel: &mut tds_client::SerialChannel) -> tds_client::Result<tds_client::FetchedResponse> {
    /// let fetched = {
    ///     let mut response = channel.exchange(tds_client::Batch::new("SELECT 1")).await?;
    ///     response.fetch().await?
    /// }; // The response borrow ends; fetched data have no channel authority.
    /// channel.exchange(tds_client::Batch::new("SELECT 2")).await?.finish().await?;
    /// # Ok(fetched) }
    /// ```
    pub async fn fetch(&mut self) -> Result<FetchedResponse> {
        // A borrowed reader may have consumed a prefix. Discard that row before
        // selecting KEEP; a partial row cannot become an invented complete row.
        self.drain_row().await?;
        self.control.retention().keep();
        while self.read_record().await?.is_some() {}
        self.at_end()?;
        Ok(self.snapshot())
    }
    fn at_end(&mut self) -> Result<()> {
        if self.reported {
            return Ok(());
        }
        let retained = self.control.retention();
        if retained.record.canceled {
            let snapshot = retained.record.clone();
            drop(retained);
            self.reported = true;
            return Err(Error::canceled().with_response(snapshot));
        }
        let errors: Vec<_> = retained.record.errors().cloned().collect();
        if !errors.is_empty() {
            let snapshot = retained.record.clone();
            drop(retained);
            self.reported = true;
            return Err(Error::new(ErrorKind::ServerErrors(errors))
                .at(Step::Exchange, Execution::PossiblyExecuted)
                .with_response(snapshot));
        }
        Ok(())
    }
    async fn read_record(&mut self) -> Result<Option<Record>> {
        let result = self.read_from_driver().await;
        result.map_err(|error| {
            self.reported = true;
            self.finished = true;
            error.with_response(self.snapshot())
        })
    }
    async fn read_from_driver(&mut self) -> Result<Option<Record>> {
        if self.finished {
            return Ok(None);
        }
        if self
            .channel
            .as_ref()
            .expect("response owns its channel")
            .life
            .close_request()
            .is_some()
        {
            let original =
                Error::new(ErrorKind::Closed).at(Step::Cleanup, Execution::PossiblyExecuted);
            return match self.cleanup_result().await {
                Ok(_) => Err(original),
                Err(error) => Err(Error::cleanup(original, error)),
            };
        }
        if self.control.request().is_some() {
            return match self.cleanup_result().await {
                Ok(Completion::Normal) => Ok(None),
                Ok(Completion::Canceled) => Err(Error::canceled()),
                Err(error) => Err(Error::cleanup(Error::canceled(), error)),
            };
        }
        let endpoint = &self
            .channel
            .as_ref()
            .expect("response owns its channel")
            .endpoint;
        if self.control.epoch != endpoint.epoch() {
            return self.cleanup_result().await.map(|_| None);
        }
        let permit = endpoint
            .commands
            .reserve()
            .await
            .map_err(|_| endpoint.closed_error())?;
        if endpoint.is_closed() {
            return Err(endpoint.closed_error());
        }
        let mut guard = Abandon::for_epoch(endpoint.clone(), self.control.epoch);
        let (reply, receive) = oneshot::channel();
        permit.send(Command::Next {
            channel: self
                .channel
                .as_ref()
                .expect("response owns its channel")
                .life
                .id,
            exchange: self.exchange,
            epoch: self.control.epoch,
            reply,
        });
        let result = receive.await.map_err(|_| endpoint.closed_error())?;
        guard.disarm();
        let record = match result {
            Ok(record) => record,
            Err(error) if matches!(error.kind, ErrorKind::Canceled) => {
                self.finished = true;
                return Err(error);
            }
            Err(error) if self.control.request().is_some() => {
                return Err(Error::cleanup(Error::canceled(), error));
            }
            Err(error) => return Err(error),
        };
        if matches!(&record,Record::Done(done) if done.is_final()) {
            self.finished = true;
        }
        Ok(Some(record))
    }
    pub fn cancel_handle(&self) -> CancelHandle {
        CancelHandle {
            control: self.control.clone(),
        }
    }

    async fn cleanup_result(&mut self) -> Result<Completion> {
        let receive = self
            .completion
            .take()
            .ok_or_else(|| Error::new(ErrorKind::State("exchange completion already consumed")))?;
        let mut guard = Abandon::for_epoch(
            self.channel
                .as_ref()
                .expect("response owns its channel")
                .endpoint
                .clone(),
            self.control.epoch,
        );
        let completion = receive.await.map_err(|_| {
            self.channel
                .as_ref()
                .expect("response owns its channel")
                .endpoint
                .closed_error()
        })??;
        guard.disarm();
        self.finished = true;
        Ok(completion)
    }
    async fn cleanup(&mut self) -> Result<()> {
        if self.finished {
            return Ok(());
        }
        self.control.retention().discard();
        self.cancel_handle().cancel();
        self.cleanup_result().await.map(|_| ())
    }
    /// Stop reading: send Attention and drain its acknowledgement under the
    /// connection's separate cleanup deadline. Successful cleanup permits reuse;
    /// failure, timeout or dropping this future discards the connection.
    /// This does not normally drain all rows and does not imply transaction rollback.
    pub async fn close(mut self) -> Result<()> {
        self.cleanup().await.map_err(|cause| {
            Error::cleanup(Error::canceled(), cause).with_response(self.snapshot())
        })
    }
    /// Clean up while preserving an error already being returned by the caller.
    /// Success returns `original`; failure returns both original and cleanup cause.
    /// This avoids replacing an application's failure with a teardown failure.
    pub async fn close_after(mut self, original: Error) -> Error {
        match self.cleanup().await {
            Ok(()) => original,
            Err(cause) => Error::cleanup(original, cause).with_response(self.snapshot()),
        }
    }
}
#[cfg(feature = "encryption")]
impl<'a> Response<'a> {
    /// Internal continuation after a fully drained, explicitly stale enclave
    /// refusal. Extracting a live response's channel is never permitted.
    pub(crate) fn into_finished_channel(mut self) -> Result<&'a mut SerialChannel> {
        if !self.finished || self.channel.as_ref().is_none_or(|c| c.endpoint.is_closed()) {
            return Err(Error::new(ErrorKind::Closed));
        }
        Ok(self
            .channel
            .take()
            .expect("finished response owns its channel"))
    }
}
impl Drop for Response<'_> {
    fn drop(&mut self) {
        if !self.finished
            && self
                .channel
                .as_ref()
                .is_some_and(|c| c.life.close_result().is_none())
        {
            self.channel
                .as_ref()
                .expect("response owns its channel")
                .endpoint
                .revoke_epoch(self.control.epoch);
        }
    }
}
struct Abandon {
    endpoint: Arc<Endpoint>,
    epoch: Option<u64>,
    armed: bool,
}
impl Abandon {
    fn new(endpoint: Arc<Endpoint>) -> Self {
        Self {
            endpoint,
            epoch: None,
            armed: true,
        }
    }
    fn for_epoch(endpoint: Arc<Endpoint>, epoch: u64) -> Self {
        Self {
            endpoint,
            epoch: Some(epoch),
            armed: true,
        }
    }
    fn disarm(&mut self) {
        self.armed = false;
    }
}
impl Drop for Abandon {
    fn drop(&mut self) {
        if self.armed {
            if let Some(epoch) = self.epoch {
                self.endpoint.revoke_epoch(epoch);
            } else {
                self.endpoint.revoke();
            }
        }
    }
}

fn unix_seconds() -> Result<u64> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| Error::new(ErrorKind::State("system clock precedes Unix epoch")))
}

// The task owns transport and protocol state. Each channel has one submitted
// request, one advancing read and one completion notification. The application
// owns the channel lifetime; Weak entries cannot keep abandoned authority alive.
struct Return {
    endpoint: Arc<Endpoint>,
    commands: mpsc::Receiver<Command>,
    reply: Reply<bool>,
    deadline: Instant,
}
struct Reconnect {
    options: ConnectOptions,
    login_server_name: Option<String>,
    configuration: Option<crate::config::Binding>,
}
struct DriverSettings {
    login_deadline: Instant,
    observer: Option<Observer>,
    capture: Option<Capture>,
    reconnect: Reconnect,
}
struct Broken {
    cause: Arc<Error>,
    idle: bool,
}
struct Driver {
    login_deadline: Instant,
    #[cfg(feature = "integrated-auth")]
    authentication: Option<crate::auth::Context>,
    reconnect: Reconnect,
    broken: Option<Broken>,
    observer: Option<Observer>,
    capture: Option<Capture>,
    began: Instant,
    core: ConnectionCore,
    socket: Option<TcpStream>, // None while the failed physical epoch awaits explicit/new-work recovery
    commands: mpsc::Receiver<Command>,
    endpoint: Arc<Endpoint>,
    ready: Option<Reply<()>>,
    channels: BTreeMap<u64, DriverChannel>,
    channel_sequence: u64,
    failure_channel: Option<u64>,
    last_polled: u64,
    returning: Option<Return>,
    checkout: Option<Reply<()>>,
    idle: bool,
    stopping: bool,
}
struct DriverChannel {
    life: Weak<ChannelLife>,
    released: bool,
    begin: Option<Reply<()>>,
    next: Option<Reply<Record>>,
    active: Option<ActiveExchange>,
    sending: Option<Sending>,
    aborting: Option<SendAbort>,
}
struct ActiveExchange {
    control: Arc<ExchangeControl>,
    complete: Reply<Completion>,
}
impl DriverChannel {
    fn closing(&self) -> Option<Arc<ChannelLife>> {
        self.life
            .upgrade()
            .filter(|life| life.close_request().is_some())
    }
    fn requests(&self) -> impl Iterator<Item = CancelRequest> + '_ {
        let exchange = self.active.as_ref().and_then(|a| a.control.request());
        let channel = self
            .closing()
            .filter(|_| !self.released)
            .and_then(|life| life.close_request());
        exchange.into_iter().chain(channel)
    }
    fn complete(&mut self, completion: Completion) {
        if let Some(active) = self.active.take() {
            active
                .control
                .retention()
                .end(matches!(completion, Completion::Canceled));
            active.control.finished.store(true, Ordering::Release);
            let _ = active.complete.send(Ok(completion));
        }
    }
    fn fail(mut self, cause: Arc<Error>, fatal_record: bool) {
        let error = self.fail_exchange(cause, fatal_record);
        if let Some(life) = self.life.upgrade() {
            life.complete_close(Err(error));
        }
    }
    fn fail_exchange(&mut self, cause: Arc<Error>, fatal_record: bool) -> Arc<Error> {
        let primary = match &cause.cause().kind {
            ErrorKind::Cleanup { original, .. } => original.cause(),
            _ => cause.cause(),
        };
        if fatal_record
            && let ErrorKind::Server(message) = &primary.kind
            && let Some(active) = &self.active
        {
            let _ = active
                .control
                .retention()
                .take(&Record::Error((**message).clone()));
        }
        self.sending = None;
        let mut error = if let Some(abort) = self.aborting.take() {
            Error::cleanup(abort.cause, Error::shared(cause))
        } else {
            Error::shared(cause)
        };
        if let Some(active) = &self.active {
            active.control.finished.store(true, Ordering::Release);
            error = error.with_response(active.control.retention().record.clone());
        }
        let error = Arc::new(error);
        if let Some(reply) = self.begin.take() {
            let _ = reply.send(Err(Error::shared(error.clone())));
        }
        if let Some(reply) = self.next.take() {
            let _ = reply.send(Err(Error::shared(error.clone())));
        }
        if let Some(active) = self.active.take() {
            let _ = active.complete.send(Err(Error::shared(error.clone())));
        }
        error
    }
}
fn deliver_traces(
    core: &mut ConnectionCore,
    observer: &mut Option<Observer>,
    capture: &mut Option<Capture>,
    endpoint: &Endpoint,
    began: Instant,
) -> Result<()> {
    for trace in core.take_observations() {
        match trace {
            Trace::Packet {
                direction,
                channel,
                bytes,
            } => {
                if let Some(capture) = capture.as_mut() {
                    capture
                        .packet(began.elapsed(), direction, channel, &bytes)
                        .map_err(|e| Error::new(ErrorKind::Capture(e)))?;
                }
            }
            Trace::Event(mut event) => {
                event.elapsed = began.elapsed();
                if let Some(capture) = capture.as_mut() {
                    capture
                        .event(&event)
                        .map_err(|e| Error::new(ErrorKind::Capture(e)))?;
                }
                if let Some(callback) = observer.as_ref()
                    && callback.level != Level::Off
                    && let Err(error) = callback.emit(&event)
                {
                    *endpoint
                        .observation_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(Arc::new(error));
                    *observer = None;
                    core.disable_observer();
                }
            }
        }
    }
    Ok(())
}

impl Driver {
    async fn authenticate_federated(&mut self) -> Result<()> {
        if self.core.is_ready()
            || !matches!(
                self.reconnect.options.authentication,
                crate::Authentication::Entra(_)
            )
        {
            return Ok(());
        }
        let result = tokio::select! {
            result = recovery::supply_federated(&mut self.core, &self.reconnect.options, self.login_deadline) => result,
            _ = self.endpoint.changed.notified() => return Err(Error::new(ErrorKind::Canceled)),
        };
        if self.endpoint.is_revoked() {
            return Err(Error::new(ErrorKind::Canceled));
        }
        result
    }
    #[cfg(feature = "integrated-auth")]
    async fn authenticate(&mut self) -> Result<()> {
        if self.core.is_ready() {
            self.authentication = None;
            return Ok(());
        }
        let Some(challenge) = self.core.take_authentication_request() else {
            return Ok(());
        };
        let options = &self.reconnect.options;
        if self.authentication.is_none() {
            let auth = options
                .authentication
                .windows()
                .ok_or_else(|| Error::new(ErrorKind::State("missing authentication provider")))?;
            self.authentication = Some(crate::auth::Context::new(
                auth,
                &options.host,
                options.port,
            )?);
        }
        let binding = self.core.authentication_binding()?;
        let context = self.authentication.as_mut().expect("created context");
        let result = tokio::select! {
            result = timeout_at(self.login_deadline, context.step(challenge, &binding)) =>
                result.map_err(|_| Error::new(ErrorKind::Timeout))?,
            _ = self.endpoint.changed.notified() => return Err(Error::new(ErrorKind::Canceled)),
        }?;
        if self.endpoint.is_revoked() {
            return Err(Error::new(ErrorKind::Canceled));
        }
        #[cfg(feature = "system-gssapi")]
        if let Some(evidence) = context.gssapi_evidence() {
            self.core.record_gssapi_evidence(evidence);
        }
        self.core.provide_authentication_token(result.0, result.1)
    }
    fn deliver_observations(&mut self) -> Result<()> {
        deliver_traces(
            &mut self.core,
            &mut self.observer,
            &mut self.capture,
            &self.endpoint,
            self.began,
        )
    }
    fn reply_after_observation<T>(&mut self, reply: Reply<T>, value: T) -> Result<()> {
        if let Err(error) = self.deliver_observations() {
            let cause = Arc::new(error.at(self.core.step(), self.core.execution()));
            *self
                .endpoint
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cause.clone());
            let _ = reply.send(Err(Error::shared(cause.clone())));
            return Err(Error::shared(cause));
        }
        let _ = reply.send(Ok(value));
        Ok(())
    }
    fn begin_return(&mut self, returning: Return) -> Result<()> {
        let unresolved = self.channels.values().any(|c| {
            c.active.is_some()
                || c.begin.is_some()
                || c.next.is_some()
                || (c.closing().is_some() && !c.released)
        });
        if !self.core.can_release() || unresolved {
            let _ = returning.reply.send(Ok(false));
            self.stopping = true;
            return Ok(());
        }
        self.returning = Some(returning);
        for (&id, channel) in &mut self.channels {
            if !channel.released {
                self.core.close_channel(id)?;
                channel.released = true;
            }
        }
        Ok(())
    }
    fn complete_return(&mut self) -> Result<()> {
        let Some(returning) = &self.returning else {
            return Ok(());
        };
        if returning.endpoint.is_revoked() {
            return Err(Error::new(ErrorKind::Closed));
        }
        if !self.core.release_complete() {
            return Ok(());
        }
        self.core.prepare_reuse()?;
        let returning = self.returning.take().unwrap();
        returning.endpoint.recoveries.store(
            self.endpoint.recoveries.load(Ordering::Acquire),
            Ordering::Release,
        );
        self.endpoint.revoke();
        self.commands.close();
        while let Ok(command) = self.commands.try_recv() {
            command.fail(&self.endpoint);
        }
        self.endpoint = returning.endpoint;
        self.commands = returning.commands;
        self.idle = true;
        if returning.reply.send(Ok(true)).is_err() {
            return Err(Error::new(ErrorKind::Closed));
        }
        Ok(())
    }
    fn check_idle_transport(&mut self) -> Result<()> {
        let mut input = [0; 16384];
        loop {
            match self.socket.as_ref().unwrap().try_read(&mut input) {
                Ok(0) => return Err(Error::new(ErrorKind::Closed)),
                Ok(n) => self.core.feed(&input[..n])?,
                Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return Ok(()),
                Err(e) => return Err(e.into()),
            }
        }
    }
    fn poll_channel_close(&mut self) -> Result<()> {
        for (&id, channel) in &mut self.channels {
            let Some(life) = channel.closing() else {
                continue;
            };
            if channel.released {
                continue;
            }
            if self.core.pending_bulk(id) && !self.core.channel_busy(id) {
                let exchange = u64::MAX; // Reserved for private continuation cleanup.
                let (complete, _) = oneshot::channel();
                let control = Arc::new(ExchangeControl {
                    channel: id,
                    exchange,
                    epoch: self.endpoint.epoch(),
                    endpoint: Arc::downgrade(&self.endpoint),
                    finished: AtomicBool::new(false),
                    request: Mutex::new(Some(life.close_request().unwrap())),
                    retention: Mutex::new(Retention::default()),
                });
                let request = crate::requests::bulk::Abort;
                self.core.begin(id, exchange, &request)?;
                channel.active = Some(ActiveExchange { control, complete });
            }
            if self.core.channel_busy(id) {
                let active = channel
                    .active
                    .as_ref()
                    .ok_or_else(|| Error::new(ErrorKind::State("busy channel without exchange")))?;
                active.control.retention().discard();
                let mut request = active
                    .control
                    .request
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let close = life.close_request().unwrap();
                if request.is_none_or(|current| close.deadline < current.deadline) {
                    *request = Some(close);
                }
            } else {
                self.core.close_channel(id)?;
                // A MARS FIN must reach the socket before the close waiter wins.
                channel.released = true;
            }
        }
        Ok(())
    }
    fn complete_channel_close(&mut self) {
        self.channels.retain(|_, channel| {
            if !channel.released {
                return true;
            }
            if let Some(life) = channel.life.upgrade() {
                life.complete_close(Ok(()));
            }
            false
        });
    }
    fn update_position(&self) {
        let step = if self.returning.is_some()
            || self
                .channels
                .values()
                .flat_map(DriverChannel::requests)
                .next()
                .is_some()
        {
            Step::Cleanup
        } else {
            self.core.step()
        };
        *self
            .endpoint
            .position
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = (step, self.core.execution());
    }
    fn retire_peer_closed(&mut self) -> Result<()> {
        let ids: Vec<_> = self
            .channels
            .iter()
            .filter(|(id, c)| !c.released && self.core.channel_peer_closed(**id))
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            if self.channels[&id].requests().next().is_some() {
                return Err(Error::new(ErrorKind::Closed)); // cleanup could not prove its acknowledgement
            }
            let error = Error::new(ErrorKind::Closed).at(
                Step::Exchange,
                if self.core.channel_busy(id) {
                    Execution::PossiblyExecuted
                } else {
                    Execution::NotSent
                },
            );
            self.core.retire_peer_closed(id)?;
            self.channels
                .remove(&id)
                .unwrap()
                .fail(Arc::new(error), false);
        }
        Ok(())
    }
    fn release_abandoned_channel(&mut self) -> Result<()> {
        let ids: Vec<_> = self
            .channels
            .iter()
            .filter(|(_, c)| c.life.strong_count() == 0)
            .map(|(&id, _)| id)
            .collect();
        for id in ids {
            if !self.channels[&id].released {
                self.core.close_channel(id)?;
            }
            self.channels.remove(&id);
        }
        Ok(())
    }
    fn deadline(&self) -> Option<Instant> {
        self.channels
            .values()
            .flat_map(DriverChannel::requests)
            .filter_map(|r| r.deadline)
            .chain(
                self.channels
                    .values()
                    .filter_map(|c| c.aborting.as_ref().map(|a| a.deadline)),
            )
            .chain(self.returning.as_ref().map(|r| r.deadline))
            .min()
    }
    fn check_deadline(&self) -> Result<()> {
        if self.channels.values().any(|c| {
            c.aborting
                .as_ref()
                .is_some_and(|a| Instant::now() >= a.deadline)
        }) {
            return Err(Error::new(ErrorKind::Timeout));
        }
        if let Some(returning) = &self.returning {
            if returning.endpoint.is_revoked() {
                return Err(Error::new(ErrorKind::Closed));
            }
            if Instant::now() >= returning.deadline {
                return Err(Error::new(ErrorKind::Timeout));
            }
        }
        for request in self.channels.values().flat_map(DriverChannel::requests) {
            let deadline = request
                .deadline
                .ok_or_else(|| Error::new(ErrorKind::Limit("cancellation cleanup timeout")))?;
            if Instant::now() >= deadline {
                return Err(Error::new(ErrorKind::Timeout));
            }
        }
        Ok(())
    }
    fn request_cancellation(&mut self) -> Result<()> {
        for (&id, channel) in &self.channels {
            if let Some(active) = &channel.active
                && active.control.request().is_some()
                && channel.sending.is_none()
                && channel.aborting.is_none()
                && !self.core.channel_canceling(id)
                && !self.core.channel_sending(id)
            {
                self.core
                    .cancel(active.control.channel, active.control.exchange)?;
            }
        }
        Ok(())
    }
    async fn flush_output(&mut self) -> Result<()> {
        self.deliver_observations()?;
        let bytes = self.core.take_output();
        // The offset survives wakeups. Reads remain possible while MARS writes
        // wait: a peer's credit announcement must not be trapped behind its own
        // blocked output. TCP readiness + try_* permits both directions without
        // canceling a partial write or holding a core borrow across I/O.
        let mut offset = 0;
        let mut input = [0; 16384];
        while offset < bytes.len() {
            if self.endpoint.is_revoked() {
                return Err(self.endpoint.closed_error());
            }
            self.check_deadline()?;
            let deadline = self.deadline();
            tokio::select! {
                biased;
                _ = cleanup_timer(deadline) => return Err(Error::new(ErrorKind::Timeout)),
                _ = self.endpoint.changed.notified() => self.release_abandoned_channel()?,
                ready = async {
                    #[cfg(test)]
                    self.endpoint.writes.ready().await;
                    self.socket.as_ref().unwrap().writable().await
                } => {
                    ready?;
                    #[cfg(test)]
                    let written = self.endpoint.writes.try_write(self.socket.as_ref().unwrap(), &bytes[offset..]);
                    #[cfg(not(test))]
                    let written = self.socket.as_ref().unwrap().try_write(&bytes[offset..]);
                    match written {
                        Ok(0) => return Err(std::io::Error::from(std::io::ErrorKind::WriteZero).into()),
                        Ok(n) => offset += n,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(e) => return Err(e.into()),
                    }
                }
                ready = self.socket.as_ref().unwrap().readable(), if self.core.mars_enabled() => {
                    ready?;
                    match self.socket.as_ref().unwrap().try_read(&mut input) {
                        Ok(0) => return Err(Error::new(ErrorKind::Closed)),
                        Ok(n) => self.core.feed(&input[..n])?,
                        Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {},
                        Err(e) => return Err(e.into()),
                    }
                }
            }
            self.deliver_observations()?;
        }
        Ok(())
    }
    /// One record per turn, with round-robin selection among ready readers and
    /// autonomous cancellation drains. Unrequested responses stay in their SMP
    /// credit queues. Session announcements apply when those bytes are consumed.
    fn poll_response(&mut self) -> Result<bool> {
        self.core.set_elapsed(self.began.elapsed());
        let mut ids: Vec<_> = self.channels.keys().copied().collect();
        let split = ids.partition_point(|id| *id <= self.last_polled);
        ids.rotate_left(split);
        for id in ids {
            let channel = self.channels.get_mut(&id).unwrap();
            let canceling = self.core.channel_canceling(id);
            if channel.released
                || (!canceling && channel.aborting.is_none() && channel.next.is_none())
            {
                continue;
            }
            let Some(active) = &channel.active else {
                continue;
            };
            self.failure_channel = Some(id);
            let result = self.core.next_record(id, active.control.exchange);
            if let Some(timing) = self.core.channel_timing(id) {
                active.control.retention().record.timing = timing;
            }
            let record = result?;
            self.failure_channel = None;
            let Some(record) = record else {
                continue;
            };
            #[cfg(feature = "encryption")]
            if let Some(link) = &*self
                .endpoint
                .keys
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                link.observe(&record)
                    .map_err(|_| Error::malformed(0, "encryption lifecycle announcement"))?;
            }
            active.control.retention().take(&record)?;
            // Commit the semantic prefix before diagnostic delivery, but do not
            // publish a record/completion until its requested recording succeeds.
            self.deliver_observations()?;
            let channel = self.channels.get_mut(&id).unwrap();
            if !self.core.channel_busy(id) {
                if let Some(life) = channel.life.upgrade() {
                    life.pending_bulk
                        .store(self.core.pending_bulk(id), Ordering::Release);
                }
                let abort = channel.aborting.take();
                let snapshot = abort.as_ref().map(|_| {
                    channel
                        .active
                        .as_ref()
                        .unwrap()
                        .control
                        .retention()
                        .record
                        .clone()
                });
                channel.complete(if canceling {
                    Completion::Canceled
                } else {
                    Completion::Normal
                });
                if let Some(abort) = abort
                    && let Some(reply) = channel.begin.take()
                {
                    let mut snapshot = snapshot.unwrap();
                    snapshot.ended = true;
                    let _ = reply.send(Err(abort
                        .cause
                        .at(Step::Exchange, Execution::PossiblyExecuted)
                        .with_response(snapshot)));
                }
            }
            if canceling {
                if channel.active.is_none()
                    && let Some(reply) = channel.next.take()
                {
                    let _ = reply.send(Err(Error::canceled()));
                }
            } else if let Some(reply) = channel.next.take()
                && reply.send(Ok(record)).is_err()
            {
                return Err(self.endpoint.closed_error());
            }
            self.last_polled = id;
            return Ok(true);
        }
        Ok(false)
    }
    fn command(&mut self, command: Command) -> Result<()> {
        if let Err(error) = self.deliver_observations() {
            let cause = Arc::new(error.at(self.core.step(), self.core.execution()));
            *self
                .endpoint
                .failure
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cause.clone());
            command.fail(&self.endpoint);
            return Err(Error::shared(cause));
        }
        if self.endpoint.returning.load(Ordering::Acquire)
            && !matches!(command, Command::Recycle(_))
        {
            command.fail(&self.endpoint);
            return Ok(());
        }
        match command {
            #[cfg(feature = "encryption")]
            Command::AttachKeys(link, reply) => {
                let mut slot = self
                    .endpoint
                    .keys
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if self.endpoint.is_closed() || self.broken.is_some() {
                    let _ = reply.send(Err(crate::encryption::Error::Closed));
                } else if self.core.is_busy()
                    || slot
                        .as_ref()
                        .is_some_and(crate::encryption::LifecycleLink::alive)
                {
                    let _ = reply.send(Err(crate::encryption::Error::Busy));
                } else {
                    let result = link.transaction(self.core.session().transaction);
                    if result.is_ok() {
                        link.expect_reuse_reset(self.core.reuse_reset_pending());
                        *slot = Some(link);
                    }
                    let _ = reply.send(result);
                }
            }
            Command::Recover(reply) => {
                let _ = reply.send(Err(recovery_error("connection is not broken", None)));
            }
            Command::Observe(observer, reply) => {
                let result = self.core.configure_observation(
                    observer.as_ref().map_or(Level::Off, |o| o.level),
                    self.capture.is_some(),
                    self.capture.as_ref().is_some_and(|c| c.keep_password),
                );
                if result.is_ok() {
                    self.observer = observer;
                    *self
                        .endpoint
                        .observation_error
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
                }
                let _ = reply.send(result);
            }
            Command::Capture(capture, reply) => {
                let result = self.core.configure_observation(
                    self.observer.as_ref().map_or(Level::Off, |o| o.level),
                    capture.is_some(),
                    capture.as_ref().is_some_and(|c| c.keep_password),
                );
                if result.is_ok() {
                    self.capture = capture;
                }
                let _ = reply.send(result);
            }
            Command::Open(reply) => {
                let id = self.channel_sequence;
                self.channel_sequence = self
                    .channel_sequence
                    .checked_add(1)
                    .ok_or_else(|| Error::new(ErrorKind::Limit("channel identity")))?;
                match self.core.open_channel(id) {
                    Ok(()) => {
                        let life = Arc::new(ChannelLife {
                            pending_bulk: AtomicBool::new(false),
                            id,
                            endpoint: Arc::downgrade(&self.endpoint),
                            close_request: Mutex::new(None),
                            close_result: Mutex::new(None),
                            released: Notify::new(),
                        });
                        self.channels.insert(
                            id,
                            DriverChannel {
                                life: Arc::downgrade(&life),
                                released: false,
                                begin: None,
                                next: None,
                                active: None,
                                sending: None,
                                aborting: None,
                            },
                        );
                        self.reply_after_observation(reply, life)?;
                    }
                    Err(error) => {
                        let _ = reply.send(Err(error.at(self.core.step(), self.core.execution())));
                    }
                }
            }
            Command::Begin {
                channel: id,
                exchange,
                request,
                control,
                complete,
                reply,
            } => {
                if control.epoch != self.endpoint.epoch()
                    || self
                        .channels
                        .get(&id)
                        .is_none_or(|c| c.released || c.closing().is_some())
                {
                    let _ = reply.send(Err(self.endpoint.closed_error()));
                    return Ok(());
                }
                let label = request.label();
                let prepared = self
                    .core
                    .request_context(id)
                    .and_then(|context| request.prepare(&context));
                let result = prepared.and_then(|prepared| {
                    let streaming = !prepared.sources.is_empty()
                        || prepared.encoded.body.len() > crate::wire::MAX_PENDING;
                    let kind = prepared.encoded.kind;
                    let body = self.core.begin_encoded(
                        id,
                        exchange,
                        label,
                        prepared.encoded,
                        streaming,
                    )?;
                    Ok(streaming.then(|| Sending::new(kind, body, prepared.sources)))
                });
                match result {
                    Ok(sending) => {
                        if self.core.channel_canceling(id) {
                            *control
                                .request
                                .lock()
                                .unwrap_or_else(std::sync::PoisonError::into_inner) =
                                Some(CancelRequest {
                                    deadline: Instant::now()
                                        .checked_add(self.endpoint.cleanup_timeout),
                                });
                        }
                        let channel = self.channels.get_mut(&id).unwrap();
                        channel.active = Some(ActiveExchange { control, complete });
                        channel.sending = sending;
                        // Reply after every frame and source has completed.
                        channel.begin = Some(reply);
                    }
                    Err(error) => {
                        let fatal = self.core.is_failed();
                        // A nonfatal begin refusal happened before this request
                        // emitted bytes. A busy MARS sibling cannot make this
                        // new request's execution uncertain.
                        let error = if fatal {
                            error.at(self.core.step(), self.core.execution())
                        } else {
                            error.at(Step::Exchange, Execution::NotSent)
                        };
                        let _ = reply.send(Err(error));
                        if fatal {
                            return Err(self.endpoint.closed_error());
                        }
                    }
                }
            }
            Command::Next {
                channel: id,
                exchange,
                epoch,
                reply,
            } => {
                if epoch != self.endpoint.epoch() {
                    let _ = reply.send(Err(self.endpoint.closed_error()));
                    return Ok(());
                }
                let Some(channel) = self.channels.get_mut(&id) else {
                    let _ = reply.send(Err(self.endpoint.closed_error()));
                    return Ok(());
                };
                if channel.next.is_some() {
                    let _ = reply.send(Err(Error::new(ErrorKind::State(
                        "one advancing reader is allowed per channel",
                    ))));
                } else if channel
                    .active
                    .as_ref()
                    .is_none_or(|a| a.control.exchange != exchange)
                {
                    let _ = reply.send(Err(Error::canceled()));
                } else {
                    channel.next = Some(reply);
                }
            }
            Command::Session(reply) => {
                let _ = reply.send(Ok(self.core.session().clone()));
            }
            Command::Recycle(returning) => self.begin_return(returning)?,
            Command::Checkout(reply) => {
                if !self.idle {
                    let _ = reply.send(Err(Error::new(ErrorKind::State(
                        "connection is already lent",
                    ))));
                } else {
                    self.checkout = Some(reply);
                    self.check_idle_transport()?;
                    self.idle = false;
                }
            }
        }
        Ok(())
    }
    async fn run(&mut self) -> Result<()> {
        let mut input = [0; 16384];
        loop {
            if self.endpoint.is_revoked() || self.stopping {
                return Ok(());
            }
            if self.broken.is_some() {
                self.wait_broken().await?;
                continue;
            }
            self.update_position();
            self.authenticate_federated().await?;
            #[cfg(feature = "integrated-auth")]
            self.authenticate().await?;
            self.deliver_observations()?;
            if self.endpoint.is_revoked() || self.stopping {
                return Ok(());
            }
            self.release_abandoned_channel()?;
            self.retire_peer_closed()?;
            self.poll_channel_close()?;
            self.request_cancellation()?;
            self.check_deadline()?;
            // A cancellation drain can have many buffered records. Give one
            // waiting command a turn too; an eager drain must not starve siblings.
            if self.core.is_ready()
                && let Ok(command) = self.commands.try_recv()
            {
                if self.endpoint.is_revoked() {
                    command.fail(&self.endpoint);
                    return Ok(());
                }
                self.command(command)?;
            }
            self.poll_sources_once().await?;
            let sending_progress = self.pump_senders()?;
            self.flush_output().await?;
            if self.endpoint.is_revoked() {
                return Ok(());
            }
            self.poll_channel_close()?;
            self.request_cancellation()?;
            if self.core.has_output() {
                continue;
            }
            self.complete_channel_close();
            self.complete_return()?;
            if let Some(reply) = self.checkout.take()
                && reply.send(Ok(())).is_err()
            {
                return Err(self.endpoint.closed_error());
            }
            self.core.set_elapsed(self.began.elapsed());
            for (&id, channel) in &self.channels {
                if channel.closing().is_none()
                    && channel.begin.is_some()
                    && channel.sending.is_none()
                    && channel.aborting.is_none()
                    && !self.core.channel_sending(id)
                {
                    self.core.observe_request_sent(id);
                    if let Some(active) = &channel.active {
                        active.control.retention().record.timing =
                            self.core.channel_timing(id).unwrap();
                    }
                }
            }
            self.deliver_observations()?;
            for (&id, channel) in &mut self.channels {
                if channel.closing().is_none()
                    && channel.sending.is_none()
                    && channel.aborting.is_none()
                    && !self.core.channel_sending(id)
                    && let Some(reply) = channel.begin.take()
                    && reply.send(Ok(())).is_err()
                {
                    return Err(self.endpoint.closed_error());
                }
            }
            if self.core.is_ready()
                && let Some(reply) = self.ready.take()
            {
                if !self.reconnect.options.new_password.is_empty() {
                    self.reconnect
                        .options
                        .authentication
                        .sql_credentials_mut()
                        .expect("validated SQL password change")
                        .password = std::mem::take(&mut self.reconnect.options.new_password).into();
                }
                if reply.send(Ok(())).is_err() {
                    return Err(self.endpoint.closed_error());
                }
            }
            if self.poll_response()? {
                continue;
            }
            // A token may consume several SMP frames without yielding a
            // semantic record (notably an owned large output parameter). Flush
            // its receive-credit acknowledgements before awaiting more bytes.
            if sending_progress || self.core.has_output() {
                continue;
            }
            // MARS always routes incoming frames, even when an owner is idle:
            // a sibling or a pending sender may need those bytes to progress.
            let reading = !self.core.is_busy()
                || self.idle
                || self.returning.is_some()
                || self.core.mars_enabled()
                || !self.core.is_ready()
                || self.core.is_canceling()
                || self
                    .channels
                    .values()
                    .any(|c| c.aborting.is_some() || c.sending.is_some())
                || self.channels.values().any(|c| c.next.is_some());
            let deadline = self.deadline();
            tokio::select! {
                _ = cleanup_timer(deadline) => return Err(Error::new(ErrorKind::Timeout)),
                _ = self.endpoint.changed.notified() => {},
                produced = Self::await_source(&mut self.channels) => {
                    for (id, value) in produced { self.source_result(id, value)?; }
                }
                command = self.commands.recv() => {
                    let Some(command) = command else { return Ok(()); };
                    if self.endpoint.is_revoked() { command.fail(&self.endpoint); return Ok(()); }
                    self.command(command)?;
                }
                result = self.socket.as_mut().unwrap().read(&mut input), if reading => {
                    let n = result?;
                    if n == 0 { return Err(Error::new(ErrorKind::Closed)); }
                    self.core.set_time(unix_seconds()?);
                    self.core.feed(&input[..n])?;
                }
            }
        }
    }
    fn finish(mut self, outcome: Result<()>) {
        // A failed core step may still have received recordable packets (a
        // routing login, fatal token, or malformed reply). Do not lose that last
        // step just because there will be no next driver-loop iteration.
        let outcome = match self.deliver_observations() {
            Ok(()) => outcome,
            Err(recording) => Err(match outcome {
                Ok(()) => recording,
                Err(original) => Error::cleanup(original, recording),
            }),
        };
        self.update_position();
        self.commands.close();
        let error = outcome
            .err()
            .unwrap_or_else(|| Error::new(ErrorKind::Closed))
            .at(self.endpoint.position().0, self.core.execution());
        if let Some(reply) = self.ready.take() {
            self.endpoint.revoke();
            let _ = reply.send(Err(error));
            return;
        }
        let cause = Arc::new(error);
        *self
            .endpoint
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cause.clone());
        self.endpoint.revoke();
        if let Some(returning) = self.returning.take() {
            returning.endpoint.revoke();
            let _ = returning.reply.send(Err(Error::shared(cause.clone())));
        }
        if let Some(reply) = self.checkout.take() {
            let _ = reply.send(Err(Error::shared(cause.clone())));
        }
        for (id, channel) in std::mem::take(&mut self.channels) {
            channel.fail(cause.clone(), self.failure_channel == Some(id));
        }
        while let Ok(command) = self.commands.try_recv() {
            command.fail(&self.endpoint);
        }
        // All current waiters observe the same cause, each with its own response
        // prefix. Socket/core destruction ends every transport obligation here.
    }
}

// Follow the CURRENT endpoint after every lease rotation, including on task
// abort, panic and runtime destruction. Old endpoint guards cannot protect it.
impl Drop for Driver {
    fn drop(&mut self) {
        self.endpoint.revoke();
        if let Some(returning) = &self.returning {
            returning.endpoint.revoke();
        }
    }
}

async fn cleanup_timer(deadline: Option<Instant>) {
    match deadline {
        Some(deadline) => sleep_until(deadline).await,
        None => std::future::pending::<()>().await,
    }
}

async fn drive(
    core: ConnectionCore,
    socket: TcpStream,
    commands: mpsc::Receiver<Command>,
    endpoint: Arc<Endpoint>,
    ready: Reply<()>,
    settings: DriverSettings,
) {
    let mut driver = Driver {
        login_deadline: settings.login_deadline,
        #[cfg(feature = "integrated-auth")]
        authentication: None,
        observer: settings.observer,
        capture: settings.capture,
        reconnect: settings.reconnect,
        broken: None,
        began: Instant::now(),
        core,
        socket: Some(socket),
        commands,
        endpoint,
        ready: Some(ready),
        channels: BTreeMap::new(),
        channel_sequence: 0,
        failure_channel: None,
        last_polled: 0,
        returning: None,
        checkout: None,
        idle: false,
        stopping: false,
    };
    loop {
        let outcome = driver.run().await;
        match outcome {
            Err(error) if driver.can_suspend(&error) => {
                if let Err(error) = driver.suspend(error) {
                    driver.finish(Err(error));
                    return;
                }
            }
            outcome => {
                driver.finish(outcome);
                return;
            }
        }
    }
}

#[cfg(test)]
mod interruptions;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn old_epoch_abandonment_is_harmless_but_current_and_root_guards_revoke() {
        let (commands, _) = mpsc::channel(1);
        let endpoint = Arc::new(Endpoint {
            writes: Default::default(),
            #[cfg(feature = "encryption")]
            keys: Mutex::new(None),
            observation_error: Arc::new(Mutex::new(None)),
            commands,
            revoked: AtomicBool::new(false),
            returning: AtomicBool::new(false),
            changed: Notify::new(),
            position: Mutex::new((Step::Ready, Execution::NotSent)),
            failure: Mutex::new(None),
            cleanup_timeout: Duration::from_secs(5),
            epoch: Mutex::new(0),
            disconnected: AtomicBool::new(false),
            recoveries: AtomicU64::new(0),
        });
        let old = Abandon::for_epoch(endpoint.clone(), 0);
        *endpoint.epoch.lock().unwrap() = 1;
        drop(old);
        assert!(!endpoint.is_revoked());
        drop(Abandon::for_epoch(endpoint.clone(), 1));
        assert!(endpoint.is_revoked());
        endpoint.revoked.store(false, Ordering::Release);
        let root = Abandon::new(endpoint.clone());
        *endpoint.epoch.lock().unwrap() = 2;
        drop(root);
        assert!(endpoint.is_revoked());
    }
    #[tokio::test(start_paused = true)]
    async fn channel_close_bypasses_a_full_mailbox_and_shares_the_first_deadline() {
        let (commands, _receive) = mpsc::channel(1);
        let endpoint = Arc::new(Endpoint {
            writes: Default::default(),
            #[cfg(feature = "encryption")]
            keys: Mutex::new(None),
            observation_error: Arc::new(Mutex::new(None)),
            commands,
            revoked: AtomicBool::new(false),
            epoch: Mutex::new(0),
            disconnected: AtomicBool::new(false),
            recoveries: AtomicU64::new(0),
            returning: AtomicBool::new(false),
            changed: Notify::new(),
            failure: Mutex::new(None),
            position: Mutex::new((Step::Exchange, Execution::PossiblyExecuted)),
            cleanup_timeout: Duration::from_secs(5),
        });
        let (reply, _) = oneshot::channel();
        endpoint
            .commands
            .try_send(Command::Session(reply))
            .unwrap_or_else(|_| panic!("fill mailbox"));
        let life = Arc::new(ChannelLife {
            pending_bulk: AtomicBool::new(false),
            id: 1,
            endpoint: Arc::downgrade(&endpoint),
            close_request: Mutex::new(None),
            close_result: Mutex::new(None),
            released: Notify::new(),
        });
        let control = ChannelCloseHandle {
            life: Arc::downgrade(&life),
        };
        let first = control.close();
        tokio::pin!(first);
        let began = Instant::now();
        tokio::select! { biased; _ = &mut first => panic!("early release"), _ = tokio::task::yield_now() => {} }
        let deadline = life.close_request().unwrap().deadline;
        assert_eq!(deadline, Some(began + Duration::from_secs(5)));
        tokio::time::advance(Duration::from_secs(2)).await;
        let second = control.close();
        tokio::pin!(second);
        tokio::select! { biased; _ = &mut second => panic!("early release"), _ = tokio::task::yield_now() => {} }
        assert_eq!(life.close_request().unwrap().deadline, deadline);
        assert_eq!(endpoint.commands.capacity(), 0);
        life.complete_close(Ok(()));
        first.await.unwrap();
        second.await.unwrap();
        assert!(!endpoint.is_closed());
    }
    #[tokio::test(start_paused = true)]
    async fn cancel_bypasses_a_full_mailbox_and_repeats_do_not_extend_its_budget() {
        let (commands, mut receive) = mpsc::channel(1);
        let endpoint = Arc::new(Endpoint {
            writes: Default::default(),
            #[cfg(feature = "encryption")]
            keys: Mutex::new(None),
            observation_error: Arc::new(Mutex::new(None)),
            commands,
            revoked: AtomicBool::new(false),
            epoch: Mutex::new(0),
            disconnected: AtomicBool::new(false),
            recoveries: AtomicU64::new(0),
            returning: AtomicBool::new(false),
            changed: Notify::new(),
            failure: Mutex::new(None),
            position: Mutex::new((Step::Exchange, Execution::PossiblyExecuted)),
            cleanup_timeout: Duration::from_secs(5),
        });
        let (reply, _) = oneshot::channel();
        endpoint
            .commands
            .try_send(Command::Session(reply))
            .unwrap_or_else(|_| panic!("fill mailbox"));
        let control = Arc::new(ExchangeControl {
            channel: 1,
            exchange: 1,
            epoch: 0,
            endpoint: Arc::downgrade(&endpoint),
            finished: AtomicBool::new(false),
            request: Mutex::new(None),
            retention: Mutex::new(Retention::default()),
        });
        let cancel = CancelHandle {
            control: control.clone(),
        };
        let began = Instant::now();
        cancel.cancel();
        endpoint.changed.notified().await;
        let deadline = control.request().unwrap().deadline.unwrap();
        assert_eq!(deadline, began + Duration::from_secs(5));
        assert_eq!(endpoint.commands.capacity(), 0);
        tokio::time::advance(Duration::from_secs(2)).await;
        cancel.cancel();
        assert_eq!(control.request().unwrap().deadline, Some(deadline));
        assert!(matches!(receive.try_recv().unwrap(), Command::Session(_)));
        let completed = Arc::new(ExchangeControl {
            channel: 1,
            exchange: 2,
            epoch: 0,
            endpoint: Arc::downgrade(&endpoint),
            finished: AtomicBool::new(true),
            request: Mutex::new(None),
            retention: Mutex::new(Retention::default()),
        });
        CancelHandle {
            control: completed.clone(),
        }
        .cancel();
        assert!(completed.request().is_none());
    }
}

mod bulk;
pub use bulk::BulkWriter;
