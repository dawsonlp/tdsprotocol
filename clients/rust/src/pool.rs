//! Whole authenticated connections lent to one borrower at a time.
//! Reference: `docs/design/A-the-client.md` §3, Python `connection/shell.py::Pool`.
//!
//! A semaphore bounds lent + opening connections. Idle connections are removed
//! under one short synchronous lock before a reserved slot opens another. Return
//! inserts an idle connection BEFORE releasing its slot. No lock crosses I/O.
//! A reservation's destructor accounts for canceled acquisition, opening failure,
//! and dropped leases; it performs no protocol work. Only awaited release can
//! put a connection back. The driver retires its old authority endpoint first.

use crate::config::{Binding, ConfigState};
use crate::{
    ConfigError, ConfigPhase, ConfigService, ConnectionConfig, ConnectionServices, PoolPolicy,
    StaticConfig,
};
use crate::{ConnectOptions, Connection, Error, ErrorKind, Execution, Result, Step};
use std::{
    ops::Deref,
    sync::{Arc, Mutex},
};
use tokio::sync::{OwnedSemaphorePermit, Semaphore, watch};
use tokio::time::Instant;

/// One pool owner; use `Arc<Pool>` when independent tasks share acquisition.
/// Dropping the pool closes idle connections and prevents further acquisition.
/// Lent connections stay usable until their lease is returned or dropped.
///
/// ```no_run
/// # async fn example(options: tds_client::ConnectOptions) -> tds_client::Result<()> {
/// use tds_client::{Batch, Pool};
/// let pool = Pool::new(options, 2)?;
/// let lease = pool.acquire().await?;
/// let mut channel = lease.serial_channel().await?;
/// channel.exchange(Batch::new("SELECT 1")).await?.finish().await?;
/// channel.close().await?;
/// lease.release().await?; // Drop would discard the connection instead.
/// pool.close().await?;
/// # Ok(()) }
/// ```
pub struct Pool {
    inner: Arc<Inner>,
}
struct Inner {
    configuration: Arc<ConfigState>,
    services: ConnectionServices,
    policy: PoolPolicy,
    stopping: watch::Sender<bool>,
    slots: Arc<Semaphore>,
    capacity: usize,
    state: Mutex<State>,
}
#[derive(Default)]
struct State {
    idle: Vec<Connection>,
    closed: bool,
    lent: usize,
}
impl Inner {
    fn state(&self) -> std::sync::MutexGuard<'_, State> {
        self.state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn shut_down(&self) -> Vec<Connection> {
        let mut state = self.state();
        state.closed = true;
        self.slots.close();
        self.stopping.send_replace(true);
        std::mem::take(&mut state.idle)
    }
}
fn closed() -> Error {
    Error::new(ErrorKind::Closed).at(Step::Pool, Execution::NotSent)
}
impl Pool {
    /// Construction opens no sockets. Credentials are retained for new logins;
    /// their per-opening clones have the same redacted Debug as ConnectOptions.
    pub fn new(options: ConnectOptions, capacity: usize) -> Result<Self> {
        if !options.new_password.is_empty() {
            return Err(Error::new(ErrorKind::State(
                "a pool cannot change the server password; use an explicit connection and provide current configuration",
            )));
        }
        let configuration = ConnectionConfig::from_options(&options);
        configuration
            .validate()
            .map_err(|e| Error::new(ErrorKind::Configuration(e)))?;
        let services = ConnectionServices {
            roots: options.roots,
            server_name: options.server_name,
            observe: options.observe,
            capture_factory: options.capture_factory,
        };
        let policy = PoolPolicy {
            timeout: options.timeout,
            cleanup_timeout: options.cleanup_timeout,
        };
        Self::from_config(
            Arc::new(StaticConfig(configuration)),
            capacity,
            services,
            policy,
        )
    }
    /// Construction performs no I/O. Read current values only on a physical
    /// opening or recovery; no watcher or background configuration task is made.
    pub fn from_config(
        source: Arc<dyn ConfigService>,
        capacity: usize,
        services: ConnectionServices,
        policy: PoolPolicy,
    ) -> Result<Self> {
        if capacity == 0 || capacity > Semaphore::MAX_PERMITS {
            return Err(
                Error::new(ErrorKind::Limit("pool capacity")).at(Step::Pool, Execution::NotSent)
            );
        }
        if Instant::now().checked_add(policy.timeout).is_none()
            || Instant::now().checked_add(policy.cleanup_timeout).is_none()
        {
            return Err(Error::new(ErrorKind::Limit("pool opening/cleanup timeout")));
        }
        let (stopping, _) = watch::channel(false);
        Ok(Self {
            inner: Arc::new(Inner {
                configuration: ConfigState::new(source),
                services,
                policy,
                stopping,
                slots: Arc::new(Semaphore::new(capacity)),
                capacity,
                state: Mutex::new(State::default()),
            }),
        })
    }
    async fn open(&self) -> Result<Connection> {
        let deadline = Instant::now()
            .checked_add(self.inner.policy.timeout)
            .ok_or_else(|| Error::new(ErrorKind::Limit("pool opening timeout")))?;
        let configuration = self.inner.configuration.read(deadline).await?;
        let options = self
            .inner
            .services
            .options(&configuration, self.inner.policy);
        let binding = Binding::new(self.inner.configuration.clone(), configuration.clone());
        match Connection::connect_until(options, deadline, Some(binding)).await {
            Err(original) if original.is_authentication_failure() => {
                let refreshed = self.inner.configuration.read(deadline).await?;
                if *refreshed == *configuration {
                    return Err(original);
                }
                let options = self.inner.services.options(&refreshed, self.inner.policy);
                let binding = Binding::new(self.inner.configuration.clone(), refreshed);
                Connection::connect_until(options, deadline, Some(binding)).await
            }
            outcome => outcome,
        }
    }
    pub fn capacity(&self) -> usize {
        self.inner.capacity
    }
    /// Completed acquisitions still owned by borrowers; excludes opening logins.
    pub fn in_use(&self) -> usize {
        self.inner.state().lent
    }
    pub fn idle(&self) -> usize {
        self.inner.state().idle.len()
    }
    pub fn is_closed(&self) -> bool {
        self.inner.state().closed
    }
    /// Wait for capacity, then obtain one whole session. Canceling a waiter
    /// takes no slot; canceling an opening/checkout discards that connection and
    /// releases its reservation. An application request is never retried here.
    pub async fn acquire(&self) -> Result<Lease> {
        let permit = self
            .inner
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| closed())?;
        let mut reservation = Reservation::new(self.inner.clone(), permit)?;
        loop {
            let idle = {
                let mut state = self.inner.state();
                if state.closed {
                    return Err(closed());
                }
                state.idle.pop()
            };
            let connection = if let Some(connection) = idle {
                if !connection.configuration_is_current()
                    || connection.is_closed()
                    || connection.checkout().await.is_err()
                {
                    connection.close().await?;
                    continue; // No request was sent. Replace an idle failed transport.
                }
                connection
            } else {
                let mut stopping = self.inner.stopping.subscribe();
                if *stopping.borrow() {
                    return Err(closed());
                }
                tokio::select! {
                    _ = stopping.changed() => return Err(closed()),
                    result = self.open() => result?,
                }
            };
            // Pool closure can race an opening login. Never lend its late result.
            let lent = {
                let mut state = self.inner.state();
                if state.closed {
                    false
                } else {
                    state.lent += 1;
                    reservation.lent = true;
                    true
                }
            };
            if !lent {
                connection.close().await?;
                return Err(closed());
            }
            if !connection.configuration_is_current() {
                // Reservation already accounts for the pending lease; its Drop
                // rolls back that counter after the uncommitted transport closes.
                connection.close().await?;
                return Err(Error::new(ErrorKind::Configuration(ConfigError::new(
                    ConfigPhase::Superseded,
                    "settings changed before opening completed",
                )))
                .at(Step::Configuration, Execution::NotSent));
            }
            return Ok(Lease {
                connection: Some(connection),
                reservation,
            });
        }
    }
    /// Wake waiting acquirers and close all idle connections. Like Python, this
    /// does not interrupt borrowed sessions; their later release discards them.
    /// Canceling close still leaves the pool closed and remaining sockets revoked.
    pub async fn close(&self) -> Result<()> {
        let idle = self.inner.shut_down();
        let mut failure = None;
        for connection in idle {
            if let Err(error) = connection.close().await {
                failure.get_or_insert(error);
            }
        }
        failure.map_or(Ok(()), Err)
    }
}
impl Drop for Pool {
    fn drop(&mut self) {
        drop(self.inner.shut_down());
    }
}

struct Reservation {
    inner: Arc<Inner>,
    // A capacity slot is released AFTER the state counters/idle list are updated.
    _permit: OwnedSemaphorePermit,
    lent: bool,
}
impl Reservation {
    fn new(inner: Arc<Inner>, permit: OwnedSemaphorePermit) -> Result<Self> {
        {
            let state = inner.state();
            if state.closed {
                return Err(closed());
            }
        }
        Ok(Self {
            inner,
            _permit: permit,
            lent: false,
        })
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut state = self.inner.state();
        if self.lent {
            state.lent -= 1;
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReleaseOutcome {
    /// Authority retired, FIN obligations resolved, reset pending on first request.
    Returned,
    /// An active/failed connection or a closed pool prevented reuse.
    Discarded,
}
/// Unique whole-connection lease. Channels and controls cannot survive return as
/// usable authority. `Deref` lends Connection methods without permitting removal
/// of the owned connection. Drop always discards, even if the session is idle.
#[must_use = "await release() for reuse; dropping a lease discards its connection"]
pub struct Lease {
    connection: Option<Connection>,
    reservation: Reservation,
}
impl Deref for Lease {
    type Target = Connection;
    fn deref(&self) -> &Connection {
        self.connection
            .as_ref()
            .expect("live lease owns connection")
    }
}
impl Lease {
    /// Return only after quiescence is proved, under the connection cleanup
    /// budget. Active exchanges are discarded, not implicitly canceled. Dropping
    /// this future also discards, including if endpoint retirement already won.
    pub async fn release(mut self) -> Result<ReleaseOutcome> {
        let connection = self.connection.take().expect("live lease owns connection");
        if self.reservation.inner.state().closed || !connection.configuration_is_current() {
            connection.close().await?;
            return Ok(ReleaseOutcome::Discarded);
        }
        let Some(connection) = connection.recycle().await? else {
            return Ok(ReleaseOutcome::Discarded);
        };
        let discard = {
            let mut state = self.reservation.inner.state();
            if state.closed || !connection.configuration_is_current() {
                Some(connection)
            } else {
                state.idle.push(connection);
                None
            }
        };
        if let Some(connection) = discard {
            connection.close().await?;
            Ok(ReleaseOutcome::Discarded)
        } else {
            Ok(ReleaseOutcome::Returned)
        }
    }
}
// Field destruction first drops/revokes the connection, then frees its capacity.
// There is intentionally no async return or cleanup started by Lease::drop.
