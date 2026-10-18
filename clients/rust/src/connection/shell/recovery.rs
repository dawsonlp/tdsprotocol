//! Recovery replaces a transport, never an application owner or interrupted SQL.
//!
//! One driver remains the logical authority. A network break first retires its
//! physical epoch, then fails every outstanding exchange. A candidate login owns
//! a separate socket/core/recording until the server accepts recovery and fresh
//! wire channels are established. No old request bytes enter that candidate.
use super::{
    Broken, Command, ConnectOptions, Driver, Endpoint, Reconnect, deliver_traces, unix_seconds,
};
use crate::{
    Error, ErrorKind, Execution, Result, Step,
    capture::Capture,
    config::{ConfigError, ConfigPhase, ConnectionConfig},
    connection::core::ConnectionCore,
    login7::Login,
    observe::{Level, Observer},
};
use rustls::pki_types::ServerName;
use std::sync::{Arc, atomic::Ordering};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout_at},
};

pub(super) fn recovery_error(reason: impl Into<String>, cause: Option<Error>) -> Error {
    Error::new(ErrorKind::SessionNotRecovered {
        reason: reason.into(),
        cause: cause.map(Box::new),
    })
    .at(Step::Recover, Execution::NotSent)
}
pub(super) fn protocol_core(
    options: &ConnectOptions,
    login_name: Option<&str>,
    data: Option<Vec<u8>>,
) -> Result<ConnectionCore> {
    let name = ServerName::try_from(
        options
            .server_name
            .clone()
            .unwrap_or_else(|| options.host.clone()),
    )
    .map_err(|_| Error::malformed(0, "certificate server name"))?;
    let host_name = match options.host_name.as_ref().filter(|s| !s.is_empty()) {
        Some(name) => name.clone(),
        None => hostname::get()?.into_string().map_err(|_| {
            Error::new(ErrorKind::State(
                "system hostname is not Unicode; supply host_name explicitly",
            ))
        })?,
    };
    let login = Login {
        user: options.user.clone(),
        password: options.password.clone(),
        new_password: options.new_password.clone(),
        database: options.database.clone(),
        host_name,
        server_name: login_name.unwrap_or(&options.host).to_owned(),
        process_id: std::process::id(),
        app_name: options.app_name.clone(),
        language: options.language.clone(),
        odbc: options.odbc,
        read_only_intent: options.read_only_intent,
        session_recovery: options.session_recovery,
        json_support: options.json_support,
        vector_support: options.vector_support,
        data_classification: options.data_classification,
        utf8_support: options.utf8_support,
        column_encryption: options.column_encryption,
        recovery_data: data,
    };
    ConnectionCore::new_with_mars(
        login,
        options.roots.clone(),
        name,
        unix_seconds()?,
        options.version,
        options.mars,
    )
}
struct Physical {
    core: ConnectionCore,
    socket: TcpStream,
    observer: Option<Observer>,
    capture: Option<Capture>,
    began: Instant,
    configuration: Option<Arc<ConnectionConfig>>,
}
async fn physical_recovery(
    settings: &Reconnect,
    old: &ConnectionCore,
    ids: &[u64],
    mut observer: Option<Observer>,
    endpoint: &Endpoint,
    deadline: Instant,
) -> Result<Physical> {
    // Recovery preserves the routed target and session identity. Only the
    // credential may change; opening a different session is not recovery.
    let mut options = settings.options.clone();
    let configuration = if let Some(binding) = &settings.configuration {
        let candidate = binding.state.read(deadline).await?;
        if !candidate.compatible_with(&binding.actual()) {
            return Err(Error::new(ErrorKind::Configuration(ConfigError::new(
                ConfigPhase::Compatibility,
                "recovery configuration changed session identity",
            )))
            .at(Step::Configuration, Execution::NotSent));
        }
        options.password.clone_from(&candidate.password);
        options.new_password.clear();
        Some(candidate)
    } else {
        None
    };
    let data = old.recovery_data()?;
    let mut capture = settings
        .options
        .capture_factory
        .as_ref()
        .map(|f| f())
        .transpose()
        .map_err(|e| Error::new(ErrorKind::Capture(e)))?;
    let mut core = protocol_core(&options, settings.login_server_name.as_deref(), Some(data))?;
    core.configure_observation(
        observer.as_ref().map_or(Level::Off, |o| o.level),
        capture.is_some(),
        capture.as_ref().is_some_and(|c| c.keep_password),
    )?;
    let began = Instant::now();
    core.observe_recovery(false);
    core.observe_start()?;
    let outcome = async {
        let mut socket = TcpStream::connect((options.host.as_str(), options.port)).await?;
        socket.set_nodelay(true)?;
        let mut input = [0; 16384];
        loop {
            deliver_traces(&mut core, &mut observer, &mut capture, endpoint, began)?;
            socket.write_all(&core.take_output()).await?;
            if core.is_ready() {
                break;
            }
            let n = socket.read(&mut input).await?;
            if n == 0 {
                return Err(Error::new(ErrorKind::Closed));
            }
            core.set_time(unix_seconds()?);
            core.feed(&input[..n])?;
        }
        core.adopt_recovery(old)?;
        for id in ids {
            core.open_channel(*id)?;
        }
        deliver_traces(&mut core, &mut observer, &mut capture, endpoint, began)?;
        socket.write_all(&core.take_output()).await?;
        core.observe_recovery(true);
        Ok(socket)
    }
    .await;
    // Preserve the failed login's last diagnostic step too. Recording failure
    // takes the same terminal policy as it does in the ordinary driver.
    let tracing = deliver_traces(&mut core, &mut observer, &mut capture, endpoint, began);
    let socket = match (outcome, tracing) {
        (Ok(socket), Ok(())) => socket,
        (Err(original), Err(recording)) => return Err(Error::cleanup(original, recording)),
        (Err(error), _) | (_, Err(error)) => return Err(error),
    };
    Ok(Physical {
        core,
        socket,
        observer,
        capture,
        began,
        configuration,
    })
}
impl Driver {
    pub(super) fn can_suspend(&self, error: &Error) -> bool {
        !self.endpoint.is_revoked()
            && self.ready.is_none()
            && self.core.is_ready()
            && !self.idle
            && self.returning.is_none()
            && self
                .channels
                .values()
                .filter(|c| !c.released)
                .all(|c| c.requests().next().is_none())
            && matches!(error.cause().kind, ErrorKind::Io(_) | ErrorKind::Closed)
    }
    pub(super) fn suspend(&mut self, error: Error) -> Result<()> {
        self.deliver_observations()?;
        let idle = !self.core.is_busy();
        let cause = Arc::new(error.at(self.core.step(), self.core.execution()));
        {
            let mut epoch = self
                .endpoint
                .epoch
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            *epoch = epoch
                .checked_add(1)
                .ok_or_else(|| Error::new(ErrorKind::Limit("physical epoch")))?;
        }
        // Epoch retirement precedes notification. A failed old read can now be
        // dropped at any scheduling point without revoking a later transport.
        self.socket.take(); // close the failed transport before any replacement login
        self.endpoint.disconnected.store(true, Ordering::Release);
        #[cfg(feature = "encryption")]
        self.endpoint.revoke_keys();
        *self
            .endpoint
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(cause.clone());
        for channel in self.channels.values_mut() {
            channel.fail_exchange(cause.clone(), false);
        }
        while let Ok(command) = self.commands.try_recv() {
            command.fail(&self.endpoint);
        }
        self.broken = Some(Broken { cause, idle });
        Ok(())
    }
    async fn reconnect(&mut self) -> Result<()> {
        let broken = self.broken.as_mut().unwrap();
        broken.idle = false; // only one automatic attempt per observed idle break
        if self.capture.is_some() && self.reconnect.options.capture_factory.is_none() {
            return Err(recovery_error(
                "recording a recovered connection requires capture_factory",
                Some(Error::shared(broken.cause.clone())),
            ));
        }
        let ids: Vec<_> = self
            .channels
            .iter()
            .filter(|(_, c)| !c.released && c.closing().is_none() && c.life.strong_count() != 0)
            .map(|(&id, _)| id)
            .collect();
        let deadline = Instant::now()
            .checked_add(self.reconnect.options.timeout)
            .ok_or_else(|| Error::new(ErrorKind::Limit("recovery timeout")))?;
        let endpoint = self.endpoint.clone();
        let result = {
            let attempt = timeout_at(
                deadline,
                physical_recovery(
                    &self.reconnect,
                    &self.core,
                    &ids,
                    self.observer.clone(),
                    &endpoint,
                    deadline,
                ),
            );
            tokio::pin!(attempt);
            loop {
                tokio::select! {
                    result = &mut attempt => break result.map_err(|_| Error::new(ErrorKind::Timeout)).and_then(|r| r),
                    _ = endpoint.changed.notified() => {
                        if endpoint.is_revoked() { return Err(endpoint.closed_error()); }
                    }
                }
            }
        };
        if result.is_err()
            && self
                .endpoint
                .observation_error
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .is_some()
        {
            self.observer = None;
            self.core.disable_observer();
        }
        let physical = result.map_err(|error| {
            recovery_error(
                "replacement login or channel establishment failed",
                Some(error),
            )
        })?;
        if let (Some(binding), Some(configuration)) =
            (&self.reconnect.configuration, physical.configuration)
        {
            binding.commit(configuration.clone()).map_err(|error| {
                recovery_error("replacement configuration was superseded", Some(error))
            })?;
            self.reconnect
                .options
                .password
                .clone_from(&configuration.password);
            self.reconnect.options.new_password.clear();
        }
        // All of these writes are synchronous. Logical close and channel close
        // signals are checked before any new SQL runs on the installed core.
        self.core = physical.core;
        self.socket = Some(physical.socket);
        self.observer = physical.observer;
        self.capture = physical.capture;
        self.began = physical.began;
        self.broken = None;
        self.endpoint.disconnected.store(false, Ordering::Release);
        *self
            .endpoint
            .failure
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = None;
        self.endpoint.recoveries.fetch_add(1, Ordering::Release);
        Ok(())
    }
    pub(super) async fn wait_broken(&mut self) -> Result<()> {
        // Closing/dropping an application channel while offline revokes it
        // locally. It is excluded from adoption; no cleanup runs on a new peer.
        for channel in self.channels.values_mut() {
            if channel.life.strong_count() == 0 || channel.closing().is_some() {
                channel.released = true;
                if let Some(life) = channel.life.upgrade() {
                    life.complete_close(Ok(()));
                }
            }
        }
        let command = tokio::select! {
            _ = self.endpoint.changed.notified() => return Ok(()),
            command = self.commands.recv() => command,
        };
        let Some(command) = command else {
            self.stopping = true;
            return Ok(());
        };
        if self.endpoint.is_revoked() {
            command.fail(&self.endpoint);
            return Ok(());
        }
        if matches!(&command, Command::Begin { control, .. } if control.epoch != self.endpoint.epoch())
        {
            command.fail(&self.endpoint);
            return Ok(());
        }
        let recover = matches!(command, Command::Recover(_))
            || (matches!(command, Command::Begin { .. }) && self.broken.as_ref().unwrap().idle);
        if !recover {
            command.fail(&self.endpoint);
            return Ok(());
        }
        match self.reconnect().await {
            Ok(()) => match command {
                Command::Recover(reply) => {
                    let _ = reply.send(Ok(()));
                }
                command => self.command(command)?,
            },
            Err(error) => {
                let terminal = recording_failed(&error);
                let cause = Arc::new(error);
                match command {
                    Command::Recover(reply) | Command::Begin { reply, .. } => {
                        let _ = reply.send(Err(Error::shared(cause.clone())));
                    }
                    _ => unreachable!(),
                }
                if terminal {
                    return Err(Error::shared(cause));
                }
            }
        }
        Ok(())
    }
}
fn recording_failed(error: &Error) -> bool {
    match &error.cause().kind {
        ErrorKind::Capture(_) => true,
        ErrorKind::SessionNotRecovered {
            cause: Some(cause), ..
        } => recording_failed(cause),
        ErrorKind::Cleanup { original, cleanup } => {
            recording_failed(original) || recording_failed(cleanup)
        }
        _ => false,
    }
}
