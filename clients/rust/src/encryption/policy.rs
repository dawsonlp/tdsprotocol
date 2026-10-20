use super::{
    ColumnKey, Error, KeyOperation, KeyProvider, LocalKeyStore, MasterKey, Plaintext, Result,
    cell::{Cell, MAX_VALUE},
    secret::Secret,
};
use std::{
    collections::BTreeSet,
    fmt,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    sync::{Mutex as AsyncMutex, Notify, oneshot},
    time::Instant,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub enum Policy {
    Exchange,
    #[default]
    Transaction,
    /// Absolute age, never renewed by use. May span transactions on one lease.
    Time(Duration),
}
impl Policy {
    fn validate(self) -> Result<()> {
        if let Self::Time(age) = self
            && (age.is_zero() || Instant::now().checked_add(age).is_none())
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Policies {
    pub master: Policy,
    pub column: Policy,
    pub master_capacity: usize,
    pub column_capacity: usize,
}
impl Default for Policies {
    fn default() -> Self {
        Self {
            master: Policy::Transaction,
            column: Policy::Transaction,
            master_capacity: 8,
            column_capacity: 32,
        }
    }
}
impl Policies {
    fn validate(self) -> Result<()> {
        self.master.validate()?;
        self.column.validate()?;
        if self.master_capacity == 0
            || self.column_capacity == 0
            || self.master_capacity > 4096
            || self.column_capacity > 4096
        {
            return Err(Error::InvalidPolicy);
        }
        Ok(())
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revocation {
    PoolReturn,
    Reset,
    Recovery,
    Close,
}

/// Operation counts, not CPU times. Statistics never trigger expiry themselves.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Statistics {
    pub master_load_attempts: u64,
    pub master_loads: u64,
    pub unwrap_attempts: u64,
    pub unwraps: u64,
    /// Logical calls; SDK transport retries/challenges are separate.
    pub metadata_verifications: u64,
    pub authorized_keys: u64,
    pub enclave_packages: u64,
    pub hits: u64,
    pub coalesced: u64,
    pub evictions: u64,
    pub expirations: u64,
    pub discarded_loads: u64,
    pub live_masters: usize,
    pub live_columns: usize,
    pub pending: usize,
    pub closed: bool,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    Exchange(u64),
    Transaction(u64),
    Time(Duration),
}
fn deadline(scope: Scope, born: Instant) -> Result<Option<Instant>> {
    match scope {
        Scope::Time(age) => born.checked_add(age).map(Some).ok_or(Error::InvalidPolicy),
        _ => Ok(None),
    }
}
struct Entry<K, V> {
    scope: Scope,
    key: K,
    value: V,
    deadline: Option<Instant>,
    used: u64,
}
#[derive(Clone, PartialEq, Eq)]
struct MasterId {
    provider: usize,
    path: String,
}
#[derive(Clone)]
struct Token {
    id: u64,
    context: u64,
    transaction: Option<u64>,
    policies: Policies,
}
struct Bank {
    policies: Policies,
    context: u64,
    sequence: u64,
    transaction: Option<u64>,
    transaction_sequence: u64,
    guards: BTreeSet<u64>,
    masters: Vec<Entry<MasterId, Arc<dyn MasterKey>>>,
    cells: Vec<Entry<ColumnKey, Arc<Cell>>>,
    stats: Statistics,
    enclaves: bool,
    enclave: Option<Arc<Mutex<super::enclave::Session>>>,
}
impl Bank {
    fn next(&mut self) -> Result<u64> {
        self.sequence = self.sequence.checked_add(1).ok_or(Error::Closed)?;
        Ok(self.sequence)
    }
    fn check(&self, token: &Token) -> Result<()> {
        if self.stats.closed {
            Err(Error::Closed)
        } else if token.context != self.context {
            Err(Error::Expired)
        } else if !self.guards.contains(&token.id) {
            Err(Error::Closed)
        } else {
            Ok(())
        }
    }
    fn scope(&self, token: &Token, policy: Policy) -> Scope {
        match policy {
            Policy::Exchange => Scope::Exchange(token.id),
            Policy::Transaction
                if token.transaction.is_some() && token.transaction == self.transaction =>
            {
                Scope::Transaction(token.transaction.unwrap())
            }
            Policy::Transaction => Scope::Exchange(token.id),
            Policy::Time(age) => Scope::Time(age),
        }
    }
    fn scopes(&self, token: &Token) -> (Scope, Scope) {
        (
            self.scope(token, token.policies.master),
            self.scope(token, token.policies.column),
        )
    }
    fn expire(&mut self, now: Instant) {
        let before = self.masters.len() + self.cells.len();
        self.masters.retain(|e| e.deadline.is_none_or(|d| now < d));
        self.cells.retain(|e| e.deadline.is_none_or(|d| now < d));
        self.stats.expirations += (before - self.masters.len() - self.cells.len()) as u64;
    }
    fn clear(&mut self) {
        self.masters.clear();
        self.cells.clear();
        self.enclave = None;
    }
    fn transaction_end(&mut self) {
        self.masters
            .retain(|e| !matches!(e.scope, Scope::Transaction(_)));
        self.cells
            .retain(|e| !matches!(e.scope, Scope::Transaction(_)));
        self.transaction = None;
    }
    fn cached(
        &mut self,
        token: &Token,
        key: &ColumnKey,
    ) -> Result<Option<(Arc<Cell>, Option<Instant>)>> {
        self.check(token)?;
        self.expire(Instant::now());
        let scope = self.scope(token, token.policies.column);
        let Some(index) = self
            .cells
            .iter()
            .position(|e| e.scope == scope && e.key == *key)
        else {
            return Ok(None);
        };
        self.cells[index].used = self.next()?;
        self.stats.hits += 1;
        Ok(Some((
            self.cells[index].value.clone(),
            self.cells[index].deadline,
        )))
    }
}
fn insert<K, V>(entries: &mut Vec<Entry<K, V>>, entry: Entry<K, V>, capacity: usize) -> bool {
    let evicted = entries.len() >= capacity;
    if evicted {
        let index = entries
            .iter()
            .enumerate()
            .min_by_key(|(_, e)| e.used)
            .unwrap()
            .0;
        entries.remove(index); // destruction erases the owned secret handles
    }
    entries.push(entry);
    evicted
}
struct Inner {
    bank: Mutex<Bank>,
    providers: Vec<Arc<dyn KeyProvider>>,
    gate: Arc<AsyncMutex<()>>,
    changed: Arc<Notify>,
    completed: Arc<Notify>,
    pending: Arc<AtomicUsize>,
    revoked: Notify,
    provider_timeout: Duration,
    #[cfg(test)]
    audit: Option<super::secret::Audit>,
    #[cfg(test)]
    load_gate: Mutex<Option<Arc<tests::LoadGate>>>,
}
impl Inner {
    fn bank(&self) -> std::sync::MutexGuard<'_, Bank> {
        self.bank
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }
    fn revoke(&self) {
        let mut bank = self.bank();
        bank.stats.closed = true;
        bank.clear();
        bank.guards.clear();
        drop(bank);
        self.changed.notify_one();
        self.revoked.notify_waiters();
    }
    fn check_loading(
        &self,
        bank: &mut Bank,
        token: &Token,
        scopes: (Scope, Scope),
        canceled: bool,
    ) -> Result<()> {
        let result = bank.check(token).and_then(|()| {
            if canceled {
                Err(Error::Closed)
            } else if bank.scopes(token) != scopes {
                Err(Error::Expired)
            } else {
                Ok(())
            }
        });
        if result.is_err() {
            bank.stats.discarded_loads += 1;
        }
        result
    }
    fn operation(&self) -> KeyOperation {
        KeyOperation {
            pending: self.pending.clone(),
            completed: self.completed.clone(),
        }
    }
    async fn cached_value(
        &self,
        token: &Token,
        cell: Arc<Cell>,
        expires: Option<Instant>,
        input: Input,
        reply: &oneshot::Sender<Result<Output>>,
        scopes: (Scope, Scope),
    ) -> Result<Output> {
        let output = self
            .operation()
            .blocking(move || Ok(input.apply(&cell)))
            .await?;
        let mut bank = self.bank();
        self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
        if expires.is_some_and(|at| Instant::now() >= at) {
            return Err(Error::AcquisitionExpired);
        }
        output.map(|value| value.with_deadline(expires))
    }
    async fn load(
        &self,
        token: &Token,
        key: &ColumnKey,
        input: Input,
        reply: &oneshot::Sender<Result<Output>>,
        scopes: (Scope, Scope),
    ) -> Result<Output> {
        self.check_loading(&mut self.bank(), token, scopes, reply.is_closed())?;
        if let Input::Release { signatures, .. } = &input {
            if !self.bank().enclaves {
                return Err(Error::InvalidPolicy);
            }
            let mut allowed = false;
            for (wrapped, signature) in signatures {
                let Some(provider) = self
                    .providers
                    .iter()
                    .find(|p| p.name().to_uppercase() == wrapped.provider.to_uppercase())
                else {
                    continue;
                };
                let master = provider.open(&wrapped.path, self.operation()).await?;
                self.check_loading(&mut self.bank(), token, scopes, reply.is_closed())?;
                self.bank().stats.metadata_verifications += 1;
                let valid = master
                    .verify_metadata(true, signature, self.operation())
                    .await?;
                self.check_loading(&mut self.bank(), token, scopes, reply.is_closed())?;
                if valid {
                    self.bank().stats.authorized_keys += 1;
                    allowed = true;
                    break;
                }
            }
            if !allowed {
                return Err(Error::Authentication);
            }
        }
        let cached = {
            let mut bank = self.bank();
            self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
            bank.cached(token, key)?
        };
        if let Some((cell, expires)) = cached {
            return self
                .cached_value(token, cell, expires, input, reply, scopes)
                .await;
        }
        let _gate = self.gate.clone().lock_owned().await;
        let cached = {
            let mut bank = self.bank();
            self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
            let cached = bank.cached(token, key)?;
            if cached.is_some() {
                bank.stats.coalesced += 1;
            }
            cached
        };
        if let Some((cell, expires)) = cached {
            return self
                .cached_value(token, cell, expires, input, reply, scopes)
                .await;
        }
        let mut failure = Error::KeyUnavailable;
        for wrapped in &key.values {
            let Some(provider) = self
                .providers
                .iter()
                .position(|p| p.name().to_uppercase() == wrapped.provider.to_uppercase())
            else {
                continue;
            };
            let id = MasterId {
                provider,
                path: wrapped.path.clone(),
            };
            let cached_master = {
                let mut bank = self.bank();
                self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
                bank.expire(Instant::now());
                if let Some(index) = bank
                    .masters
                    .iter()
                    .position(|e| e.scope == scopes.0 && e.key == id)
                {
                    bank.masters[index].used = bank.next()?;
                    Some((
                        bank.masters[index].value.clone(),
                        bank.masters[index].deadline,
                    ))
                } else {
                    bank.stats.master_load_attempts += 1;
                    None
                }
            };
            let master_born = Instant::now();
            let (master, existing_deadline, install_master) =
                if let Some((master, deadline)) = cached_master {
                    (master, deadline, false)
                } else {
                    #[cfg(test)]
                    {
                        let gate = self.load_gate.lock().unwrap().clone();
                        if let Some(gate) = gate {
                            self.operation()
                                .blocking(move || {
                                    gate.block();
                                    Ok(())
                                })
                                .await?;
                        }
                    }
                    let opened = self.providers[provider]
                        .open(&wrapped.path, self.operation())
                        .await;
                    {
                        let mut bank = self.bank();
                        if opened.is_ok() {
                            bank.stats.master_loads += 1;
                        }
                        self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
                    }
                    let master = match opened {
                        Ok(value) => value,
                        Err(error) => {
                            failure = error;
                            continue;
                        }
                    };
                    let expires = deadline(scopes.0, master_born)?;
                    if expires.is_some_and(|at| Instant::now() >= at) {
                        return Err(Error::AcquisitionExpired);
                    }
                    (master, expires, true)
                };
            self.bank().stats.unwrap_attempts += 1;
            let born = Instant::now();
            let root = master.unwrap(wrapped, self.operation()).await;
            {
                let mut bank = self.bank();
                self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
                if root.is_ok() {
                    bank.stats.unwraps += 1;
                }
            }
            let root = match root {
                Ok(value) => value,
                Err(error) => {
                    failure = error;
                    continue;
                }
            };
            if existing_deadline.is_some_and(|at| Instant::now() >= at) {
                return Err(Error::AcquisitionExpired);
            }
            #[cfg(test)]
            let audit = self.audit.clone();
            let retain_root = self.bank().enclaves;
            let (cell, output) = self
                .operation()
                .blocking(move || {
                    let mut cell = Cell::derive(
                        root.as_bytes(),
                        #[cfg(test)]
                        &audit,
                    )?;
                    if retain_root {
                        cell.root = Some(root);
                    }
                    let cell: Arc<Cell> = cell.into();
                    let output = input.apply(&cell);
                    Ok((cell, output))
                })
                .await?;
            let mut bank = self.bank();
            return self.finish_load(
                &mut bank,
                token,
                key,
                output,
                scopes,
                cell,
                born,
                install_master.then_some((id, master, master_born)),
                reply,
            );
        }
        Err(failure)
    }
    #[allow(clippy::too_many_arguments)]
    fn finish_load(
        &self,
        bank: &mut Bank,
        token: &Token,
        key: &ColumnKey,
        output: Result<Output>,
        scopes: (Scope, Scope),
        cell: Arc<Cell>,
        born: Instant,
        master: Option<(MasterId, Arc<dyn MasterKey>, Instant)>,
        reply: &oneshot::Sender<Result<Output>>,
    ) -> Result<Output> {
        let now = Instant::now();
        let expires = deadline(scopes.1, born)?;
        if expires.is_some_and(|d| now >= d)
            || master.as_ref().is_some_and(|(_, _, born)| {
                deadline(scopes.0, *born).is_ok_and(|d| d.is_some_and(|d| now >= d))
            })
        {
            return Err(Error::AcquisitionExpired);
        }
        // Failed value authentication never returns plaintext. A valid key can
        // still be reused after a corrupted value, so insertion is independent.
        self.check_loading(bank, token, scopes, reply.is_closed())?;
        let now = Instant::now();
        if expires.is_some_and(|d| now >= d)
            || master.as_ref().is_some_and(|(_, _, born)| {
                deadline(scopes.0, *born).is_ok_and(|d| d.is_some_and(|d| now >= d))
            })
        {
            return Err(Error::AcquisitionExpired);
        }
        if let Some((id, value, born)) = master {
            let used = bank.next()?;
            let evicted = insert(
                &mut bank.masters,
                Entry {
                    scope: scopes.0,
                    key: id,
                    value,
                    deadline: deadline(scopes.0, born)?,
                    used,
                },
                token.policies.master_capacity,
            );
            bank.stats.evictions += u64::from(evicted);
        }
        let used = bank.next()?;
        let evicted = insert(
            &mut bank.cells,
            Entry {
                scope: scopes.1,
                key: key.clone(),
                value: cell,
                deadline: expires,
                used,
            },
            token.policies.column_capacity,
        );
        bank.stats.evictions += u64::from(evicted);
        self.changed.notify_one();
        output.map(|value| value.with_deadline(expires))
    }
}
enum Input {
    Encrypt(Secret, bool),
    Decrypt(Vec<u8>),
    Release {
        signatures: Vec<(super::WrappedKey, Vec<u8>)>,
        scopes: (Scope, Scope),
    },
}
enum Output {
    Cipher(Vec<u8>),
    Plain(Plaintext),
    Root(Plaintext, Option<Instant>),
}
impl Output {
    fn with_deadline(self, expires: Option<Instant>) -> Self {
        match self {
            Self::Root(value, _) => Self::Root(value, expires),
            other => other,
        }
    }
}
impl Input {
    fn apply(&self, cell: &Cell) -> Result<Output> {
        match self {
            Self::Encrypt(secret, random) => {
                cell.encrypt(&secret.bytes, *random).map(Output::Cipher)
            }
            Self::Decrypt(bytes) => cell.decrypt(bytes).map(Output::Plain),
            Self::Release { .. } => {
                Plaintext::copy(cell.root.as_ref().ok_or(Error::InvalidPolicy)?.as_bytes())
                    .map(|value| Output::Root(value, None))
            }
        }
    }
}

/// One owner. Its Drop revokes even while exchange guards/workers still exist.
pub struct KeySession {
    inner: Arc<Inner>,
}
/// The driver never owns a key handle or keeps the session owner alive.
pub(crate) struct LifecycleLink {
    inner: std::sync::Weak<Inner>,
    bootstrap_reset: std::sync::atomic::AtomicBool,
}
impl LifecycleLink {
    pub(crate) fn alive(&self) -> bool {
        self.inner
            .upgrade()
            .is_some_and(|inner| !inner.bank().stats.closed)
    }
    pub(crate) fn revoke(&self) {
        if let Some(inner) = self.inner.upgrade() {
            inner.revoke();
        }
    }
    pub(crate) fn transaction(&self, descriptor: u64) -> Result<()> {
        if descriptor == 0 {
            return Ok(());
        }
        if let Some(inner) = self.inner.upgrade() {
            let mut bank = inner.bank();
            if bank.stats.closed {
                return Ok(());
            }
            bank.transaction_end();
            bank.transaction_sequence = bank
                .transaction_sequence
                .checked_add(1)
                .ok_or(Error::Closed)?;
            bank.transaction = Some(bank.transaction_sequence);
            drop(bank);
            inner.revoked.notify_waiters();
        }
        Ok(())
    }
    pub(crate) fn observe(&self, record: &crate::Record) -> Result<()> {
        use crate::tokens::EnvironmentChange;
        let Some(inner) = self.inner.upgrade() else {
            return Ok(());
        };
        match record {
            crate::Record::Environment(EnvironmentChange::Bytes { kind: 8, new, .. })
                if new.len() == 8 =>
            {
                self.transaction(u64::from_le_bytes(new.as_slice().try_into().unwrap()))?;
            }
            crate::Record::Environment(EnvironmentChange::Bytes {
                kind: 9 | 10 | 17, ..
            }) => inner.bank().transaction_end(),
            crate::Record::Environment(EnvironmentChange::Bytes { kind: 18, .. }) => {
                if self.bootstrap_reset.swap(false, Ordering::AcqRel) {
                    // This owner was created AFTER borrower rotation. Erase
                    // pre-ACK entries, but do not retire the new lease itself.
                    inner.bank().clear();
                } else {
                    inner.revoke();
                }
            }
            crate::Record::Environment(EnvironmentChange::Text { kind: 1, .. })
            | crate::Record::Environment(EnvironmentChange::Bytes { kind: 7, .. }) => {
                let mut bank = inner.bank();
                bank.clear();
                bank.guards.clear();
                if let Some(next) = bank.context.checked_add(1) {
                    bank.context = next;
                } else {
                    bank.stats.closed = true;
                }
            }
            _ => {}
        }
        inner.changed.notify_one();
        inner.revoked.notify_waiters();
        Ok(())
    }
    pub(crate) fn expect_reuse_reset(&self, pending: bool) {
        self.bootstrap_reset.store(pending, Ordering::Release);
    }
}
impl KeySession {
    pub(super) fn forget_enclave(&self) {
        self.inner.bank().enclave = None;
    }
    pub(super) fn enable_enclaves(&self) {
        let mut bank = self.inner.bank();
        bank.clear();
        bank.enclaves = true;
    }
    pub(crate) fn link(&self) -> LifecycleLink {
        LifecycleLink {
            inner: Arc::downgrade(&self.inner),
            bootstrap_reset: std::sync::atomic::AtomicBool::new(false),
        }
    }
    /// Requires a running Tokio runtime. Opens no key file until first use.
    pub fn new(mut providers: Vec<LocalKeyStore>, policies: Policies) -> Result<Self> {
        #[cfg(test)]
        let audit = Some(Arc::new(Mutex::new(Vec::new())));
        #[cfg(test)]
        for provider in &mut providers {
            provider.audit.clone_from(&audit);
        }
        Self::build(
            providers
                .drain(..)
                .map(|p| Arc::new(p) as Arc<dyn KeyProvider>)
                .collect(),
            policies,
            Duration::from_secs(30),
            #[cfg(test)]
            audit,
        )
    }
    /// A finite total acquisition budget includes queueing, open and unwrap.
    /// Provider SDK retries consume this same budget. Constructors open no keys.
    pub fn with_providers(
        providers: Vec<Arc<dyn KeyProvider>>,
        policies: Policies,
        provider_timeout: Duration,
    ) -> Result<Self> {
        Self::build(
            providers,
            policies,
            provider_timeout,
            #[cfg(test)]
            Some(Arc::new(Mutex::new(Vec::new()))),
        )
    }
    fn build(
        providers: Vec<Arc<dyn KeyProvider>>,
        policies: Policies,
        provider_timeout: Duration,
        #[cfg(test)] audit: Option<super::secret::Audit>,
    ) -> Result<Self> {
        policies.validate()?;
        if tokio::runtime::Handle::try_current().is_err()
            || provider_timeout.is_zero()
            || Instant::now().checked_add(provider_timeout).is_none()
            || providers.is_empty()
            || providers
                .iter()
                .any(|p| p.name().is_empty() || p.name().len() > 255)
            || providers
                .iter()
                .map(|p| p.name().to_uppercase())
                .collect::<BTreeSet<_>>()
                .len()
                != providers.len()
        {
            return Err(Error::InvalidPolicy);
        }
        let inner = Arc::new(Inner {
            bank: Mutex::new(Bank {
                policies,
                context: 0,
                sequence: 0,
                transaction: None,
                transaction_sequence: 0,
                guards: BTreeSet::new(),
                masters: Vec::new(),
                cells: Vec::new(),
                stats: Statistics::default(),
                enclaves: false,
                enclave: None,
            }),
            providers,
            gate: Arc::new(AsyncMutex::new(())),
            changed: Arc::new(Notify::new()),
            completed: Arc::new(Notify::new()),
            pending: Arc::new(AtomicUsize::new(0)),
            revoked: Notify::new(),
            provider_timeout,
            #[cfg(test)]
            audit,
            #[cfg(test)]
            load_gate: Mutex::new(None),
        });
        let weak = Arc::downgrade(&inner);
        struct TimerAuthority(std::sync::Weak<Inner>);
        impl Drop for TimerAuthority {
            fn drop(&mut self) {
                if let Some(inner) = self.0.upgrade() {
                    inner.revoke();
                }
            }
        }
        // Captured before spawn, so even a never-polled/aborted timer revokes.
        let authority = TimerAuthority(weak.clone());
        let changed = inner.changed.clone();
        tokio::spawn(async move {
            let _authority = authority;
            loop {
                let next = {
                    let Some(inner) = weak.upgrade() else {
                        break;
                    };
                    let mut bank = inner.bank();
                    if bank.stats.closed {
                        break;
                    }
                    bank.expire(Instant::now());
                    bank.masters
                        .iter()
                        .filter_map(|e| e.deadline)
                        .chain(bank.cells.iter().filter_map(|e| e.deadline))
                        .min()
                };
                match next {
                    Some(at) => {
                        tokio::select! { _ = tokio::time::sleep_until(at) => {}, _ = changed.notified() => {} }
                    }
                    None => changed.notified().await,
                }
            }
        });
        Ok(Self { inner })
    }
    pub fn exchange(&self) -> Result<KeyExchange> {
        let policies = self.inner.bank().policies;
        self.exchange_with(policies)
    }
    /// An override is isolated from entries retained under broader policies.
    pub fn exchange_with(&self, policies: Policies) -> Result<KeyExchange> {
        policies.validate()?;
        let mut bank = self.inner.bank();
        if bank.stats.closed {
            return Err(Error::Closed);
        }
        if policies.master_capacity != bank.policies.master_capacity
            || policies.column_capacity != bank.policies.column_capacity
        {
            return Err(Error::InvalidPolicy);
        }
        let token = Token {
            id: bank.next()?,
            context: bank.context,
            transaction: bank.transaction,
            policies,
        };
        bank.guards.insert(token.id);
        Ok(KeyExchange {
            inner: self.inner.clone(),
            token,
        })
    }
    /// Call for an actual outer begin announcement, including a chained begin.
    pub fn transaction_begin(&self, server_descriptor: u64) -> Result<()> {
        if server_descriptor == 0 {
            return Err(Error::InvalidMetadata);
        }
        let mut bank = self.inner.bank();
        if bank.stats.closed {
            return Err(Error::Closed);
        }
        bank.transaction_end();
        bank.transaction_sequence = bank
            .transaction_sequence
            .checked_add(1)
            .ok_or(Error::Closed)?;
        bank.transaction = Some(bank.transaction_sequence);
        self.inner.changed.notify_one();
        self.inner.revoked.notify_waiters();
        Ok(())
    }
    /// Savepoint rollback and inner commit must not call this method.
    pub fn transaction_end(&self) {
        self.inner.bank().transaction_end();
        self.inner.changed.notify_one();
        self.inner.revoked.notify_waiters();
    }
    /// Advance context after provider/security/database changes. Old guards fail.
    pub fn invalidate(&self) {
        let mut bank = self.inner.bank();
        bank.clear();
        bank.guards.clear();
        if let Some(next) = bank.context.checked_add(1) {
            bank.context = next;
        } else {
            bank.stats.closed = true;
        }
        self.inner.changed.notify_one();
        self.inner.revoked.notify_waiters();
    }
    pub fn revoke(&self, _reason: Revocation) {
        self.inner.revoke();
    }
    pub fn set_policies(&mut self, policies: Policies) -> Result<()> {
        policies.validate()?;
        let mut bank = self.inner.bank();
        if bank.stats.closed {
            return Err(Error::Closed);
        }
        if !bank.guards.is_empty() {
            return Err(Error::Busy);
        }
        bank.clear();
        bank.policies = policies;
        bank.context = bank.context.checked_add(1).ok_or(Error::Closed)?;
        self.inner.changed.notify_one();
        self.inner.revoked.notify_waiters();
        Ok(())
    }
    pub fn statistics(&self) -> Statistics {
        let bank = self.inner.bank();
        Statistics {
            live_masters: bank.masters.len(),
            live_columns: bank.cells.len(),
            pending: self.inner.pending.load(Ordering::Acquire),
            ..bank.stats
        }
    }
    /// Revoke first, then wait for every tracked blocking operation to destroy
    /// its local secret handles. Cannot interrupt an OS file read already running.
    pub async fn close(self) {
        self.inner.revoke();
        loop {
            let notified = self.inner.completed.notified();
            if self.inner.pending.load(Ordering::Acquire) == 0 {
                break;
            }
            notified.await;
        }
    }
}
impl Drop for KeySession {
    fn drop(&mut self) {
        self.inner.revoke();
    }
}
impl fmt::Debug for KeySession {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeySession")
            .field("statistics", &self.statistics())
            .finish_non_exhaustive()
    }
}

/// Non-cloneable authority for one application exchange, not a key handle.
pub struct KeyExchange {
    inner: Arc<Inner>,
    token: Token,
}
impl KeyExchange {
    pub(super) fn has_enclave(&self) -> Result<bool> {
        let bank = self.inner.bank();
        bank.check(&self.token)?;
        Ok(bank.enclave.is_some())
    }
    pub(super) async fn establish_enclave(
        &self,
        attestation: super::enclave::Attestation,
        info: Vec<u8>,
    ) -> Result<()> {
        self.inner.bank().check(&self.token)?;
        let session = self
            .inner
            .operation()
            .blocking(move || attestation.establish(&info))
            .await?;
        let mut bank = self.inner.bank();
        bank.check(&self.token)?;
        if !bank.enclaves {
            return Err(Error::InvalidPolicy);
        }
        // Another channel may have established while this describe was in
        // flight. Keep the accepted counter and discard this candidate.
        if bank.enclave.is_none() {
            bank.enclave = Some(Arc::new(Mutex::new(session)));
        }
        Ok(())
    }
    pub(super) async fn enclave_package(
        &self,
        statement: &str,
        keys: &[super::context::EnclaveColumn],
    ) -> Result<Vec<u8>> {
        let (session, scopes) = {
            let bank = self.inner.bank();
            bank.check(&self.token)?;
            (
                bank.enclave.clone().ok_or(Error::InvalidMetadata)?,
                bank.scopes(&self.token),
            )
        };
        let mut released = Vec::with_capacity(keys.len());
        let mut expires: Option<Instant> = None;
        for needed in keys {
            let Output::Root(root, deadline) = self
                .operate(
                    &needed.key,
                    Input::Release {
                        signatures: needed.signatures.clone(),
                        scopes,
                    },
                )
                .await?
            else {
                unreachable!()
            };
            if let Some(at) = deadline {
                expires = Some(expires.map_or(at, |previous| previous.min(at)));
            }
            released.push(super::enclave::ReleasedKey {
                database_id: needed.key.database_id,
                metadata_version: needed.key.metadata_version,
                key_id: needed.key.key_id,
                root,
            });
        }
        let statement = statement.to_owned();
        let expected = session.clone();
        let package = self
            .inner
            .operation()
            .blocking(move || {
                session
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .package(&statement, &released)
            })
            .await?;
        let mut bank = self.inner.bank();
        self.inner
            .check_loading(&mut bank, &self.token, scopes, false)?;
        if expires.is_some_and(|at| Instant::now() >= at) {
            return Err(Error::AcquisitionExpired);
        }
        if !bank
            .enclave
            .as_ref()
            .is_some_and(|session| Arc::ptr_eq(session, &expected))
        {
            return Err(Error::Expired);
        }
        bank.stats.enclave_packages += 1;
        Ok(package)
    }
    pub async fn encrypt(
        &self,
        key: &ColumnKey,
        normalized_plaintext: &[u8],
        randomized: bool,
    ) -> Result<Vec<u8>> {
        if normalized_plaintext.len() > MAX_VALUE {
            return Err(Error::ValueTooLarge);
        }
        let input = Input::Encrypt(Secret::copy(normalized_plaintext), randomized);
        match self.operate(key, input).await? {
            Output::Cipher(bytes) => Ok(bytes),
            _ => unreachable!(),
        }
    }
    pub async fn decrypt(&self, key: &ColumnKey, ciphertext: &[u8]) -> Result<Plaintext> {
        if ciphertext.len() > MAX_VALUE + 65 {
            return Err(Error::ValueTooLarge);
        }
        if ciphertext.len() < 65
            || ciphertext[0] != 1
            || !(ciphertext.len() - 49).is_multiple_of(16)
        {
            return Err(Error::InvalidCiphertext);
        }
        match self
            .operate(key, Input::Decrypt(ciphertext.to_vec()))
            .await?
        {
            Output::Plain(value) => Ok(value),
            _ => unreachable!(),
        }
    }
    async fn operate(&self, key: &ColumnKey, input: Input) -> Result<Output> {
        key.validate()?;
        let deadline = Instant::now()
            .checked_add(self.inner.provider_timeout)
            .ok_or(Error::InvalidPolicy)?;
        let (send, receive) = oneshot::channel();
        let inner = self.inner.clone();
        let token = self.token.clone();
        let key = key.clone();
        let cancel = Arc::new(Notify::new());
        struct Cancel(Arc<Notify>);
        impl Drop for Cancel {
            fn drop(&mut self) {
                self.0.notify_one();
            }
        }
        let _cancel = Cancel(cancel.clone());
        let scopes = {
            let mut bank = inner.bank();
            bank.check(&token)?;
            let scopes = match &input {
                Input::Release { scopes, .. } => *scopes,
                _ => bank.scopes(&token),
            };
            inner.check_loading(&mut bank, &token, scopes, send.is_closed())?;
            scopes
        };
        let pending = inner.operation().enter();
        tokio::spawn(async move {
            let _pending = pending;
            let revoked = inner.revoked.notified();
            tokio::pin!(revoked);
            revoked.as_mut().enable();
            let result = {
                let load = tokio::time::timeout_at(
                    deadline,
                    inner.load(&token, &key, input, &send, scopes),
                );
                tokio::pin!(load);
                loop {
                    tokio::select! {
                        result=&mut load => break result.unwrap_or(Err(Error::ProviderTimeout)),
                        _=cancel.notified() => { inner.bank().stats.discarded_loads += 1; break Err(Error::Closed); },
                        _=&mut revoked => {
                            let checked=inner.check_loading(&mut inner.bank(),&token,scopes,send.is_closed());
                            if let Err(error)=checked { break Err(error); }
                            revoked.set(inner.revoked.notified()); revoked.as_mut().enable();
                        }
                    }
                }
            };
            let _ = send.send(result);
        });
        receive.await.map_err(|_| Error::Worker)?
    }
}
impl Drop for KeyExchange {
    fn drop(&mut self) {
        let mut bank = self.inner.bank();
        bank.guards.remove(&self.token.id);
        bank.masters
            .retain(|e| e.scope != Scope::Exchange(self.token.id));
        bank.cells
            .retain(|e| e.scope != Scope::Exchange(self.token.id));
        self.inner.changed.notify_one();
        self.inner.revoked.notify_waiters();
    }
}
impl fmt::Debug for KeyExchange {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KeyExchange")
            .field("policies", &self.token.policies)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
