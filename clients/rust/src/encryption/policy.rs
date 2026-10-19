use super::{
    ColumnKey, Error, LocalKeyStore, Plaintext, Result,
    cell::{Cell, MAX_VALUE},
    local::Master,
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
    masters: Vec<Entry<MasterId, Master>>,
    cells: Vec<Entry<ColumnKey, Box<Cell>>>,
    stats: Statistics,
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
    }
    fn transaction_end(&mut self) {
        self.masters
            .retain(|e| !matches!(e.scope, Scope::Transaction(_)));
        self.cells
            .retain(|e| !matches!(e.scope, Scope::Transaction(_)));
        self.transaction = None;
    }
    fn cached(&mut self, token: &Token, key: &ColumnKey, input: &Input) -> Result<Option<Output>> {
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
        input.apply(&self.cells[index].value).map(Some)
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
    providers: Vec<LocalKeyStore>,
    gate: Arc<AsyncMutex<()>>,
    changed: Arc<Notify>,
    completed: Notify,
    pending: AtomicUsize,
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
    fn load(
        &self,
        token: &Token,
        key: &ColumnKey,
        input: &Input,
        reply: &oneshot::Sender<Result<Output>>,
    ) -> Result<Output> {
        let scopes = {
            let bank = self.bank();
            bank.check(token)?;
            bank.scopes(token)
        };
        let mut failure = Error::KeyUnavailable;
        for wrapped in &key.values {
            let Some(provider) = self
                .providers
                .iter()
                .position(|p| p.name == wrapped.provider.to_uppercase())
            else {
                continue;
            };
            let id = MasterId {
                provider,
                path: wrapped.path.clone(),
            };
            let mut bank = self.bank();
            self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
            bank.expire(Instant::now());
            if let Some(index) = bank
                .masters
                .iter()
                .position(|e| e.scope == scopes.0 && e.key == id)
            {
                bank.masters[index].used = bank.next()?;
                bank.stats.unwrap_attempts += 1;
                let born = Instant::now();
                let cell = bank.masters[index].value.unwrap(
                    wrapped,
                    #[cfg(test)]
                    &self.audit,
                );
                match cell {
                    Ok(cell) => {
                        bank.stats.unwraps += 1;
                        let now = Instant::now();
                        if bank.masters[index].deadline.is_some_and(|d| now >= d)
                            || deadline(scopes.1, born)?.is_some_and(|d| now >= d)
                        {
                            bank.expire(now);
                            return Err(Error::AcquisitionExpired);
                        }
                        return self.finish_load(
                            &mut bank, token, key, input, scopes, cell, born, None, reply,
                        );
                    }
                    Err(error) => {
                        failure = error;
                        continue;
                    }
                }
            }
            bank.stats.master_load_attempts += 1;
            drop(bank); // no lock crosses provider I/O
            let master_born = Instant::now();
            #[cfg(test)]
            if let Some(gate) = self.load_gate.lock().unwrap().clone() {
                gate.block();
            }
            let master = self.providers[provider].load(
                &wrapped.path,
                #[cfg(test)]
                &self.audit,
            );
            let mut bank = self.bank();
            if master.is_ok() {
                bank.stats.master_loads += 1;
            }
            self.check_loading(&mut bank, token, scopes, reply.is_closed())?;
            let master = match master {
                Ok(master) => master,
                Err(error) => {
                    failure = error;
                    continue;
                }
            };
            if deadline(scopes.0, master_born)?.is_some_and(|d| Instant::now() >= d) {
                return Err(Error::AcquisitionExpired);
            }
            bank.stats.unwrap_attempts += 1;
            let born = Instant::now();
            match master.unwrap(
                wrapped,
                #[cfg(test)]
                &self.audit,
            ) {
                Ok(cell) => {
                    bank.stats.unwraps += 1;
                    return self.finish_load(
                        &mut bank,
                        token,
                        key,
                        input,
                        scopes,
                        cell,
                        born,
                        Some((id, master, master_born)),
                        reply,
                    );
                }
                Err(error) => {
                    failure = error;
                }
            }
        }
        Err(failure)
    }
    #[allow(clippy::too_many_arguments)]
    fn finish_load(
        &self,
        bank: &mut Bank,
        token: &Token,
        key: &ColumnKey,
        input: &Input,
        scopes: (Scope, Scope),
        cell: Box<Cell>,
        born: Instant,
        master: Option<(MasterId, Master, Instant)>,
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
        let output = input.apply(&cell);
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
        output
    }
}
enum Input {
    Encrypt(Secret, bool),
    Decrypt(Vec<u8>),
}
enum Output {
    Cipher(Vec<u8>),
    Plain(Plaintext),
}
impl Input {
    fn apply(&self, cell: &Cell) -> Result<Output> {
        match self {
            Self::Encrypt(secret, random) => {
                cell.encrypt(&secret.bytes, *random).map(Output::Cipher)
            }
            Self::Decrypt(bytes) => cell.decrypt(bytes).map(Output::Plain),
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
        Ok(())
    }
    pub(crate) fn expect_reuse_reset(&self, pending: bool) {
        self.bootstrap_reset.store(pending, Ordering::Release);
    }
}
impl KeySession {
    pub(crate) fn link(&self) -> LifecycleLink {
        LifecycleLink {
            inner: Arc::downgrade(&self.inner),
            bootstrap_reset: std::sync::atomic::AtomicBool::new(false),
        }
    }
    /// Requires a running Tokio runtime. Opens no key file until first use.
    pub fn new(providers: Vec<LocalKeyStore>, policies: Policies) -> Result<Self> {
        policies.validate()?;
        if tokio::runtime::Handle::try_current().is_err()
            || providers.is_empty()
            || providers
                .iter()
                .map(|p| &p.name)
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
            }),
            providers,
            gate: Arc::new(AsyncMutex::new(())),
            changed: Arc::new(Notify::new()),
            completed: Notify::new(),
            pending: AtomicUsize::new(0),
            #[cfg(test)]
            audit: Some(Arc::new(Mutex::new(Vec::new()))),
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
        Ok(())
    }
    /// Savepoint rollback and inner commit must not call this method.
    pub fn transaction_end(&self) {
        self.inner.bank().transaction_end();
        self.inner.changed.notify_one();
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
        if let Some(output) = self.inner.bank().cached(&self.token, key, &input)? {
            return Ok(output);
        }
        let gate = self.inner.gate.clone().lock_owned().await;
        {
            let mut bank = self.inner.bank();
            if let Some(output) = bank.cached(&self.token, key, &input)? {
                bank.stats.coalesced += 1;
                return Ok(output);
            }
        }
        let (send, receive) = oneshot::channel();
        let inner = self.inner.clone();
        let token = self.token.clone();
        let key = key.clone();
        inner.pending.fetch_add(1, Ordering::AcqRel);
        tokio::task::spawn_blocking(move || {
            struct Pending(Arc<Inner>);
            impl Drop for Pending {
                fn drop(&mut self) {
                    self.0.pending.fetch_sub(1, Ordering::AcqRel);
                    self.0.completed.notify_one();
                }
            }
            let _pending = Pending(inner.clone());
            let _gate = gate;
            let output = inner.load(&token, &key, &input, &send);
            let _ = send.send(output); // closed receiver destroys owned output
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
