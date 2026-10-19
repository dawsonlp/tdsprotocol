//! Opaque key capabilities. A vault reference is never a local private key.
//! The per-operation context owns eventual cleanup of blocking provider calls.
use super::{Error, Plaintext, Result, WrappedKey};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};
use tokio::sync::{Notify, oneshot};

pub type KeyFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 'a>>;

pub trait KeyProvider: Send + Sync {
    fn name(&self) -> &str;
    fn open<'a>(
        &'a self,
        path: &'a str,
        operation: KeyOperation,
    ) -> KeyFuture<'a, Arc<dyn MasterKey>>;
}
pub trait MasterKey: Send + Sync {
    fn wrap<'a>(
        &'a self,
        column_key: &'a Plaintext,
        operation: KeyOperation,
    ) -> KeyFuture<'a, Vec<u8>>;
    fn unwrap<'a>(
        &'a self,
        evidence: &'a WrappedKey,
        operation: KeyOperation,
    ) -> KeyFuture<'a, Plaintext>;
    fn sign_metadata(&self, enclaves: bool, operation: KeyOperation) -> KeyFuture<'_, Vec<u8>>;
    fn verify_metadata<'a>(
        &'a self,
        enclaves: bool,
        signature: &'a [u8],
        operation: KeyOperation,
    ) -> KeyFuture<'a, bool>;
}

/// Built-in local/native providers use this context instead of detaching an
/// untracked worker. Cancellation drops the receiver; the job still owns its
/// handles/buffers until completion, and a rejected result is destroyed there.
#[derive(Clone, Default)]
pub struct KeyOperation {
    pub(super) pending: Arc<AtomicUsize>,
    pub(super) completed: Arc<Notify>,
}
pub(super) struct Pending(KeyOperation);
impl Drop for Pending {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::AcqRel);
        self.0.completed.notify_waiters();
        self.0.completed.notify_one();
    }
}
impl KeyOperation {
    /// Number of blocking jobs still owning this operation's resources.
    pub fn pending(&self) -> usize {
        self.pending.load(Ordering::Acquire)
    }
    /// Await eventual cleanup after canceling a standalone provider future.
    /// Do not start new work on this context concurrently with draining it.
    pub async fn drain(&self) {
        loop {
            let completed = self.completed.notified();
            tokio::pin!(completed);
            completed.as_mut().enable();
            if self.pending() == 0 {
                return;
            }
            completed.await;
        }
    }
    pub(super) fn enter(&self) -> Pending {
        self.pending.fetch_add(1, Ordering::AcqRel);
        Pending(self.clone())
    }
    pub async fn blocking<T: Send + 'static>(
        &self,
        work: impl FnOnce() -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let pending = self.enter();
        let (send, receive) = oneshot::channel();
        tokio::task::spawn_blocking(move || {
            let _pending = pending;
            let _ = send.send(work());
        });
        receive.await.map_err(|_| Error::Worker)?
    }
}

/// Python's signed master-key authorization input. Case conversion is Unicode
/// lowercase, followed by UTF-16LE; the boolean is the literal true/false word.
pub fn master_key_metadata(provider: &str, path: &str, enclaves: bool) -> Vec<u8> {
    format!(
        "{provider}{path}{}",
        if enclaves { "true" } else { "false" }
    )
    .to_lowercase()
    .encode_utf16()
    .flat_map(u16::to_le_bytes)
    .collect()
}
