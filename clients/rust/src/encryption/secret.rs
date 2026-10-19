use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Stable, fixed-size allocation. No resizing, cloning or byte-bearing Debug.
pub(super) struct Secret {
    pub(super) bytes: Zeroizing<Box<[u8]>>,
    #[cfg(test)]
    pub(super) audit: Option<Audit>,
    #[cfg(test)]
    pub(super) kind: &'static str,
}
#[cfg(test)]
pub(super) type Audit = std::sync::Arc<std::sync::Mutex<Vec<(&'static str, usize, bool)>>>;
impl Secret {
    pub(super) fn new(size: usize) -> Self {
        Self {
            bytes: Zeroizing::new(vec![0; size].into_boxed_slice()),
            #[cfg(test)]
            audit: None,
            #[cfg(test)]
            kind: "temporary",
        }
    }
    pub(super) fn copy(bytes: &[u8]) -> Self {
        let mut secret = Self::new(bytes.len());
        secret.bytes.copy_from_slice(bytes);
        secret
    }
    #[cfg(test)]
    pub(super) fn audited(mut self, audit: &Option<Audit>, kind: &'static str) -> Self {
        self.audit.clone_from(audit);
        self.kind = kind;
        self
    }
}
impl Drop for Secret {
    fn drop(&mut self) {
        self.bytes.as_mut().zeroize();
        #[cfg(test)]
        if let Some(audit) = &self.audit {
            audit.lock().unwrap().push((
                self.kind,
                self.bytes.len(),
                self.bytes.iter().all(|b| *b == 0),
            ));
        }
    }
}
impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret([redacted])")
    }
}

/// Decrypted application bytes. The caller may explicitly copy them; this
/// allocation is erased on Drop. It is not a key or a cloneable key handle.
pub struct Plaintext {
    pub(super) storage: Secret,
    pub(super) length: usize,
}
impl Plaintext {
    /// Copy application-owned bytes into a fixed erasing allocation.
    pub fn copy(bytes: &[u8]) -> super::Result<Self> {
        if bytes.len() > super::cell::MAX_VALUE {
            return Err(super::Error::ValueTooLarge);
        }
        Ok(Self {
            storage: Secret::copy(bytes),
            length: bytes.len(),
        })
    }
    pub fn as_bytes(&self) -> &[u8] {
        &self.storage.bytes[..self.length]
    }
}
impl fmt::Debug for Plaintext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Plaintext([redacted])")
    }
}
