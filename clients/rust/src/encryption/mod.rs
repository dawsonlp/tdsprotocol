//! Always Encrypted SQL, opaque key providers and key lifetimes (D-66, design O).
//!
//! [`EncryptedConnection`] composes raw protocol authority with the optional key
//! service. [`KeySession`] and [`KeyExchange`] remain available for explicitly
//! normalized byte operations. Use `Connection::encrypted` to bind transaction,
//! pool/reset/recovery/close events rather than supplying boundaries manually.

mod cell;
#[cfg(feature = "certificate-store")]
pub mod certstore;
mod context;
mod enclave;
pub use context::{EncryptedChannel, EncryptedConnection, EncryptedResponse};
#[cfg(feature = "azure-keyvault")]
pub mod keyvault;
mod local;
pub mod normalize;
mod policy;
mod provider;
mod secret;
pub use local::LocalKeyStore;
pub(crate) use policy::LifecycleLink;
pub use policy::{KeyExchange, KeySession, Policies, Policy, Revocation, Statistics};
pub use provider::{KeyFuture, KeyOperation, KeyProvider, MasterKey, master_key_metadata};
pub use secret::Plaintext;
use std::fmt;

/// Errors contain categories, never provider error strings or secret buffers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Error {
    Provider(ProviderFailure),
    InvalidPolicy,
    InvalidValue,
    InvalidMetadata,
    InvalidMasterKey,
    KeyUnavailable,
    Authentication,
    InvalidCiphertext,
    ValueTooLarge,
    Closed,
    Expired,
    AcquisitionExpired,
    Busy,
    Worker,
    ProviderTimeout,
    UnsupportedPlatform,
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Provider(_) => "key provider operation failed",
            Self::InvalidValue => {
                "value does not match SQL encryption normalization or declaration"
            }
            Self::InvalidPolicy => "invalid encryption policy or capacity",
            Self::InvalidMetadata => "invalid or unsupported wrapped-key metadata",
            Self::InvalidMasterKey => "invalid PKCS#8 RSA master key",
            Self::KeyUnavailable => "configured master key is unavailable",
            Self::Authentication => "encrypted value or wrapped key did not authenticate",
            Self::InvalidCiphertext => "invalid encrypted value layout or padding",
            Self::ValueTooLarge => "encryption value exceeds the 16 MiB operation limit",
            Self::Closed => "encryption session or exchange is closed",
            Self::Expired => "encryption authority changed during the operation",
            Self::AcquisitionExpired => "key acquisition exceeded the configured maximum age",
            Self::Busy => "encryption owner is busy or already has an attached key service",
            Self::Worker => "encryption provider worker did not complete",
            Self::ProviderTimeout => "key provider exceeded its acquisition deadline",
            Self::UnsupportedPlatform => "key provider is unavailable on this platform",
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

/// Explicit protected diagnostics are separate from normal error formatting.
#[derive(Clone)]
pub struct ProviderFailure(std::sync::Arc<dyn std::error::Error + Send + Sync>);
impl ProviderFailure {
    pub fn new(cause: impl std::error::Error + Send + Sync + 'static) -> Self {
        Self(std::sync::Arc::new(cause))
    }
    pub fn protected_cause(&self) -> &(dyn std::error::Error + Send + Sync + 'static) {
        self.0.as_ref()
    }
}
impl PartialEq for ProviderFailure {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for ProviderFailure {}
impl fmt::Debug for ProviderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProviderFailure([protected cause])")
    }
}

pub use crate::types::crypto::{ColumnKey, WrappedKey};
impl ColumnKey {
    fn validate(&self) -> Result<()> {
        if self.values.is_empty()
            || self.values.len() > 16
            || self.values.iter().any(|v| {
                v.provider.len() > 255
                    || v.path.len() > 65535
                    || v.algorithm.len() > 32
                    || v.encrypted.len() > 132_096
            })
        {
            return Err(Error::InvalidMetadata);
        }
        Ok(())
    }
}
