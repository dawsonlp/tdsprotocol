//! Local-key Always Encrypted SQL and key lifetimes (D-66, design O).
//!
//! [`EncryptedConnection`] composes raw protocol authority with the optional key
//! service. [`KeySession`] and [`KeyExchange`] remain available for explicitly
//! normalized byte operations. Use `Connection::encrypted` to bind transaction,
//! pool/reset/recovery/close events rather than supplying boundaries manually.

mod cell;
mod context;
pub use context::{EncryptedChannel, EncryptedConnection, EncryptedResponse};
mod local;
pub mod normalize;
mod policy;
mod secret;
pub use local::LocalKeyStore;
pub(crate) use policy::LifecycleLink;
pub use policy::{KeyExchange, KeySession, Policies, Policy, Revocation, Statistics};
pub use secret::Plaintext;
use std::fmt;

/// Errors contain categories, never provider error strings or secret buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
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
}
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
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
        })
    }
}
impl std::error::Error for Error {}
pub type Result<T> = std::result::Result<T, Error>;

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
