//! Always Encrypted wire vocabulary. Contains wrapped ciphertext, never keys.
use super::*;
use std::fmt;
/// Complete ciphertext metadata, not a usable plaintext key.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct WrappedKey {
    pub provider: String,
    pub path: String,
    pub algorithm: String,
    pub encrypted: Vec<u8>,
}
impl fmt::Debug for WrappedKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WrappedKey")
            .field("provider", &self.provider)
            .field("encrypted_bytes", &self.encrypted.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct ColumnKey {
    pub database_id: u32,
    pub key_id: u32,
    pub version: u32,
    pub metadata_version: [u8; 8],
    pub values: Vec<WrappedKey>,
}
impl fmt::Debug for ColumnKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ColumnKey")
            .field("database_id", &self.database_id)
            .field("key_id", &self.key_id)
            .field("wrapped_values", &self.values.len())
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CryptoMetadata {
    pub base: TypeInfo,
    pub user_type: u32,
    pub algorithm: u8,
    pub algorithm_name: Option<crate::SqlText>,
    pub encryption_type: u8,
    pub normalization: u8,
    /// Output parameters obtain their key from the request's parameter plan.
    pub key: Option<ColumnKey>,
}
impl CryptoMetadata {
    pub(crate) fn read(r: &mut Reader<'_>, key: Option<ColumnKey>) -> Result<Self> {
        let user_type = r.field("base user type", |r| r.u32())?;
        let base = r.field("base type", TypeInfo::read)?;
        let algorithm = r.field("encryption algorithm", |r| r.u8())?;
        let algorithm_name = if algorithm == 0 {
            let n = usize::from(r.u8()?);
            Some(crate::requests::decode::text(r, n)?)
        } else {
            None
        };
        let encryption_type = r.field("encryption type", |r| r.u8())?;
        let normalization = r.field("normalization version", |r| r.u8())?;
        if ![1, 2].contains(&encryption_type) {
            return Err(crate::Error::malformed(r.offset, "encryption type"));
        }
        Ok(Self {
            base,
            user_type,
            algorithm,
            algorithm_name,
            encryption_type,
            normalization,
            key,
        })
    }
}
pub(crate) fn key_table(r: &mut Reader<'_>) -> Result<Vec<ColumnKey>> {
    let count = usize::from(r.field("key count", |r| r.u16())?);
    if count > 4096 {
        return Err(crate::Error::new(crate::ErrorKind::Limit(
            "column key count",
        )));
    }
    let mut keys = Vec::with_capacity(count);
    for i in 0..count {
        keys.push(r.indexed("column key", i, |r| {
            let database_id = r.u32()?;
            let key_id = r.u32()?;
            let version = r.u32()?;
            let metadata_version = r.take(8)?.try_into().expect("eight bytes");
            let count = usize::from(r.u8()?);
            if count > 16 {
                return Err(crate::Error::malformed(r.offset, "wrapped key count"));
            }
            let mut values = Vec::with_capacity(count);
            for _ in 0..count {
                let n = usize::from(r.u16()?);
                let encrypted = r.take(n)?.to_vec();
                let n = usize::from(r.u8()?);
                let provider = string(r, n)?;
                let n = usize::from(r.u16()?);
                let path = string(r, n)?;
                let n = usize::from(r.u8()?);
                let algorithm = string(r, n)?;
                values.push(WrappedKey {
                    provider,
                    path,
                    algorithm,
                    encrypted,
                });
            }
            Ok(ColumnKey {
                database_id,
                key_id,
                version,
                metadata_version,
                values,
            })
        })?);
    }
    Ok(keys)
}
fn string(r: &mut Reader<'_>, n: usize) -> Result<String> {
    crate::requests::decode::text(r, n)?
        .to_string()
        .map_err(|_| crate::Error::malformed(r.offset, "key metadata UTF-16"))
}

pub(crate) fn write_key_table(keys: &[ColumnKey], out: &mut Vec<u8>) -> Result<()> {
    fn length(n: usize, out: &mut Vec<u8>) -> Result<()> {
        out.extend(
            u16::try_from(n)
                .map_err(|_| crate::Error::new(crate::ErrorKind::Parameter("key metadata length")))?
                .to_le_bytes(),
        );
        Ok(())
    }
    length(keys.len(), out)?;
    for key in keys {
        out.extend(key.database_id.to_le_bytes());
        out.extend(key.key_id.to_le_bytes());
        out.extend(key.version.to_le_bytes());
        out.extend(key.metadata_version);
        // Client bulk metadata sends identities only, never wrapped values
        // (the server already owns them); this is SqlClient's wire contract.
        out.push(0);
    }
    Ok(())
}
impl CryptoMetadata {
    pub(crate) fn write(&self, out: &mut Vec<u8>) -> Result<()> {
        if self.algorithm != 2 || self.normalization != 1 || ![1, 2].contains(&self.encryption_type)
        {
            return Err(crate::Error::new(crate::ErrorKind::Parameter(
                "unsupported column encryption metadata",
            )));
        }
        out.extend(self.user_type.to_le_bytes());
        let encoded = self.base.sql_type.encode_parameter(None)?;
        let mut r = Reader::new(&encoded);
        TypeInfo::read_parameter(&mut r)?;
        out.extend_from_slice(&encoded[..r.offset]);
        out.extend([self.algorithm, self.encryption_type, self.normalization]);
        Ok(())
    }
}
