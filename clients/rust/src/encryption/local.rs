use super::{Error, Result, WrappedKey, cell::Cell, secret::Secret};
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{OAEP_SHA1_MGF1SHA1, OaepPrivateDecryptingKey, PrivateDecryptingKey},
    signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
};

/// Fixed provider binding. The source file is read only on a master-key miss.
#[derive(Debug)]
pub struct LocalKeyStore {
    pub(super) name: String,
    root: PathBuf,
}
impl LocalKeyStore {
    pub fn new(name: impl Into<String>, directory: impl AsRef<Path>) -> Result<Self> {
        let name = name.into().to_uppercase();
        if name.is_empty() || name.len() > 255 {
            return Err(Error::InvalidPolicy);
        }
        let root = directory
            .as_ref()
            .canonicalize()
            .map_err(|_| Error::KeyUnavailable)?;
        if !root.is_dir() {
            return Err(Error::KeyUnavailable);
        }
        Ok(Self { name, root })
    }
    pub(super) fn load(
        &self,
        path: &str,
        #[cfg(test)] audit: &Option<super::secret::Audit>,
    ) -> Result<Master> {
        let source = self
            .root
            .join(path)
            .canonicalize()
            .map_err(|_| Error::KeyUnavailable)?;
        if !source.starts_with(&self.root) || !source.is_file() {
            return Err(Error::KeyUnavailable);
        }
        let mut file = File::open(source)
            .map_err(|_| Error::KeyUnavailable)?
            .take(65_537);
        let mut pem = Secret::new(65_537);
        #[cfg(test)]
        {
            pem = pem.audited(audit, "pem");
        }
        let mut length = 0;
        while length < pem.bytes.len() {
            let n = file
                .read(&mut pem.bytes[length..])
                .map_err(|_| Error::KeyUnavailable)?;
            if n == 0 {
                break;
            }
            length += n;
        }
        if length > 65_536 {
            return Err(Error::InvalidMasterKey);
        }
        const HEADER: &[u8] = b"-----BEGIN PRIVATE KEY-----";
        const FOOTER: &[u8] = b"-----END PRIVATE KEY-----";
        let data = pem.bytes[..length].trim_ascii();
        let data = data
            .strip_prefix(HEADER)
            .and_then(|b| b.strip_suffix(FOOTER))
            .ok_or(Error::InvalidMasterKey)?;
        let mut encoded = Secret::new(data.len());
        #[cfg(test)]
        {
            encoded = encoded.audited(audit, "base64");
        }
        let mut n = 0;
        for &b in data.iter().filter(|b| !b.is_ascii_whitespace()) {
            encoded.bytes[n] = b;
            n += 1;
        }
        let mut der = Secret::new(n);
        #[cfg(test)]
        {
            der = der.audited(audit, "der");
        }
        let size = STANDARD
            .decode_slice(&encoded.bytes[..n], &mut der.bytes)
            .map_err(|_| Error::InvalidMasterKey)?;
        let key = PrivateDecryptingKey::from_pkcs8(&der.bytes[..size])
            .map_err(|_| Error::InvalidMasterKey)?;
        let public = key
            .public_key()
            .as_der()
            .map_err(|_| Error::InvalidMasterKey)?
            .as_ref()
            .to_vec();
        let private = OaepPrivateDecryptingKey::new(key).map_err(|_| Error::InvalidMasterKey)?;
        Ok(Master { private, public })
    }
}
pub(super) struct Master {
    private: OaepPrivateDecryptingKey,
    public: Vec<u8>,
}
impl Master {
    pub(super) fn unwrap(
        &self,
        wrapped: &WrappedKey,
        #[cfg(test)] audit: &Option<super::secret::Audit>,
    ) -> Result<Box<Cell>> {
        let bytes = &wrapped.encrypted;
        if !wrapped.algorithm.eq_ignore_ascii_case("RSA_OAEP") || bytes.len() < 5 || bytes[0] != 1 {
            return Err(Error::InvalidMetadata);
        }
        let path_size = usize::from(u16::from_le_bytes([bytes[1], bytes[2]]));
        let cipher_size = usize::from(u16::from_le_bytes([bytes[3], bytes[4]]));
        let start = 5 + path_size;
        let end = start + cipher_size;
        if path_size % 2 != 0
            || cipher_size != self.private.key_size_bytes()
            || bytes.len() != end + cipher_size
        {
            return Err(Error::InvalidMetadata);
        }
        // The signed embedded path is evidence, not filesystem authority. The
        // configured provider path above chooses the actual key source.
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.public)
            .verify(&bytes[..end], &bytes[end..])
            .map_err(|_| Error::Authentication)?;
        let mut root = Secret::new(self.private.min_output_size());
        #[cfg(test)]
        {
            root = root.audited(audit, "root");
        }
        let decrypted = self
            .private
            .decrypt(
                &OAEP_SHA1_MGF1SHA1,
                &bytes[start..end],
                &mut root.bytes,
                None,
            )
            .map_err(|_| Error::Authentication)?;
        Cell::derive(
            decrypted,
            #[cfg(test)]
            audit,
        )
    }
}
