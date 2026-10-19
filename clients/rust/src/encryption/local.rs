use super::{
    Error, KeyFuture, KeyOperation, KeyProvider, MasterKey, Plaintext, Result, WrappedKey,
    master_key_metadata, secret::Secret,
};
use aws_lc_rs::{
    encoding::AsDer,
    rsa::{
        OAEP_SHA1_MGF1SHA1, OaepPrivateDecryptingKey, OaepPublicEncryptingKey, PrivateDecryptingKey,
    },
    signature::{RSA_PKCS1_2048_8192_SHA256, RSA_PKCS1_SHA256, RsaKeyPair, UnparsedPublicKey},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use std::{
    fs::File,
    io::Read,
    path::{Path, PathBuf},
    sync::Arc,
};

/// Fixed provider binding. The source file is read only on a master-key miss.
#[derive(Clone, Debug)]
pub struct LocalKeyStore {
    pub(super) name: String,
    root: PathBuf,
    #[cfg(test)]
    pub(super) audit: Option<super::secret::Audit>,
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
        Ok(Self {
            name,
            root,
            #[cfg(test)]
            audit: None,
        })
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
        let encryptor =
            OaepPublicEncryptingKey::new(key.public_key()).map_err(|_| Error::InvalidMasterKey)?;
        let signer =
            RsaKeyPair::from_pkcs8(&der.bytes[..size]).map_err(|_| Error::InvalidMasterKey)?;
        let private = OaepPrivateDecryptingKey::new(key).map_err(|_| Error::InvalidMasterKey)?;
        Ok(Master {
            material: Arc::new(Material {
                private,
                public,
                encryptor,
                signer,
            }),
            provider: self.name.clone(),
            path: path.to_owned(),
            #[cfg(test)]
            audit: audit.clone(),
        })
    }
}
struct Material {
    private: OaepPrivateDecryptingKey,
    public: Vec<u8>,
    encryptor: OaepPublicEncryptingKey,
    signer: RsaKeyPair,
}
#[derive(Clone)]
pub(super) struct Master {
    material: Arc<Material>,
    provider: String,
    path: String,
    #[cfg(test)]
    audit: Option<super::secret::Audit>,
}
impl Master {
    fn unwrap_root(
        &self,
        wrapped: &WrappedKey,
        #[cfg(test)] audit: &Option<super::secret::Audit>,
    ) -> Result<Plaintext> {
        let bytes = &wrapped.encrypted;
        if wrapped.algorithm.to_uppercase() != "RSA_OAEP" || bytes.len() < 5 || bytes[0] != 1 {
            return Err(Error::InvalidMetadata);
        }
        let path_size = usize::from(u16::from_le_bytes([bytes[1], bytes[2]]));
        let cipher_size = usize::from(u16::from_le_bytes([bytes[3], bytes[4]]));
        let start = 5 + path_size;
        let end = start + cipher_size;
        if path_size % 2 != 0
            || cipher_size != self.material.private.key_size_bytes()
            || bytes.len() != end + cipher_size
        {
            return Err(Error::InvalidMetadata);
        }
        // The signed embedded path is evidence, not filesystem authority. The
        // configured provider path above chooses the actual key source.
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.material.public)
            .verify(&bytes[..end], &bytes[end..])
            .map_err(|_| Error::Authentication)?;
        let mut root = Secret::new(self.material.private.min_output_size());
        #[cfg(test)]
        {
            root = root.audited(audit, "root");
        }
        let decrypted = self
            .material
            .private
            .decrypt(
                &OAEP_SHA1_MGF1SHA1,
                &bytes[start..end],
                &mut root.bytes,
                None,
            )
            .map_err(|_| Error::Authentication)?;
        let length = decrypted.len();
        if length != 32 {
            return Err(Error::InvalidMetadata);
        }
        Ok(Plaintext {
            storage: root,
            length,
        })
    }
}

impl KeyProvider for LocalKeyStore {
    fn name(&self) -> &str {
        &self.name
    }
    fn open<'a>(
        &'a self,
        path: &'a str,
        operation: KeyOperation,
    ) -> KeyFuture<'a, Arc<dyn MasterKey>> {
        let store = self.clone();
        let path = path.to_owned();
        Box::pin(async move {
            operation
                .blocking(move || {
                    store
                        .load(
                            &path,
                            #[cfg(test)]
                            &store.audit,
                        )
                        .map(|master| Arc::new(master) as Arc<dyn MasterKey>)
                })
                .await
        })
    }
}
impl Master {
    fn signature(&self, bytes: &[u8]) -> Result<Vec<u8>> {
        let mut signature = vec![0; self.material.private.key_size_bytes()];
        self.material
            .signer
            .sign(
                &RSA_PKCS1_SHA256,
                &aws_lc_rs::rand::SystemRandom::new(),
                bytes,
                &mut signature,
            )
            .map_err(|_| Error::Authentication)?;
        Ok(signature)
    }
}
impl MasterKey for Master {
    fn wrap<'a>(
        &'a self,
        column_key: &'a Plaintext,
        operation: KeyOperation,
    ) -> KeyFuture<'a, Vec<u8>> {
        let own = self.clone();
        let root = Secret::copy(column_key.as_bytes());
        Box::pin(async move {
            operation
                .blocking(move || {
                    if root.bytes.len() != 32 {
                        return Err(Error::InvalidMetadata);
                    }
                    let mut cipher = vec![0; own.material.encryptor.ciphertext_size()];
                    own.material
                        .encryptor
                        .encrypt(&OAEP_SHA1_MGF1SHA1, &root.bytes, &mut cipher, None)
                        .map_err(|_| Error::Authentication)?;
                    let path: Vec<u8> =
                        own.path.encode_utf16().flat_map(u16::to_le_bytes).collect();
                    let size = u16::try_from(path.len()).map_err(|_| Error::InvalidMetadata)?;
                    let mut body = vec![1];
                    body.extend(size.to_le_bytes());
                    body.extend((cipher.len() as u16).to_le_bytes());
                    body.extend(path);
                    body.extend(cipher);
                    body.extend(own.signature(&body)?);
                    Ok(body)
                })
                .await
        })
    }
    fn unwrap<'a>(
        &'a self,
        evidence: &'a WrappedKey,
        operation: KeyOperation,
    ) -> KeyFuture<'a, Plaintext> {
        let own = self.clone();
        let wrapped = evidence.clone();
        Box::pin(async move {
            operation
                .blocking(move || {
                    own.unwrap_root(
                        &wrapped,
                        #[cfg(test)]
                        &own.audit,
                    )
                })
                .await
        })
    }
    fn sign_metadata(&self, enclaves: bool, operation: KeyOperation) -> KeyFuture<'_, Vec<u8>> {
        let own = self.clone();
        Box::pin(async move {
            operation
                .blocking(move || {
                    own.signature(&master_key_metadata(&own.provider, &own.path, enclaves))
                })
                .await
        })
    }
    fn verify_metadata<'a>(
        &'a self,
        enclaves: bool,
        signature: &'a [u8],
        operation: KeyOperation,
    ) -> KeyFuture<'a, bool> {
        let own = self.clone();
        let signature = signature.to_vec();
        Box::pin(async move {
            operation
                .blocking(move || {
                    Ok(
                        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &own.material.public)
                            .verify(
                                &master_key_metadata(&own.provider, &own.path, enclaves),
                                &signature,
                            )
                            .is_ok(),
                    )
                })
                .await
        })
    }
}
