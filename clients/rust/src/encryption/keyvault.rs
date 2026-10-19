//! Azure Key Vault keeps private keys remote. The envelope/signature operations
//! match Python encryption/keyvault.py. SDK buffers are outside driver erasure.
use super::{
    Error, KeyFuture, KeyOperation, KeyProvider, MasterKey, Plaintext, ProviderFailure, Result,
    WrappedKey, master_key_metadata,
};
use aws_lc_rs::digest::{self, SHA256};
use azure_core::credentials::TokenCredential;
use azure_security_keyvault_keys::{
    KeyClient, KeyClientOptions, ResourceId,
    models::{
        EncryptionAlgorithm, KeyClientSignOptions, KeyClientWrapKeyOptions, KeyOperationParameters,
        SignParameters, SignatureAlgorithm, VerifyParameters,
    },
};
use std::{fmt, sync::Arc};
use zeroize::Zeroizing;

fn failure(error: azure_core::Error) -> Error {
    Error::Provider(ProviderFailure::new(error))
}
fn digest(bytes: &[u8]) -> Vec<u8> {
    digest::digest(&SHA256, bytes).as_ref().to_vec()
}

pub struct AzureKeyVaultKeyStore {
    credential: Arc<dyn TokenCredential>,
    options: KeyClientOptions,
}
impl AzureKeyVaultKeyStore {
    pub fn new(credential: Arc<dyn TokenCredential>) -> Self {
        Self::with_options(credential, Default::default())
    }
    /// SDK transport/retry options are explicit. The key session supplies the
    /// outer finite deadline; retries never restart that budget.
    pub fn with_options(credential: Arc<dyn TokenCredential>, options: KeyClientOptions) -> Self {
        Self {
            credential,
            options,
        }
    }
}
impl fmt::Debug for AzureKeyVaultKeyStore {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AzureKeyVaultKeyStore([opaque credential])")
    }
}
impl KeyProvider for AzureKeyVaultKeyStore {
    fn name(&self) -> &str {
        "AZURE_KEY_VAULT"
    }
    fn open<'a>(&'a self, path: &'a str, _: KeyOperation) -> KeyFuture<'a, Arc<dyn MasterKey>> {
        Box::pin(async move {
            let id: ResourceId = path.parse().map_err(failure)?;
            let client = KeyClient::new(
                &id.vault_url,
                self.credential.clone(),
                Some(self.options.clone()),
            )
            .map_err(failure)?;
            Ok(Arc::new(VaultKey {
                client,
                path: path.into(),
                name: id.name,
                version: id.version,
            }) as Arc<dyn MasterKey>)
        })
    }
}
struct VaultKey {
    client: KeyClient,
    path: String,
    name: String,
    version: Option<String>,
}
impl VaultKey {
    async fn sign(&self, digest: Vec<u8>) -> Result<Vec<u8>> {
        let parameters = SignParameters {
            algorithm: Some(SignatureAlgorithm::Rs256),
            value: Some(digest),
        };
        let options = KeyClientSignOptions {
            key_version: self.version.clone(),
            ..Default::default()
        };
        self.client
            .sign(
                &self.name,
                parameters.try_into().map_err(failure)?,
                Some(options),
            )
            .await
            .map_err(failure)?
            .into_model()
            .map_err(failure)?
            .result
            .ok_or(Error::InvalidMetadata)
    }
    async fn verify(&self, digest: Vec<u8>, signature: Vec<u8>) -> Result<bool> {
        let parameters = VerifyParameters {
            algorithm: Some(SignatureAlgorithm::Rs256),
            digest: Some(digest),
            signature: Some(signature),
        };
        self.client
            .verify(
                &self.name,
                self.version.as_deref().unwrap_or(""),
                parameters.try_into().map_err(failure)?,
                None,
            )
            .await
            .map_err(failure)?
            .into_model()
            .map_err(failure)?
            .value
            .ok_or(Error::InvalidMetadata)
    }
}
impl MasterKey for VaultKey {
    fn wrap<'a>(&'a self, column_key: &'a Plaintext, _: KeyOperation) -> KeyFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if column_key.as_bytes().len() != 32 {
                return Err(Error::InvalidMetadata);
            }
            let parameters = KeyOperationParameters {
                algorithm: Some(EncryptionAlgorithm::RsaOaep),
                value: Some(column_key.as_bytes().to_vec()),
                ..Default::default()
            };
            let options = KeyClientWrapKeyOptions {
                key_version: self.version.clone(),
                ..Default::default()
            };
            let result = self
                .client
                .wrap_key(
                    &self.name,
                    parameters.try_into().map_err(failure)?,
                    Some(options),
                )
                .await
                .map_err(failure)?
                .into_model()
                .map_err(failure)?;
            let ciphertext = result.result.ok_or(Error::InvalidMetadata)?;
            let path: Vec<u8> = self
                .path
                .to_lowercase()
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect();
            let mut body = vec![1];
            body.extend(
                u16::try_from(path.len())
                    .map_err(|_| Error::InvalidMetadata)?
                    .to_le_bytes(),
            );
            body.extend(
                u16::try_from(ciphertext.len())
                    .map_err(|_| Error::InvalidMetadata)?
                    .to_le_bytes(),
            );
            body.extend(path);
            body.extend(ciphertext);
            body.extend(self.sign(digest(&body)).await?);
            Ok(body)
        })
    }
    fn unwrap<'a>(&'a self, evidence: &'a WrappedKey, _: KeyOperation) -> KeyFuture<'a, Plaintext> {
        Box::pin(async move {
            let bytes = &evidence.encrypted;
            if evidence.algorithm.to_uppercase() != "RSA_OAEP" || bytes.len() < 5 || bytes[0] != 1 {
                return Err(Error::InvalidMetadata);
            }
            // Python slicing clips these lengths. Verify exactly its signed
            // prefix before unwrapping; structural concerns remain review items.
            let start = 5 + usize::from(u16::from_le_bytes(bytes[1..3].try_into().unwrap()));
            let end = start + usize::from(u16::from_le_bytes(bytes[3..5].try_into().unwrap()));
            let body = &bytes[..end.min(bytes.len())];
            let signature = &bytes[end.min(bytes.len())..];
            if !self.verify(digest(body), signature.to_vec()).await? {
                return Err(Error::Authentication);
            }
            let parameters = KeyOperationParameters {
                algorithm: Some(EncryptionAlgorithm::RsaOaep),
                value: Some(body[start.min(body.len())..].to_vec()),
                ..Default::default()
            };
            let result = self
                .client
                .unwrap_key(
                    &self.name,
                    self.version.as_deref().unwrap_or(""),
                    parameters.try_into().map_err(failure)?,
                    None,
                )
                .await
                .map_err(failure)?
                .into_model()
                .map_err(failure)?;
            let root = Zeroizing::new(result.result.ok_or(Error::InvalidMetadata)?);
            if root.len() != 32 {
                return Err(Error::InvalidMetadata);
            }
            Plaintext::copy(&root)
        })
    }
    fn sign_metadata(&self, enclaves: bool, _: KeyOperation) -> KeyFuture<'_, Vec<u8>> {
        Box::pin(async move {
            self.sign(digest(&master_key_metadata(
                "AZURE_KEY_VAULT",
                &self.path,
                enclaves,
            )))
            .await
        })
    }
    fn verify_metadata<'a>(
        &'a self,
        enclaves: bool,
        signature: &'a [u8],
        _: KeyOperation,
    ) -> KeyFuture<'a, bool> {
        Box::pin(async move {
            self.verify(
                digest(&master_key_metadata(
                    "AZURE_KEY_VAULT",
                    &self.path,
                    enclaves,
                )),
                signature.to_vec(),
            )
            .await
        })
    }
}
