//! Windows certificate-store parity. Private operations use owned CNG handles;
//! public verification/encryption use the certificate's RSA public key.
use super::{Error, KeyFuture, KeyOperation, KeyProvider, MasterKey};
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Default)]
pub struct WindowsCertificateStore;
impl KeyProvider for WindowsCertificateStore {
    fn name(&self) -> &str {
        "MSSQL_CERTIFICATE_STORE"
    }
    fn open<'a>(
        &'a self,
        path: &'a str,
        operation: KeyOperation,
    ) -> KeyFuture<'a, Arc<dyn MasterKey>> {
        Box::pin(async move {
            let parsed = parse_path(path)?;
            {
                if !cfg!(windows) {
                    return Err(Error::UnsupportedPlatform);
                }
                let path = path.to_owned();
                operation
                    .blocking(move || {
                        let certificate = tds_native_certstore::Certificate::open(
                            parsed.location,
                            &parsed.store,
                            &parsed.thumbprint,
                        )
                        .map_err(failure)?;
                        let (_, x509) = x509_parser::parse_x509_certificate(certificate.der())
                            .map_err(|_| Error::InvalidMasterKey)?;
                        let public = x509.public_key().raw.to_vec();
                        let encryptor = aws_lc_rs::rsa::OaepPublicEncryptingKey::new(
                            aws_lc_rs::rsa::PublicEncryptingKey::from_der(&public)
                                .map_err(|_| Error::InvalidMasterKey)?,
                        )
                        .map_err(|_| Error::InvalidMasterKey)?;
                        Ok(Arc::new(CertificateKey {
                            material: Arc::new(Material {
                                certificate,
                                encryptor,
                                public,
                            }),
                            path,
                        }) as Arc<dyn MasterKey>)
                    })
                    .await
            }
        })
    }
}
struct CertificatePath {
    location: u32,
    store: String,
    thumbprint: Vec<u8>,
}
fn parse_path(path: &str) -> super::Result<CertificatePath> {
    if path.len() > 65_535 || path.contains('\0') {
        return Err(Error::InvalidMetadata);
    }
    let normalized = path.replace('\\', "/");
    let parts: Vec<_> = normalized.split('/').collect();
    if parts.len() != 3 {
        return Err(Error::InvalidMetadata);
    }
    let location = match parts[0].to_lowercase().as_str() {
        "currentuser" => 0x10000,
        "localmachine" => 0x20000,
        _ => return Err(Error::InvalidMetadata),
    };
    // bytes.fromhex permits ASCII whitespace between complete bytes, not
    // between their nibbles. Preserve Python's path acceptance.
    let mut hex = Vec::new();
    for byte in parts[2].bytes() {
        if byte.is_ascii_whitespace() {
            if !hex.len().is_multiple_of(2) {
                return Err(Error::InvalidMetadata);
            }
        } else {
            hex.push(byte);
        }
    }
    let (pairs, remainder) = hex.as_chunks::<2>();
    if !remainder.is_empty() {
        return Err(Error::InvalidMetadata);
    }
    let thumbprint = pairs
        .iter()
        .map(|pair| {
            let digit = |b: u8| -> super::Result<u8> {
                match b {
                    b'0'..=b'9' => Ok(b - b'0'),
                    b'a'..=b'f' => Ok(b - b'a' + 10),
                    b'A'..=b'F' => Ok(b - b'A' + 10),
                    _ => Err(Error::InvalidMetadata),
                }
            };
            Ok(digit(pair[0])? * 16 + digit(pair[1])?)
        })
        .collect::<super::Result<Vec<_>>>()?;
    Ok(CertificatePath {
        location,
        store: parts[1].into(),
        thumbprint,
    })
}
fn failure(error: tds_native_certstore::Error) -> Error {
    Error::Provider(super::ProviderFailure::new(error))
}

use super::{Plaintext, Result, WrappedKey, master_key_metadata};
use aws_lc_rs::{
    digest::{SHA256, digest},
    rsa::{OAEP_SHA1_MGF1SHA1, OaepPublicEncryptingKey},
    signature::{RSA_PKCS1_2048_8192_SHA256, UnparsedPublicKey},
};
struct Material {
    certificate: tds_native_certstore::Certificate,
    encryptor: OaepPublicEncryptingKey,
    public: Vec<u8>,
}
#[derive(Clone)]
struct CertificateKey {
    material: Arc<Material>,
    path: String,
}
impl CertificateKey {
    fn sign(&self, body: &[u8]) -> Result<Vec<u8>> {
        self.material
            .certificate
            .sign_sha256_digest(digest(&SHA256, body).as_ref().try_into().unwrap())
            .map_err(failure)
    }
    fn verify(&self, body: &[u8], signature: &[u8]) -> bool {
        UnparsedPublicKey::new(&RSA_PKCS1_2048_8192_SHA256, &self.material.public)
            .verify(body, signature)
            .is_ok()
    }
}
impl MasterKey for CertificateKey {
    fn wrap<'a>(&'a self, root: &'a Plaintext, operation: KeyOperation) -> KeyFuture<'a, Vec<u8>> {
        Box::pin(async move {
            if root.as_bytes().len() != 32 {
                return Err(Error::InvalidMetadata);
            }
            let root = Plaintext::copy(root.as_bytes())?;
            let this = self.clone();
            operation
                .blocking(move || {
                    let mut ciphertext = vec![0; this.material.encryptor.ciphertext_size()];
                    let ciphertext = this
                        .material
                        .encryptor
                        .encrypt(&OAEP_SHA1_MGF1SHA1, root.as_bytes(), &mut ciphertext, None)
                        .map_err(|_| Error::Authentication)?;
                    let path: Vec<u8> = this
                        .path
                        .encode_utf16()
                        .flat_map(u16::to_le_bytes)
                        .collect();
                    let mut body = vec![1];
                    body.extend(
                        u16::try_from(path.len())
                            .map_err(|_| Error::InvalidMetadata)?
                            .to_le_bytes(),
                    );
                    body.extend((ciphertext.len() as u16).to_le_bytes());
                    body.extend(path);
                    body.extend_from_slice(ciphertext);
                    body.extend(this.sign(&body)?);
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
        let this = self.clone();
        let evidence = evidence.clone();
        Box::pin(async move {
            operation
                .blocking(move || {
                    let bytes = &evidence.encrypted;
                    if evidence.algorithm.to_uppercase() != "RSA_OAEP"
                        || bytes.len() < 5
                        || bytes[0] != 1
                    {
                        return Err(Error::InvalidMetadata);
                    }
                    let start =
                        5 + usize::from(u16::from_le_bytes(bytes[1..3].try_into().unwrap()));
                    let length = usize::from(u16::from_le_bytes(bytes[3..5].try_into().unwrap()));
                    let size = this.material.encryptor.ciphertext_size();
                    if length != size || bytes.len() != start + length + size {
                        return Err(Error::InvalidMetadata);
                    }
                    let end = start + length;
                    if !this.verify(&bytes[..end], &bytes[end..]) {
                        return Err(Error::Authentication);
                    }
                    let root = this
                        .material
                        .certificate
                        .decrypt_oaep_sha1(&bytes[start..end])
                        .map_err(failure)?;
                    if root.len() != 32 {
                        return Err(Error::InvalidMetadata);
                    }
                    Plaintext::copy(&root)
                })
                .await
        })
    }
    fn sign_metadata(&self, enclaves: bool, operation: KeyOperation) -> KeyFuture<'_, Vec<u8>> {
        let this = self.clone();
        Box::pin(async move {
            operation
                .blocking(move || {
                    this.sign(&master_key_metadata(
                        "MSSQL_CERTIFICATE_STORE",
                        &this.path,
                        enclaves,
                    ))
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
        let this = self.clone();
        let signature = signature.to_vec();
        Box::pin(async move {
            operation
                .blocking(move || {
                    Ok(this.verify(
                        &master_key_metadata("MSSQL_CERTIFICATE_STORE", &this.path, enclaves),
                        &signature,
                    ))
                })
                .await
        })
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn python_certificate_paths() {
        let path = parse_path("currentUSER\\My\\Ab 12\tff").unwrap();
        assert_eq!(path.location, 0x10000);
        assert_eq!(path.store, "My");
        assert_eq!(path.thumbprint, [0xab, 0x12, 0xff]);
        assert_eq!(parse_path("LOCALMACHINE/My/00").unwrap().location, 0x20000);
        for path in [
            "Other/My/00",
            "CurrentUser/My/0",
            "CurrentUser/My/GG",
            "CurrentUser/My/00/extra",
            "CurrentUser/My/00\0",
            "CurrentUser/My/A b",
        ] {
            assert!(parse_path(path).is_err());
        }
    }
    #[tokio::test]
    #[cfg(not(windows))]
    async fn unavailable_platform_is_explicit() {
        assert!(matches!(
            WindowsCertificateStore
                .open("CurrentUser/My/00", KeyOperation::default())
                .await,
            Err(Error::UnsupportedPlatform)
        ));
    }
}
