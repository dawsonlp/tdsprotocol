//! Fake Key Vault transport over the official Keys SDK. It answers with the
//! Python-generated envelope and signatures in `fixtures/azure/key_providers.json`.
#![allow(dead_code)]
use azure_core::{
    credentials::{AccessToken, TokenCredential, TokenRequestOptions},
    http::{AsyncRawResponse, Body, HttpClient, Request, StatusCode, Transport, headers::Headers},
};
use azure_security_keyvault_keys::KeyClientOptions;
use base64::{
    Engine,
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
};
use serde_json::{Value, json};
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tds_client::encryption::keyvault::AzureKeyVaultKeyStore;

#[derive(Debug)]
pub struct Credential;
#[async_trait::async_trait]
impl TokenCredential for Credential {
    async fn get_token(
        &self,
        scopes: &[&str],
        _: Option<TokenRequestOptions<'_>>,
    ) -> azure_core::Result<AccessToken> {
        assert_eq!(scopes, ["https://vault.azure.net/.default"]);
        Ok(AccessToken {
            token: "artificial-vault-token".into(),
            expires_on: time::OffsetDateTime::now_utc() + time::Duration::hours(1),
        })
    }
}
#[derive(Debug, Default)]
pub struct Vault {
    pub calls: Mutex<Vec<(String, Value)>>,
    pub denied: AtomicBool,
    pub requests: AtomicUsize,
}
impl Vault {
    /// Operation names (the last path segment) in request order.
    pub fn operations(&self) -> Vec<String> {
        self.calls
            .lock()
            .unwrap()
            .iter()
            .map(|(path, _)| path.rsplit('/').next().unwrap().to_owned())
            .collect()
    }
}
pub fn fixture() -> Value {
    serde_json::from_str(include_str!("../fixtures/azure/key_providers.json")).unwrap()
}
pub fn b(f: &Value, name: &str) -> Vec<u8> {
    STANDARD.decode(f[name].as_str().unwrap()).unwrap()
}
#[async_trait::async_trait]
impl HttpClient for Vault {
    async fn execute_request(&self, request: &Request) -> azure_core::Result<AsyncRawResponse> {
        self.requests.fetch_add(1, Ordering::SeqCst);
        let Body::Bytes(bytes) = request.body() else {
            panic!("JSON request")
        };
        if bytes.is_empty() {
            let mut headers = Headers::new();
            headers.insert("www-authenticate","Bearer authorization=\"https://login.windows.net/tenant\", resource=\"https://vault.azure.net\"");
            return Ok(AsyncRawResponse::from_bytes(
                StatusCode::Unauthorized,
                headers,
                Vec::new(),
            ));
        }
        let body: Value = serde_json::from_slice(bytes).unwrap();
        let path = request.url().path().to_owned();
        self.calls
            .lock()
            .unwrap()
            .push((path.clone(), body.clone()));
        if self.denied.load(Ordering::SeqCst) {
            return Ok(AsyncRawResponse::from_bytes(StatusCode::Forbidden,Headers::new(),br#"{"error":{"code":"Forbidden","message":"artificial-private-provider-diagnostic"}}"#.to_vec()));
        }
        let f = fixture();
        let value = |name: &str| {
            URL_SAFE_NO_PAD
                .decode(body[name].as_str().unwrap())
                .unwrap()
        };
        let response = if path.ends_with("/wrapkey") {
            assert_eq!(body["alg"], "RSA-OAEP");
            assert_eq!(value("value"), b(&f, "root"));
            json!({"value":URL_SAFE_NO_PAD.encode(b(&f,"ciphertext"))})
        } else if path.ends_with("/unwrapkey") {
            assert_eq!(body["alg"], "RSA-OAEP");
            assert_eq!(value("value"), b(&f, "ciphertext"));
            json!({"value":URL_SAFE_NO_PAD.encode(b(&f,"root"))})
        } else if path.ends_with("/sign") {
            assert_eq!(body["alg"], "RS256");
            let digest = value("value");
            let sig = if digest == b(&f, "body_digest") {
                b(&f, "signature")
            } else {
                assert_eq!(digest, b(&f, "metadata_digest"));
                b(&f, "metadata_signature")
            };
            json!({"value":URL_SAFE_NO_PAD.encode(sig)})
        } else if path.ends_with("/verify") {
            assert_eq!(body["alg"], "RS256");
            let digest = value("digest");
            let signature = value("value");
            json!({"value":(digest==b(&f,"body_digest")&&signature==b(&f,"signature")) || (digest==b(&f,"metadata_digest")&&signature==b(&f,"metadata_signature"))})
        } else {
            panic!("unexpected vault operation {path}")
        };
        Ok(AsyncRawResponse::from_bytes(
            StatusCode::Ok,
            Headers::new(),
            serde_json::to_vec(&response).unwrap(),
        ))
    }
}
pub fn store(vault: Arc<Vault>) -> AzureKeyVaultKeyStore {
    let mut options = KeyClientOptions::default();
    options.client_options.transport = Some(Transport::new(vault));
    AzureKeyVaultKeyStore::with_options(Arc::new(Credential), options)
}
