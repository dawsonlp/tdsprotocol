#![cfg(feature = "azure-keyvault")]
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
use tds_client::encryption::{keyvault::AzureKeyVaultKeyStore, *};

#[derive(Debug)]
struct Credential;
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
struct Vault {
    calls: Mutex<Vec<(String, Value)>>,
    denied: AtomicBool,
    requests: AtomicUsize,
}
fn fixture() -> Value {
    serde_json::from_str(include_str!("fixtures/azure/key_providers.json")).unwrap()
}
fn b(f: &Value, name: &str) -> Vec<u8> {
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
fn store(vault: Arc<Vault>) -> AzureKeyVaultKeyStore {
    let mut options = KeyClientOptions::default();
    options.client_options.transport = Some(Transport::new(vault));
    AzureKeyVaultKeyStore::with_options(Arc::new(Credential), options)
}
#[tokio::test]
async fn sdk_requests_preserve_version_verify_order_and_python_envelopes() {
    let vault = Arc::new(Vault::default());
    let store = store(vault.clone());
    let f = fixture();
    let operation = KeyOperation::default();
    let master = store
        .open(f["path"].as_str().unwrap(), operation.clone())
        .await
        .unwrap();
    assert!(vault.calls.lock().unwrap().is_empty());
    let evidence = WrappedKey {
        provider: "AZURE_KEY_VAULT".into(),
        path: f["path"].as_str().unwrap().into(),
        algorithm: "rſa_oaep".into(),
        encrypted: b(&f, "wrapped"),
    };
    let root = master.unwrap(&evidence, operation.clone()).await.unwrap();
    assert_eq!(root.as_bytes(), b(&f, "root"));
    assert_eq!(
        master.wrap(&root, operation.clone()).await.unwrap(),
        b(&f, "wrapped")
    );
    let signature = master.sign_metadata(true, operation.clone()).await.unwrap();
    assert_eq!(signature, b(&f, "metadata_signature"));
    assert!(
        master
            .verify_metadata(true, &signature, operation.clone())
            .await
            .unwrap()
    );
    assert!(
        !master
            .verify_metadata(false, &signature, operation.clone())
            .await
            .unwrap()
    );
    let mut bad = evidence.clone();
    *bad.encrypted.last_mut().unwrap() ^= 1;
    assert_eq!(
        master.unwrap(&bad, operation.clone()).await.unwrap_err(),
        Error::Authentication
    );
    let calls = vault.calls.lock().unwrap();
    assert_eq!(
        vault.requests.load(Ordering::SeqCst),
        calls.len() + 1,
        "one initial physical authentication challenge"
    );
    assert_eq!(
        calls
            .iter()
            .map(|(path, _)| path.as_str())
            .collect::<Vec<_>>(),
        [
            "/keys/MyKey/Version1/verify",
            "/keys/MyKey/Version1/unwrapkey",
            "/keys/MyKey/Version1/wrapkey",
            "/keys/MyKey/Version1/sign",
            "/keys/MyKey/Version1/sign",
            "/keys/MyKey/Version1/verify",
            "/keys/MyKey/Version1/verify",
            "/keys/MyKey/Version1/verify"
        ]
    );
    if let Some(path) = std::env::var_os("TDS_VAULT_PROVIDER_OUTPUT") {
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(path)
            .unwrap();
        file.write_all(serde_json::to_string(&json!({"vault":true,"root":STANDARD.encode(root.as_bytes()),"wrapped":f["wrapped"],"metadata_signature":STANDARD.encode(signature)})).unwrap().as_bytes()).unwrap();
    }
}
#[tokio::test]
async fn vault_denial_keeps_protected_diagnostic_out_of_normal_errors() {
    let vault = Arc::new(Vault::default());
    vault.denied.store(true, Ordering::SeqCst);
    let store = store(vault.clone());
    let f = fixture();
    let op = KeyOperation::default();
    let master = store
        .open(f["path"].as_str().unwrap(), op.clone())
        .await
        .unwrap();
    let error = master.sign_metadata(true, op).await.unwrap_err();
    assert!(
        !format!("{error} {error:?} {store:?}").contains("artificial-private-provider-diagnostic")
    );
    let Error::Provider(cause) = error else {
        panic!("protected cause")
    };
    assert!(
        cause
            .protected_cause()
            .to_string()
            .contains("artificial-private-provider-diagnostic")
    );
    assert_eq!(vault.calls.lock().unwrap().len(), 1);
    assert_eq!(vault.requests.load(Ordering::SeqCst), 2);
}
