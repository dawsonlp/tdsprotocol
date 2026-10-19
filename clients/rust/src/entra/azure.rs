//! Optional official SDK adapter. Construct credentials with their intended
//! tenant/authority; the SQL server's STS hint never selects an OAuth authority.
//!
//! SDK-managed cached/temporary secrets are not erased by the driver's buffer
//! ownership. The generic adapter cannot change an external credential's worker
//! policy. The CLI constructor below supplies a cancelable child-process owner.
use super::{AccessToken, ProviderError, TokenFuture, TokenProvider, TokenRequest};
pub use azure_core::credentials::TokenCredential;
pub use azure_identity;
use std::{fmt, sync::Arc};

pub struct AzureTokenProvider {
    credential: Arc<dyn TokenCredential>,
}
impl AzureTokenProvider {
    pub fn new(credential: Arc<dyn TokenCredential>) -> Self {
        Self { credential }
    }

    /// Supply a process owner that requests child termination when acquisition
    /// is canceled. Tokio manages eventual reaping; this is not an OS guarantee
    /// of immediate process termination on runtime destruction.
    pub fn azure_cli(
        mut options: azure_identity::AzureCliCredentialOptions,
    ) -> Result<Self, ProviderError> {
        options.executor = Some(Arc::new(OwnedExecutor));
        azure_identity::AzureCliCredential::new(Some(options))
            .map(|credential| Self::new(credential))
            .map_err(ProviderError::with_cause)
    }
}
impl fmt::Debug for AzureTokenProvider {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AzureTokenProvider([opaque credential])")
    }
}
impl TokenProvider for AzureTokenProvider {
    fn acquire<'a>(&'a self, request: TokenRequest<'a>) -> TokenFuture<'a> {
        Box::pin(async move {
            // This is exactly Python's entra._scope conversion. The supplied
            // STS URL remains evidence for custom providers, not an SDK override.
            let scope = format!("{}/.default", request.resource.trim_end_matches('/'));
            let token = self
                .credential
                .get_token(&[scope.as_str()], None)
                .await
                .map_err(ProviderError::with_cause)?;
            Ok(AccessToken::new(
                token.token.secret().to_owned(),
                Some(token.expires_on.into()),
            ))
        })
    }
}

#[derive(Debug)]
struct OwnedExecutor;
#[async_trait::async_trait]
impl azure_identity::Executor for OwnedExecutor {
    async fn run(
        &self,
        program: &std::ffi::OsStr,
        args: &[&std::ffi::OsStr],
    ) -> std::io::Result<std::process::Output> {
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output()
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use azure_core::credentials::{AccessToken as SdkToken, TokenRequestOptions};
    use std::sync::Mutex;

    #[derive(Debug, Default)]
    struct Credential {
        scopes: Mutex<Vec<Vec<String>>>,
    }
    #[async_trait::async_trait]
    impl TokenCredential for Credential {
        async fn get_token(
            &self,
            scopes: &[&str],
            _: Option<TokenRequestOptions<'_>>,
        ) -> azure_core::Result<SdkToken> {
            self.scopes
                .lock()
                .unwrap()
                .push(scopes.iter().map(|s| s.to_string()).collect());
            Ok(SdkToken {
                token: "artificial-sdk-token".into(),
                expires_on: time::OffsetDateTime::from_unix_timestamp(2_000_000_000).unwrap(),
            })
        }
    }
    #[tokio::test]
    async fn official_credential_adapter_preserves_scope_and_expiry_without_authority_override() {
        let credential = Arc::new(Credential::default());
        let adapter = AzureTokenProvider::new(credential.clone());
        for resource in ["https://database.windows.net/", "https://fixture///"] {
            let token = adapter
                .acquire(TokenRequest {
                    resource,
                    sts_url: Some("https://ignored.invalid/tenant"),
                    host: "physical",
                    port: 1433,
                    workflow: None,
                })
                .await
                .unwrap();
            assert_eq!(token.as_str(), "artificial-sdk-token");
            assert_eq!(
                token
                    .expires_at
                    .unwrap()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                2_000_000_000
            );
            assert!(!format!("{adapter:?} {token:?}").contains("artificial-sdk-token"));
        }
        assert_eq!(
            *credential.scopes.lock().unwrap(),
            vec![
                vec!["https://database.windows.net/.default"],
                vec!["https://fixture/.default"]
            ]
        );
    }

    #[derive(Debug, Default)]
    struct SecretTransport {
        calls: Mutex<Vec<(String, String)>>,
    }
    #[async_trait::async_trait]
    impl azure_core::http::HttpClient for SecretTransport {
        async fn execute_request(
            &self,
            request: &azure_core::http::Request,
        ) -> azure_core::Result<azure_core::http::AsyncRawResponse> {
            let azure_core::http::Body::Bytes(body) = request.body() else {
                panic!("form request")
            };
            self.calls.lock().unwrap().push((
                request.url().to_string(),
                String::from_utf8(body.to_vec()).unwrap(),
            ));
            Ok(azure_core::http::AsyncRawResponse::from_bytes(azure_core::http::StatusCode::Ok,azure_core::http::headers::Headers::new(),br#"{"access_token":"artificial-service-token","expires_in":3600,"ext_expires_in":3600,"token_type":"Bearer"}"#.to_vec()))
        }
    }
    fn request() -> TokenRequest<'static> {
        TokenRequest {
            resource: "https://database.windows.net/",
            sts_url: Some("https://untrusted-hint.invalid/other"),
            host: "physical",
            port: 1433,
            workflow: None,
        }
    }
    #[tokio::test]
    async fn service_principal_uses_configured_tenant_form_and_sdk_cache() {
        let http = Arc::new(SecretTransport::default());
        let mut options = azure_identity::ClientSecretCredentialOptions::default();
        options.client_options.transport = Some(azure_core::http::Transport::new(http.clone()));
        let credential = azure_identity::ClientSecretCredential::new(
            "fixture-tenant",
            "fixture-client".into(),
            "artificial-client+secret".into(),
            Some(options),
        )
        .unwrap();
        let adapter = AzureTokenProvider::new(credential);
        for _ in 0..2 {
            let token = adapter.acquire(request()).await.unwrap();
            assert_eq!(token.as_str(), "artificial-service-token");
            assert!(!format!("{adapter:?} {token:?}").contains("artificial-service-token"));
        }
        let calls = http.calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(
            calls[0].0,
            "https://login.microsoftonline.com/fixture-tenant/oauth2/v2.0/token"
        );
        assert!(
            calls[0]
                .1
                .contains("client_secret=artificial-client%2Bsecret")
        );
        assert!(
            calls[0]
                .1
                .contains("scope=https%3A%2F%2Fdatabase.windows.net%2F.default")
        );
        assert!(calls[0].1.contains("grant_type=client_credentials"));
    }
    #[derive(Debug, Default)]
    struct Cli {
        commands: Mutex<Vec<String>>,
    }
    #[async_trait::async_trait]
    impl azure_identity::Executor for Cli {
        async fn run(
            &self,
            _: &std::ffi::OsStr,
            args: &[&std::ffi::OsStr],
        ) -> std::io::Result<std::process::Output> {
            self.commands.lock().unwrap().push(
                args.iter()
                    .map(|a| a.to_string_lossy())
                    .collect::<Vec<_>>()
                    .join(" "),
            );
            #[cfg(unix)]
            use std::os::unix::process::ExitStatusExt;
            #[cfg(windows)]
            use std::os::windows::process::ExitStatusExt;
            Ok(std::process::Output {status:std::process::ExitStatus::from_raw(0),stdout:br#"{"accessToken":"artificial-cli-token","expires_on":2000000000,"tokenType":"Bearer"}"#.to_vec(),stderr:Vec::new()})
        }
    }
    #[tokio::test]
    async fn official_cli_credential_uses_selected_tenant_and_scope_without_driver_cache() {
        let executor = Arc::new(Cli::default());
        let credential = azure_identity::AzureCliCredential::new(Some(
            azure_identity::AzureCliCredentialOptions {
                tenant_id: Some("fixture-tenant".into()),
                executor: Some(executor.clone()),
                ..Default::default()
            },
        ))
        .unwrap();
        let adapter = AzureTokenProvider::new(credential);
        for _ in 0..2 {
            assert_eq!(
                adapter.acquire(request()).await.unwrap().as_str(),
                "artificial-cli-token"
            );
        }
        let commands = executor.commands.lock().unwrap();
        assert_eq!(commands.len(), 2);
        for command in commands.iter() {
            assert!(command.contains("--scope https://database.windows.net/.default"));
            assert!(command.contains("--tenant fixture-tenant"));
            assert!(!command.contains("untrusted-hint"));
        }
    }
    #[cfg(unix)]
    #[tokio::test]
    async fn owned_executor_cancellation_terminates_and_reaps_its_child() {
        use azure_identity::Executor;
        let file = std::env::temp_dir().join(format!(
            "tds-owned-cli-{}-{}.pid",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        // The path is a generated numeric fixture, passed as a positional
        // argument. No untrusted text is interpolated into shell source.
        let script = std::ffi::OsStr::new("echo $$ > \"$1\"; exec /bin/sleep 60");
        let args = [
            std::ffi::OsStr::new("-c"),
            script,
            std::ffi::OsStr::new("fixture"),
            file.as_os_str(),
        ];
        {
            let call = OwnedExecutor.run(std::ffi::OsStr::new("/bin/sh"), &args);
            tokio::pin!(call);
            tokio::select! {result=&mut call=>panic!("child exited early: {result:?}"),_ = tokio::time::timeout(std::time::Duration::from_secs(2),async {while !file.exists() {tokio::time::sleep(std::time::Duration::from_millis(5)).await;}})=> {assert!(file.exists());}}
        }
        let pid = std::fs::read_to_string(&file)
            .unwrap()
            .trim()
            .parse::<u32>()
            .unwrap()
            .to_string();
        tokio::time::timeout(std::time::Duration::from_secs(2), async {
            while std::process::Command::new("/bin/kill")
                .args(["-0", &pid])
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .status()
                .unwrap()
                .success()
            {
                tokio::time::sleep(std::time::Duration::from_millis(5)).await;
            }
        })
        .await
        .unwrap();
        std::fs::remove_file(file).unwrap();
    }
}
