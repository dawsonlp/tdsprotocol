use super::{Credentials, Method, Provider, Token, WindowsAuth};
use crate::{Error, ErrorKind, Result};
use sspi::Sspi;
use std::{future::Future, pin::Pin};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};
use zeroize::Zeroize;

pub(crate) fn failure() -> Error {
    Error::new(ErrorKind::Authentication("provider refused or failed"))
}
pub(crate) type AuthFuture<'a> = Pin<Box<dyn Future<Output = Result<(Token, bool)>> + Send + 'a>>;
pub(crate) trait SecurityContext: Send {
    fn step<'a>(&'a mut self, challenge: Option<Token>, binding: &'a [u8]) -> AuthFuture<'a>;
    #[cfg(feature = "system-gssapi")]
    fn gssapi_evidence(&self) -> Option<super::GssapiEvidence> {
        None
    }
}
pub(crate) struct Context(Box<dyn SecurityContext>);
impl Context {
    pub fn new(auth: &WindowsAuth, host: &str, port: u16) -> Result<Self> {
        if auth.provider == Provider::SystemGssapi {
            #[cfg(feature = "system-gssapi")]
            return Ok(Self(Box::new(super::gssapi::System::new(
                auth,
                auth.service_principal
                    .clone()
                    .unwrap_or_else(|| format!("MSSQLSvc/{host}:{port}")),
            )?)));
            #[cfg(not(feature = "system-gssapi"))]
            return Err(Error::new(ErrorKind::Unsupported(
                "system GSSAPI adapter is not built",
            )));
        }
        if auth.provider == Provider::NativeWindows {
            #[cfg(windows)]
            {
                if auth.credentials != Credentials::SignedIn {
                    return Err(Error::new(ErrorKind::Parameter(
                        "native Windows provider requires signed-in identity",
                    )));
                }
                let target = auth
                    .service_principal
                    .clone()
                    .unwrap_or_else(|| format!("MSSQLSvc/{host}:{port}"));
                return Ok(Self(Box::new(super::native::Native::new(
                    auth.method,
                    target,
                    auth.allow_ntlm_fallback,
                ))));
            }
            #[cfg(not(windows))]
            return Err(Error::new(ErrorKind::Unsupported(
                "native Windows SSPI adapter is not built",
            )));
        }
        let Credentials::Explicit { username, password } = &auth.credentials else {
            return Err(Error::new(ErrorKind::Parameter(
                "portable provider needs explicit credentials",
            )));
        };
        let target = auth
            .service_principal
            .clone()
            .unwrap_or_else(|| format!("MSSQLSvc/{host}:{port}"));
        if target.is_empty() || target.contains('\0') {
            return Err(failure());
        }
        let identity = sspi::AuthIdentity {
            username: sspi::Username::parse(username).map_err(|_| failure())?,
            password: password.to_string().into(),
        };
        let computer = hostname::get()?.to_string_lossy().into_owned();
        let kdc = auth.kdc_url.clone();
        macro_rules! provider {
            ($provider:expr, $identity:expr) => {{
                let mut provider = $provider;
                let credentials = provider
                    .acquire_credentials_handle()
                    .with_credential_use(sspi::CredentialUse::Outbound)
                    .with_auth_data(&$identity)
                    .execute(&mut provider)
                    .map_err(|_| failure())?
                    .credentials_handle;
                Self(Box::new(Portable {
                    provider,
                    credentials,
                    target,
                    kdc,
                    method: auth.method,
                    allow_ntlm_fallback: auth.allow_ntlm_fallback,
                }))
            }};
        }
        Ok(match auth.method {
            Method::Ntlm => provider!(sspi::Ntlm::new(), identity),
            Method::Kerberos | Method::Negotiate => {
                let url = auth.kdc_url.as_deref().ok_or_else(|| {
                    Error::new(ErrorKind::Parameter(
                        "portable Kerberos requires an explicit TCP KDC URL",
                    ))
                })?;
                let config = sspi::KerberosConfig::new(url, computer.clone());
                if config.kdc_url.as_ref().is_none_or(|u| {
                    u.scheme() != "tcp"
                        || u.host_str().is_none()
                        || u.username() != ""
                        || u.password().is_some()
                }) {
                    return Err(Error::new(ErrorKind::Parameter("invalid TCP KDC URL")));
                }
                let identity: sspi::Credentials = identity.into();
                if auth.method == Method::Kerberos {
                    provider!(
                        sspi::Kerberos::new_client_from_config(config).map_err(|_| failure())?,
                        identity
                    )
                } else {
                    let packages = if auth.allow_ntlm_fallback {
                        "kerberos,ntlm"
                    } else {
                        "kerberos,!ntlm"
                    };
                    provider!(
                        sspi::Negotiate::new_client(sspi::NegotiateConfig::new(
                            Box::new(config),
                            Some(packages.into()),
                            computer
                        ))
                        .map_err(|_| failure())?,
                        identity
                    )
                }
            }
        })
    }
    pub async fn step(
        &mut self,
        challenge: Option<Token>,
        binding: &[u8],
    ) -> Result<(Token, bool)> {
        self.0.step(challenge, binding).await
    }
    #[cfg(feature = "system-gssapi")]
    pub fn gssapi_evidence(&self) -> Option<super::GssapiEvidence> {
        self.0.gssapi_evidence()
    }
}
struct Portable<P: Sspi> {
    provider: P,
    credentials: P::CredentialsHandle,
    target: String,
    kdc: Option<String>,
    method: Method,
    allow_ntlm_fallback: bool,
}
struct Buffers(Vec<sspi::SecurityBuffer>);
impl Drop for Buffers {
    fn drop(&mut self) {
        for buffer in &mut self.0 {
            buffer.buffer.zeroize();
        }
    }
}
impl<P> SecurityContext for Portable<P>
where
    P: Sspi + Send,
    P::CredentialsHandle: Send,
{
    fn step<'a>(&'a mut self, challenge: Option<Token>, binding: &'a [u8]) -> AuthFuture<'a> {
        Box::pin(async move {
            let mut input = Buffers(Vec::new());
            if let Some(token) = &challenge {
                input.0.push(sspi::SecurityBuffer::new(
                    token.as_bytes().to_vec(),
                    sspi::BufferType::Token,
                ));
            }
            if !binding.is_empty() {
                input.0.push(sspi::SecurityBuffer::new(
                    binding.to_vec(),
                    sspi::BufferType::ChannelBindings,
                ));
            }
            let mut output = Buffers(vec![sspi::SecurityBuffer::new(
                Vec::new(),
                sspi::BufferType::Token,
            )]);
            let flags = sspi::ClientRequestFlags::CONFIDENTIALITY
                | sspi::ClientRequestFlags::INTEGRITY
                | if self.method == Method::Kerberos
                    || (self.method == Method::Negotiate && !self.allow_ntlm_fallback)
                {
                    sspi::ClientRequestFlags::MUTUAL_AUTH
                } else {
                    sspi::ClientRequestFlags::empty()
                };
            let mut builder = self
                .provider
                .initialize_security_context()
                .with_credentials_handle(&mut self.credentials)
                .with_context_requirements(flags)
                .with_target_data_representation(sspi::DataRepresentation::Native)
                .with_target_name(&self.target)
                .with_input(&mut input.0)
                .with_output(&mut output.0);
            let mut generator = self
                .provider
                .initialize_security_context_impl(&mut builder)
                .map_err(|_| failure())?;
            let mut state = generator.start();
            let mut kdc_rounds = 0_u8;
            let result = loop {
                match state {
                    sspi::generator::GeneratorState::Completed(result) => {
                        break result.map_err(|_| failure())?;
                    }
                    sspi::generator::GeneratorState::Suspended(mut request) => {
                        kdc_rounds += 1;
                        if kdc_rounds > super::MAX_ROUNDS {
                            request.data.zeroize();
                            return Err(Error::new(ErrorKind::Limit("KDC round trips")));
                        }
                        let reply = kdc_request(&request, self.kdc.as_deref()).await;
                        request.data.zeroize();
                        state = generator.resume(reply);
                    }
                }
            };
            drop(generator);
            let complete = match result.status {
                sspi::SecurityStatus::Ok => true,
                sspi::SecurityStatus::ContinueNeeded => false,
                sspi::SecurityStatus::CompleteNeeded
                | sspi::SecurityStatus::CompleteAndContinue => {
                    self.provider
                        .complete_auth_token(&mut output.0)
                        .map_err(|_| failure())?;
                    result.status == sspi::SecurityStatus::CompleteNeeded
                }
                _ => return Err(failure()),
            };
            // The direct Kerberos context has no alternative package and does
            // not implement the Negotiate-only package-query operation.
            if complete && self.method == Method::Negotiate && !self.allow_ntlm_fallback {
                let package = self
                    .provider
                    .query_context_negotiation_package()
                    .map_err(|_| {
                        Error::new(ErrorKind::Authentication("negotiated package unavailable"))
                    })?;
                if !matches!(package.name, sspi::SecurityPackageType::Kerberos) {
                    return Err(failure());
                }
            }
            Ok((
                Token::new(std::mem::take(&mut output.0[0].buffer))?,
                complete,
            ))
        })
    }
}

async fn kdc_request(
    request: &sspi::NetworkRequest,
    allowed: Option<&str>,
) -> sspi::Result<Vec<u8>> {
    async fn send(request: &sspi::NetworkRequest, allowed: Option<&str>) -> Result<Vec<u8>> {
        if request.protocol != sspi::NetworkProtocol::Tcp {
            return Err(failure());
        }
        let expected = sspi::KerberosConfig::new(allowed.ok_or_else(failure)?, String::new())
            .kdc_url
            .ok_or_else(failure)?;
        if request.url != expected || request.data.len() > super::MAX_TOKEN {
            return Err(failure());
        }
        let host = request.url.host_str().ok_or_else(failure)?;
        let mut stream = TcpStream::connect((host, request.url.port().unwrap_or(88))).await?;
        // sspi's TCP request already includes the Kerberos four-byte framing.
        stream.write_all(&request.data).await?;
        let length = stream.read_u32().await? as usize;
        if length == 0 || length > super::MAX_TOKEN {
            return Err(failure());
        }
        let mut response = vec![0; length + 4];
        response[..4].copy_from_slice(&(length as u32).to_be_bytes());
        stream.read_exact(&mut response[4..]).await?;
        Ok(response)
    }
    send(request, allowed).await.map_err(|_| {
        sspi::Error::new(
            sspi::ErrorKind::NoAuthenticatingAuthority,
            "bounded KDC exchange failed",
        )
    })
}

pub(crate) fn channel_binding(certificate: &[u8]) -> Result<Vec<u8>> {
    use sha2::Digest;
    let (_, cert) = x509_parser::parse_x509_certificate(certificate).map_err(|_| failure())?;
    let oid = cert.signature_algorithm.algorithm.to_id_string();
    let hash = match oid.as_str() {
        "1.2.840.113549.1.1.4"
        | "1.2.840.113549.1.1.5"
        | "1.2.840.10045.4.1"
        | "1.2.840.113549.1.1.11"
        | "1.2.840.10045.4.3.2" => sha2::Sha256::digest(certificate).to_vec(),
        "1.2.840.113549.1.1.12" | "1.2.840.10045.4.3.3" => {
            sha2::Sha384::digest(certificate).to_vec()
        }
        "1.2.840.113549.1.1.13" | "1.2.840.10045.4.3.4" => {
            sha2::Sha512::digest(certificate).to_vec()
        }
        _ => {
            return Err(Error::new(ErrorKind::Unsupported(
                "TLS endpoint signature hash for channel binding",
            )));
        }
    };
    let application = [b"tls-server-end-point:".as_slice(), &hash].concat();
    let mut binding = vec![0; 32];
    binding[24..28].copy_from_slice(&(application.len() as u32).to_le_bytes());
    binding[28..32].copy_from_slice(&32_u32.to_le_bytes());
    binding.extend(application);
    Ok(binding)
}

#[cfg(all(test, not(feature = "system-gssapi")))]
mod tests {
    use super::*;
    #[test]
    fn system_cache_is_explicitly_unavailable_without_its_feature() {
        let auth = WindowsAuth::system_cache(Method::Kerberos);
        let error = Context::new(&auth, "sql.test", 1433).err().unwrap();
        assert!(matches!(
            error.kind,
            ErrorKind::Unsupported("system GSSAPI adapter is not built")
        ));
    }
}
