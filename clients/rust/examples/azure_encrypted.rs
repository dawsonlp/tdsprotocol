//! Explicit service-principal configuration. Compiles without contacting Azure.
//! Run only with your own endpoint, CA, existing encrypted schema and SQL.
use std::{env, fs::File, io::BufReader, sync::Arc, time::Duration};
use tds_client::{
    ConnectOptions, Connection, EnclaveAttestation,
    encryption::{Policies, keyvault::AzureKeyVaultKeyStore},
    entra::{
        EntraLogin,
        azure::{AzureTokenProvider, azure_identity},
    },
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut roots = rustls::RootCertStore::empty();
    let mut ca = BufReader::new(File::open(env::var("TDS_CA_FILE")?)?);
    for certificate in rustls_pemfile::certs(&mut ca) {
        roots.add(certificate?)?;
    }
    let credential = azure_identity::ClientSecretCredential::new(
        &env::var("AZURE_TENANT_ID")?,
        env::var("AZURE_CLIENT_ID")?,
        env::var("AZURE_CLIENT_SECRET")?.into(),
        None,
    )?;
    // SDK credential/cache buffers have SDK ownership. Comparable identity
    // settings contain labels, not the secret or the credential object.
    let mut options = ConnectOptions::entra(
        env::var("TDS_HOST")?,
        1433,
        EntraLogin::deferred(
            "service-principal",
            env::var("TDS_IDENTITY_LABEL")?,
            tds_client::fedauth::Workflow::Password,
        ),
        Arc::new(AzureTokenProvider::new(credential.clone())),
        roots,
    );
    options.database = env::var("TDS_DATABASE")?;
    options.column_encryption = true;
    if env::var("TDS_ENCLAVE_NONE").as_deref() == Ok("1") {
        // Explicit trust in the server's enclave; no attestation verification.
        options.enclave_attestation = Some(EnclaveAttestation::None);
    }
    let connection = Connection::connect(options).await?;
    let encrypted = connection
        .encrypted_with_providers(
            vec![Arc::new(AzureKeyVaultKeyStore::new(credential))],
            Policies::default(),
            Duration::from_secs(30),
        )
        .await?;
    let mut channel = encrypted.serial_channel().await?;
    let fetched = channel
        .execute(&env::var("TDS_SQL")?, "", vec![])
        .await?
        .fetch()
        .await?;
    println!("{} result sets", fetched.result_sets().len());
    channel.close().await?;
    encrypted.close().await;
    connection.close().await?;
    Ok(())
}
