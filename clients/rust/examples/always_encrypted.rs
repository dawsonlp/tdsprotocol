//! Requires a database with dbo.encrypted_demo(secret nvarchar(100) encrypted
//! with a CEK wrapped by the TDS_LOCAL_KEYS provider). Never print secret values.
use std::{env, fs, io};
use tds_client::{
    encryption::{LocalKeyStore, Policies},
    *,
};

#[tokio::main(flavor = "current_thread")]
async fn main() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let pem = fs::read(env::var("TDS_CA_FILE")?)?;
    let mut roots = rustls::RootCertStore::empty();
    for cert in rustls_pemfile::certs(&mut pem.as_slice()) {
        roots.add(cert?)?;
    }
    let mut options = ConnectOptions::new(
        env::var("TDS_HOST")?,
        env::var("TDS_PORT")?.parse()?,
        env::var("TDS_USER")?,
        env::var("TDS_PASSWORD")?,
        roots,
    );
    options.database = env::var("TDS_DATABASE")?;
    options.column_encryption = true;
    let connection = Connection::connect(options).await?;
    let collation = Collation(
        connection
            .session()
            .await?
            .collation
            .try_into()
            .map_err(|_| io::Error::other("server collation missing"))?,
    );
    let encrypted = connection
        .encrypted(
            vec![LocalKeyStore::new(
                "TDS_LOCAL_KEYS",
                env::var("TDS_KEY_DIR")?,
            )?],
            Policies::default(),
        )
        .await?;
    let mut channel = encrypted.serial_channel().await?;
    channel
        .exchange(Transaction::Begin(Default::default()))
        .await?
        .finish()
        .await?;
    channel
        .execute(
            "INSERT dbo.encrypted_demo(secret) VALUES (@secret)",
            "@secret nvarchar(100)",
            vec![Param::new(
                "@secret",
                SqlType::Character {
                    length: 100,
                    varying: true,
                    unicode: true,
                    collation,
                },
                Some(Value::Unicode(env::var("TDS_VALUE")?.as_str().into())),
            )],
        )
        .await?
        .finish()
        .await?;
    let fetched = channel
        .exchange(Batch::new("SELECT secret FROM dbo.encrypted_demo"))
        .await?
        .fetch()
        .await?;
    println!("Read {} rows", fetched.result_sets()[0].rows()?.len());
    channel
        .exchange(Transaction::Commit(Default::default()))
        .await?
        .finish()
        .await?;
    channel.close().await?;
    encrypted.close().await;
    connection.close().await?;
    Ok(())
}
