//! SQL orchestration composes the existing borrowed channel and key service.
use super::*;
use crate::{
    Batch, Builtin, Call, Connection, ErrorKind, FetchedResponse, Param, ParamValue, Record,
    Request, Response, SerialChannel, SqlType, Value, requests::CipherInfo, response::Retention,
    tokens::Column, types::crypto::CryptoMetadata,
};
use std::collections::BTreeMap;

/// One key owner attached to a connection's current physical epoch/pool lease.
/// Drop this adapter before releasing its pool lease. After explicit recovery,
/// drop it and wrap the new epoch; guards from the previous epoch fail closed.
pub struct EncryptedConnection<'a> {
    connection: &'a Connection,
    keys: KeySession,
    enclaves: bool,
    enclave_gate: tokio::sync::Mutex<()>,
}
impl Connection {
    /// The common key service accepts local, remote and native capabilities.
    pub async fn encrypted_with_providers(
        &self,
        providers: Vec<std::sync::Arc<dyn super::KeyProvider>>,
        policies: Policies,
        provider_timeout: std::time::Duration,
    ) -> crate::Result<EncryptedConnection<'_>> {
        let version = self
            .session()
            .await?
            .features
            .get(&4)
            .and_then(|v| v.first())
            .copied();
        if !matches!(version, Some(1 | 2)) {
            return Err(crate::Error::new(ErrorKind::Unsupported(
                "server did not agree Always Encrypted",
            )));
        }
        let keys = self
            .key_session_with_providers(providers, policies, provider_timeout)
            .await?;
        if version == Some(2) {
            keys.enable_enclaves();
        }
        let mut channel = self.serial_channel().await?;
        channel.exchange(Batch::new("")).await?.finish().await?;
        channel.close().await?;
        Ok(EncryptedConnection {
            connection: self,
            keys,
            enclaves: version == Some(2),
            enclave_gate: tokio::sync::Mutex::new(()),
        })
    }
    /// Attach local-key encryption to a connection opened with
    /// `ConnectOptions::column_encryption = true`. The empty bootstrap exchange
    /// completes a deferred pool reset before any parameter discovery or key use.
    pub async fn encrypted(
        &self,
        providers: Vec<LocalKeyStore>,
        policies: Policies,
    ) -> crate::Result<EncryptedConnection<'_>> {
        let version = self
            .session()
            .await?
            .features
            .get(&4)
            .and_then(|v| v.first())
            .copied();
        if !matches!(version, Some(1 | 2)) {
            return Err(crate::Error::new(ErrorKind::Unsupported(
                "server did not agree Always Encrypted",
            )));
        }
        let keys = self.key_session(providers, policies).await?;
        if version == Some(2) {
            keys.enable_enclaves();
        }
        let mut channel = self.serial_channel().await?;
        channel.exchange(Batch::new("")).await?.finish().await?;
        channel.close().await?;
        Ok(EncryptedConnection {
            connection: self,
            keys,
            enclaves: version == Some(2),
            enclave_gate: tokio::sync::Mutex::new(()),
        })
    }
}
impl EncryptedConnection<'_> {
    pub async fn serial_channel(&self) -> crate::Result<EncryptedChannel<'_>> {
        let collation = crate::Collation(
            self.connection
                .session()
                .await?
                .collation
                .try_into()
                .map_err(|_| Error::InvalidMetadata)?,
        );
        Ok(EncryptedChannel {
            channel: self.connection.serial_channel().await?,
            keys: &self.keys,
            collation,
            enclaves: self.enclaves,
            enclave_gate: &self.enclave_gate,
        })
    }
    /// Retire keys and current guards after an application-controlled provider,
    /// master-file or security-context change not announced by SQL Server.
    pub fn invalidate_keys(&self) {
        self.keys.invalidate();
    }
    pub fn statistics(&self) -> Statistics {
        self.keys.statistics()
    }
    pub fn set_policies(&mut self, policies: Policies) -> Result<()> {
        self.keys.set_policies(policies)
    }
    /// Revoke and await all in-flight provider work. Does not close the connection.
    pub async fn close(self) {
        self.keys.close().await;
    }
}
/// Raw protocol records stay in the original channel, observations and capture.
/// Only this adapter's returned records/snapshots hold authenticated SQL values.
pub struct EncryptedChannel<'a> {
    channel: SerialChannel,
    keys: &'a KeySession,
    collation: crate::Collation,
    enclaves: bool,
    enclave_gate: &'a tokio::sync::Mutex<()>,
}
impl EncryptedChannel<'_> {
    /// Read encrypted columns for any request. Parameters passed to this method
    /// must already be encoded; use `execute` for automatic input encryption.
    pub async fn exchange(
        &mut self,
        request: impl Request + 'static,
    ) -> crate::Result<EncryptedResponse<'_>> {
        self.exchange_with(request, None).await
    }
    /// Select retention for a read-only or already-prepared request.
    pub async fn exchange_with(
        &mut self,
        request: impl Request + 'static,
        policies: Option<Policies>,
    ) -> crate::Result<EncryptedResponse<'_>> {
        let guard = match policies {
            Some(p) => self.keys.exchange_with(p)?,
            None => self.keys.exchange()?,
        };
        let raw = self.channel.exchange(request).await?;
        Ok(EncryptedResponse::new(raw, guard, BTreeMap::new()))
    }
    /// Execute explicit SQL/declarations with named scalar parameters. Discover
    /// encryption freshly on this channel, then send exactly once. SQL is never
    /// replayed on an error. The declarations remain application-owned SQL.
    pub async fn execute(
        &mut self,
        statement: &str,
        declarations: &str,
        params: Vec<Param>,
    ) -> crate::Result<EncryptedResponse<'_>> {
        self.execute_with(statement, declarations, params, None)
            .await
    }
    /// Per-exchange policy selection; session defaults apply when `None`.
    pub async fn execute_with(
        &mut self,
        statement: &str,
        declarations: &str,
        params: Vec<Param>,
        policies: Option<Policies>,
    ) -> crate::Result<EncryptedResponse<'_>> {
        execute_attempt(
            &mut self.channel,
            Execute {
                keys: self.keys,
                collation: self.collation,
                enclaves: self.enclaves,
                enclave_gate: self.enclave_gate,
            },
            statement,
            declarations,
            params,
            policies,
            1,
        )
        .await
    }
    /// Encrypt owned rows before preparing the borrowed raw bulk continuation.
    /// Column metadata comes from SELECT TOP 0 on this encrypted connection.
    pub async fn bulk(
        &mut self,
        sql: impl Into<String>,
        columns: Vec<Column>,
        mut rows: Vec<crate::Row>,
    ) -> crate::Result<FetchedResponse> {
        let guard = self.keys.exchange()?;
        for row in &mut rows {
            if row.len() != columns.len() {
                return Err(crate::Error::new(ErrorKind::Parameter("bulk row width")));
            }
            for (column, value) in columns.iter().zip(row) {
                if let Some(how) = &column.type_info.encryption {
                    check(how)?;
                    if let Some(plain) = value {
                        let normalized = normalize::normalize(&how.base.sql_type, plain)?;
                        let key = how.key.as_ref().ok_or(Error::InvalidMetadata)?;
                        *value = Some(Value::Binary(
                            guard
                                .encrypt(key, normalized.as_bytes(), how.encryption_type == 2)
                                .await?,
                        ));
                    }
                } else {
                    column.type_info.sql_type.encode_parameter(value.as_ref())?;
                }
            }
        }
        let mut fetched = self.channel.bulk(sql, columns).await?.finish(rows).await?;
        if let Err(error) = decrypt_fetched(&mut fetched, &guard).await {
            return Err(crate::Error::from(error)
                .at(crate::Step::Exchange, crate::Execution::PossiblyExecuted)
                .with_response(fetched));
        }
        Ok(fetched)
    }
    pub async fn close(self) -> crate::Result<()> {
        self.channel.close().await
    }
}
#[derive(Clone, Copy)]
struct Execute<'a> {
    keys: &'a KeySession,
    collation: crate::Collation,
    enclaves: bool,
    enclave_gate: &'a tokio::sync::Mutex<()>,
}
async fn execute_attempt<'a>(
    channel: &'a mut SerialChannel,
    context: Execute<'_>,
    statement: &str,
    declarations: &str,
    mut params: Vec<Param>,
    policies: Option<Policies>,
    attempt: u8,
) -> crate::Result<EncryptedResponse<'a>> {
    // Validate every original value before discovery or any crypto work.
    let mut names = std::collections::BTreeSet::new();
    for param in &params {
        if param.use_default
            || param.cipher.is_some()
            || matches!(param.value, ParamValue::Table(_))
        {
            return Err(crate::Error::new(ErrorKind::Parameter(
                "encrypted execute requires ordinary named scalar parameters",
            )));
        }
        let _validated =
            zeroize::Zeroizing::new(param.sql_type.encode_parameter(param.value.as_ref())?);
        let name = param
            .name
            .to_string()
            .map_err(|_| crate::Error::new(ErrorKind::Parameter("parameter name UTF-16")))?;
        if name.is_empty() || !names.insert(name.to_lowercase()) {
            return Err(crate::Error::new(ErrorKind::Parameter(
                "encrypted execute requires named parameters",
            )));
        }
    }
    let guard = match policies {
        Some(p) => context.keys.exchange_with(p)?,
        None => context.keys.exchange()?,
    };
    let text_type = SqlType::CharacterMax {
        unicode: true,
        collation: context.collation,
    };
    let describe_gate = if context.enclaves {
        Some(context.enclave_gate.lock().await)
    } else {
        None
    };
    let attestation = if context.enclaves && !guard.has_enclave()? {
        Some(enclave::Attestation::new()?)
    } else {
        None
    };
    let mut describe = Call::new(
        "sp_describe_parameter_encryption",
        vec![
            Param::new(
                "",
                text_type.clone(),
                Some(Value::Unicode(statement.into())),
            ),
            Param::new(
                "",
                text_type.clone(),
                Some(Value::Unicode(declarations.into())),
            ),
        ],
    );
    if let Some(attestation) = &attestation {
        describe.params.push(Param::new(
            "",
            SqlType::Binary {
                length: 116,
                varying: true,
            },
            Some(Value::Binary(attestation.parameters().to_vec())),
        ));
    }
    // A describing exchange can fail after its own bytes were sent, but
    // the application's SQL has not been submitted at this point.
    let fetched = match channel.exchange(describe).await {
        Ok(mut response) => response.fetch().await,
        Err(error) => Err(error),
    }
    .map_err(|error| error.at(crate::Step::Exchange, crate::Execution::NotSent))?;
    let plan = parse_plan(&fetched, context.enclaves)?;
    if let Some(attestation) = attestation
        && let Some(info) = &plan.session
    {
        guard.establish_enclave(attestation, info.clone()).await?;
    }
    drop(describe_gate);
    let enclave_package = if plan.enclave.is_empty() {
        Vec::new()
    } else {
        guard.enclave_package(statement, &plan.enclave).await?
    };
    let retry_params = (!plan.enclave.is_empty() && attempt == 1).then(|| params.clone());
    let mut outputs = BTreeMap::new();
    for (index, param) in params.iter_mut().enumerate() {
        let name = param
            .name
            .to_string()
            .map_err(|_| Error::InvalidMetadata)?
            .to_lowercase();
        if let Some(how) = plan.params.get(&name) {
            let cipher = CipherInfo {
                base: param.sql_type.clone(),
                key: how.key.clone().ok_or(Error::InvalidMetadata)?,
                encryption_type: how.encryption_type,
                algorithm: how.algorithm,
                normalization: how.normalization,
            };
            check(how)?;
            param.value = ParamValue::Scalar(match param.value.as_ref() {
                None => None,
                Some(value) => {
                    let plain = normalize::normalize(&param.sql_type, value)?;
                    Some(Value::Binary(
                        guard
                            .encrypt(&cipher.key, plain.as_bytes(), how.encryption_type == 2)
                            .await?,
                    ))
                }
            });
            if param.output {
                outputs.insert(name.clone(), how.clone());
                outputs.insert(format!("#{}", index + 2), how.clone());
            }
            // SQL uses varbinary(max) for ciphertext whose length can exceed 8000.
            param.sql_type = match param.value.as_ref() {
                Some(Value::Binary(bytes)) if !param.output && bytes.len() <= 8000 => {
                    SqlType::Binary {
                        length: u16::try_from(bytes.len().max(1)).expect("bounded"),
                        varying: true,
                    }
                }
                None => SqlType::Binary {
                    length: 8000,
                    varying: true,
                },
                _ => SqlType::BinaryMax,
            };
            param.cipher = Some(cipher);
        }
    }
    let mut all = vec![
        Param::new(
            "@stmt",
            text_type.clone(),
            Some(Value::Unicode(statement.into())),
        ),
        Param::new(
            "@params",
            text_type,
            Some(Value::Unicode(declarations.into())),
        ),
    ];
    all.extend(params);
    let mut call = Call::new(Builtin::SpExecuteSql, all);
    call.enclave_package = enclave_package;
    let mut raw = channel.exchange(call).await?;
    let first = if retry_params.is_some() {
        raw.next().await?
    } else {
        None
    };
    if matches!(&first,Some(Record::Error(message)) if [206,33514,33195].contains(&message.number))
    {
        match raw.finish().await {
            Ok(()) => {}
            Err(error) if matches!(error.kind, ErrorKind::ServerErrors(_)) => {}
            Err(error) => return Err(error),
        }
        let channel = raw.into_finished_channel()?;
        drop(guard);
        context.keys.forget_enclave();
        return Box::pin(execute_attempt(
            channel,
            context,
            statement,
            declarations,
            retry_params.expect("eligible stale refusal"),
            policies,
            2,
        ))
        .await;
    }
    let mut response = EncryptedResponse::new(raw, guard, outputs);
    response.prefetched = first;
    Ok(response)
}
fn check(how: &CryptoMetadata) -> Result<()> {
    if how.algorithm != 2 || how.normalization != 1 || ![1, 2].contains(&how.encryption_type) {
        return Err(Error::InvalidMetadata);
    }
    Ok(())
}
fn integer(v: &Option<Value>) -> Result<u32> {
    match v {
        Some(Value::Integer(n)) => u32::try_from(*n).map_err(|_| Error::InvalidMetadata),
        _ => Err(Error::InvalidMetadata),
    }
}
fn string(v: &Option<Value>) -> Result<String> {
    match v {
        Some(Value::Unicode(s)) => s.to_string().map_err(|_| Error::InvalidMetadata),
        _ => Err(Error::InvalidMetadata),
    }
}
fn binary(v: &Option<Value>) -> Result<Vec<u8>> {
    match v {
        Some(Value::Binary(s)) => Ok(s.clone()),
        _ => Err(Error::InvalidMetadata),
    }
}
pub(super) struct EnclaveColumn {
    pub key: ColumnKey,
    pub signatures: Vec<(WrappedKey, Vec<u8>)>,
}
struct Plan {
    params: BTreeMap<String, CryptoMetadata>,
    enclave: Vec<EnclaveColumn>,
    session: Option<Vec<u8>>,
}
fn parse_plan(fetched: &FetchedResponse, enclaves: bool) -> Result<Plan> {
    let sets = fetched.result_sets();
    if sets.len() < 2 || (!enclaves && sets.len() != 2) {
        return Err(Error::InvalidMetadata);
    }
    let mut keys = BTreeMap::<u32, ColumnKey>::new();
    let mut signed = BTreeMap::<u32, Vec<(WrappedKey, Vec<u8>)>>::new();
    for row in sets[0].rows().map_err(|_| Error::InvalidMetadata)? {
        if row.len() < 9 {
            return Err(Error::InvalidMetadata);
        }
        let ordinal = integer(&row[0])?;
        let identity = ColumnKey {
            database_id: integer(&row[1])?,
            key_id: integer(&row[2])?,
            version: integer(&row[3])?,
            metadata_version: binary(&row[4])?
                .try_into()
                .map_err(|_| Error::InvalidMetadata)?,
            values: vec![],
        };
        let key = keys.entry(ordinal).or_insert(identity.clone());
        if key.database_id != identity.database_id
            || key.key_id != identity.key_id
            || key.version != identity.version
            || key.metadata_version != identity.metadata_version
        {
            return Err(Error::InvalidMetadata);
        }
        let wrapped = WrappedKey {
            encrypted: binary(&row[5])?,
            provider: string(&row[6])?,
            path: string(&row[7])?,
            algorithm: string(&row[8])?,
        };
        if enclaves
            && row.len() > 10
            && matches!(&row[9], Some(Value::Bit(true)) | Some(Value::Integer(1)))
        {
            let signature = if row[10].is_none() {
                Vec::new()
            } else {
                binary(&row[10])?
            };
            signed
                .entry(ordinal)
                .or_default()
                .push((wrapped.clone(), signature));
        }
        key.values.push(wrapped);
    }
    let mut plan = BTreeMap::new();
    for row in sets[1].rows().map_err(|_| Error::InvalidMetadata)? {
        if row.len() != 6 {
            return Err(Error::InvalidMetadata);
        }
        let kind = integer(&row[3])?;
        if kind == 0 {
            continue;
        }
        let key = keys
            .get(&integer(&row[4])?)
            .ok_or(Error::InvalidMetadata)?
            .clone();
        // Base type comes from the application declaration (output tokens carry
        // their independent server base type, which is checked on decryption).
        let encoded = SqlType::BinaryMax
            .encode_parameter(None)
            .map_err(|_| Error::InvalidMetadata)?;
        let base = crate::TypeInfo::read_parameter(&mut crate::wire::Reader::new(&encoded))
            .map_err(|_| Error::InvalidMetadata)?;
        let how = CryptoMetadata {
            base,
            user_type: 0,
            algorithm: u8::try_from(integer(&row[2])?).map_err(|_| Error::InvalidMetadata)?,
            algorithm_name: None,
            encryption_type: u8::try_from(kind).map_err(|_| Error::InvalidMetadata)?,
            normalization: u8::try_from(integer(&row[5])?).map_err(|_| Error::InvalidMetadata)?,
            key: Some(key),
        };
        check(&how)?;
        if plan.insert(string(&row[1])?.to_lowercase(), how).is_some() {
            return Err(Error::InvalidMetadata);
        }
    }
    let session = if sets.len() > 2 {
        let rows = sets[2].rows().map_err(|_| Error::InvalidMetadata)?;
        rows.first()
            .map(|row| binary(row.first().ok_or(Error::InvalidMetadata)?))
            .transpose()?
    } else {
        None
    };
    let enclave = signed
        .into_iter()
        .map(|(ordinal, signatures)| EnclaveColumn {
            key: keys[&ordinal].clone(),
            signatures,
        })
        .collect();
    Ok(Plan {
        params: plan,
        enclave,
        session,
    })
}

#[must_use = "consume or close the encrypted response"]
pub struct EncryptedResponse<'a> {
    raw: Response<'a>,
    guard: Option<KeyExchange>,
    columns: Vec<Column>,
    outputs: BTreeMap<String, CryptoMetadata>,
    retained: Retention,
    discarding: bool,
    prefetched: Option<Record>,
}
impl<'a> EncryptedResponse<'a> {
    fn new(
        raw: Response<'a>,
        guard: KeyExchange,
        outputs: BTreeMap<String, CryptoMetadata>,
    ) -> Self {
        Self {
            raw,
            guard: Some(guard),
            columns: vec![],
            outputs,
            retained: Retention::default(),
            discarding: false,
            prefetched: None,
        }
    }
    pub fn snapshot(&self) -> FetchedResponse {
        self.retained.record.clone()
    }
    pub fn timing(&self) -> crate::Timing {
        self.raw.timing()
    }
    pub fn cancel_handle(&self) -> crate::CancelHandle {
        self.raw.cancel_handle()
    }
    async fn read(&mut self) -> crate::Result<Option<Record>> {
        let result = self.read_inner().await;
        if let Err(original) = result {
            self.guard.take();
            let raw = self.raw.snapshot();
            self.retained.record.ended = raw.ended;
            self.retained.record.canceled = raw.canceled;
            self.retained.record.timing = raw.timing;
            self.raw.cancel_handle().cancel();
            let original = original
                .at(crate::Step::Exchange, crate::Execution::PossiblyExecuted)
                .with_response(self.snapshot());
            return match self.raw.finish().await {
                Ok(()) => Err(original),
                Err(cleanup) if matches!(cleanup.kind, ErrorKind::Canceled) => Err(original),
                Err(cleanup) => Err(crate::Error::cleanup(original, cleanup)),
            };
        }
        result.map_err(|e| e.with_response(self.snapshot()))
    }
    async fn read_inner(&mut self) -> crate::Result<Option<Record>> {
        let next = match self.prefetched.take() {
            Some(record) => Some(record),
            None => self.raw.next().await?,
        };
        let Some(mut record) = next else {
            self.guard.take();
            self.retained.end(self.raw.snapshot().canceled);
            self.retained.record.timing = self.raw.timing();
            return Ok(None);
        };
        match &mut record {
            Record::Columns(columns) => self.columns = columns.clone(),
            Record::Row(row) if !self.discarding => {
                for (column, value) in self.columns.iter().zip(row) {
                    if let Some(how) = &column.type_info.encryption {
                        decrypt(self.guard.as_ref().ok_or(Error::Closed)?, how, value, None)
                            .await?;
                    }
                }
            }
            Record::OutputValue(output) => {
                if let Some(how) = &output.type_info.encryption {
                    let name = output
                        .name
                        .to_string()
                        .map_err(|_| Error::InvalidMetadata)?
                        .to_lowercase();
                    let plan = self
                        .outputs
                        .get(&name)
                        .or_else(|| self.outputs.get(&format!("#{}", output.ordinal)));
                    decrypt(
                        self.guard.as_ref().ok_or(Error::Closed)?,
                        how,
                        &mut output.value,
                        plan,
                    )
                    .await?;
                }
            }
            _ => {}
        }
        self.retained.take(&record)?;
        Ok(Some(record))
    }
    pub async fn next(&mut self) -> crate::Result<Option<Record>> {
        if let Some(record) = self.retained.unread.pop_front() {
            return Ok(Some(record));
        }
        let record = self.read().await?;
        Ok(self.retained.unread.pop_front().or(record))
    }
    pub async fn fetch(&mut self) -> crate::Result<FetchedResponse> {
        self.discarding = false;
        self.retained.keep();
        while self.read().await?.is_some() {}
        Ok(self.snapshot())
    }
    pub async fn finish(&mut self) -> crate::Result<()> {
        self.discarding = true;
        self.retained.discard();
        while self.read().await?.is_some() {}
        Ok(())
    }
    pub async fn close(self) -> crate::Result<()> {
        self.raw.close().await
    }
}
async fn decrypt(
    guard: &KeyExchange,
    how: &CryptoMetadata,
    value: &mut Option<Value>,
    plan: Option<&CryptoMetadata>,
) -> Result<()> {
    let Some(Value::Encrypted(cipher)) = value else {
        return if value.is_none() {
            Ok(())
        } else {
            Err(Error::InvalidMetadata)
        };
    };
    let decoded = async {
        check(how)?;
        let key = how
            .key
            .as_ref()
            .or_else(|| plan.and_then(|p| p.key.as_ref()))
            .ok_or(Error::InvalidMetadata)?;
        if let Some(plan) = plan
            && (plan.algorithm != how.algorithm
                || plan.encryption_type != how.encryption_type
                || plan.normalization != how.normalization)
        {
            return Err(Error::InvalidMetadata);
        }
        let plaintext = guard.decrypt(key, &cipher.0).await?;
        normalize::denormalize(&how.base.sql_type, plaintext.as_bytes())
    }
    .await;
    match decoded {
        Ok(decoded) => *value = Some(decoded),
        Err(error @ (Error::Closed | Error::Expired)) => return Err(error),
        Err(error) => {
            *value = Some(Value::NotDecrypted {
                ciphertext: cipher.clone(),
                reason: error.to_string(),
            })
        }
    }
    Ok(())
}

// Bulk can return ordinary result sets as well as DONE. Its fetched response
// must cross the same authentication boundary as a streaming query response.
async fn decrypt_fetched(fetched: &mut FetchedResponse, guard: &KeyExchange) -> Result<()> {
    for set in &mut fetched.result_sets {
        if let Some(rows) = &mut set.kept {
            for row in rows {
                for (column, value) in set.columns.iter().zip(row) {
                    if let Some(how) = &column.type_info.encryption {
                        decrypt(guard, how, value, None).await?;
                    }
                }
            }
        }
    }
    for returned in &mut fetched.returns {
        for output in returned
            .outputs
            .iter_mut()
            .chain(returned.function_result.iter_mut())
        {
            if let Some(how) = &output.type_info.encryption {
                decrypt(guard, how, &mut output.value, None).await?;
            }
        }
    }
    for item in &mut fetched.sequence {
        if let crate::Item::OutputValue(output) = item
            && let Some(how) = &output.type_info.encryption
        {
            decrypt(guard, how, &mut output.value, None).await?;
        }
    }
    Ok(())
}
