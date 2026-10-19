//! A prepared bulk load borrows its channel. Completion and explicit abort
//! await server proof; Drop performs no protocol I/O and revokes the transport.
use super::*;
use crate::{
    FetchedResponse, Row, RowSource,
    requests::{bulk, rows},
    tokens::Column,
};

/// Owns the gap between INSERT BULK and its data. It cannot outlive its channel
/// or let an ordinary exchange pass through that exclusive borrow.
///
/// ```compile_fail
/// # async fn example(ch: &mut tds_client::SerialChannel, columns: Vec<tds_client::tokens::Column>) -> tds_client::Result<()> {
/// let writer = ch.bulk("INSERT BULK t(a int)", columns).await?;
/// ch.exchange(tds_client::Batch::new("SELECT 1")).await?;
/// writer.abort().await?;
/// # Ok(()) }
/// ```
#[must_use = "Finish or explicitly abort this prepared bulk load; Drop discards the connection"]
pub struct BulkWriter<'a> {
    channel: &'a mut SerialChannel,
    columns: Vec<Column>,
    epoch: u64,
    finished: bool,
}
impl SerialChannel {
    /// The application writes INSERT BULK and supplies matching server column
    /// metadata. No SQL is generated or transaction boundary introduced.
    pub async fn bulk(
        &mut self,
        sql: impl Into<String>,
        columns: Vec<Column>,
    ) -> Result<BulkWriter<'_>> {
        rows::bulk_header(
            &columns,
            columns.iter().any(|c| c.type_info.encryption.is_some()),
        )?; // Refuse unencodable metadata before preparation.
        let mut guard = Abandon::for_epoch(self.endpoint.clone(), self.endpoint.epoch());
        let result = match self.exchange(bulk::Begin(sql.into())).await {
            Ok(mut response) => response.finish().await,
            Err(error) => Err(error),
        };
        if result.is_ok() || !self.life.pending_bulk.load(Ordering::Acquire) {
            guard.disarm();
        }
        result?;
        Ok(BulkWriter {
            epoch: self.endpoint.epoch(),
            channel: self,
            columns,
            finished: false,
        })
    }
}
impl BulkWriter<'_> {
    /// Validate all owned rows before their first packet, then await completion.
    /// A failed local encoding still cancels the already-prepared continuation.
    pub async fn finish(mut self, rows: Vec<Row>) -> Result<FetchedResponse> {
        let request = bulk::Rows {
            columns: std::mem::take(&mut self.columns),
            rows,
        };
        self.send(request).await
    }
    /// Poll one unique row producer using the existing send/backpressure path.
    /// Cells are whole values. A producer failure is never retried.
    pub async fn finish_source(mut self, source: impl RowSource) -> Result<FetchedResponse> {
        let request = bulk::Stream {
            columns: std::mem::take(&mut self.columns),
            source: Box::new(source),
        };
        self.send(request).await
    }
    async fn send(mut self, request: impl Request + 'static) -> Result<FetchedResponse> {
        let result = match self.channel.exchange(request).await {
            Ok(mut response) => response.fetch().await,
            Err(error) => Err(error),
        };
        // Before the first data packet, a validation/producer error leaves the
        // prepared server operation intact. After IGNORE/drain it is already
        // gone. Consult the driver's announced continuation state, not a guess.
        let result = if self.channel.life.pending_bulk.load(Ordering::Acquire) {
            match result {
                Err(original) => match self.cancel_gap().await {
                    Ok(()) => Err(original),
                    Err(cleanup) => Err(Error::cleanup(original, cleanup)),
                },
                Ok(_) => Err(Error::new(ErrorKind::State(
                    "bulk completion left an unresolved continuation",
                ))),
            }
        } else {
            result
        };
        self.finished = !self.channel.life.pending_bulk.load(Ordering::Acquire);
        result
    }
    async fn cancel_gap(&mut self) -> Result<()> {
        self.channel.exchange(bulk::Abort).await?.close().await
    }
    /// Cancel preparation and await Attention acknowledgement within the normal
    /// cleanup budget. This does not commit/roll back an enclosing transaction.
    pub async fn abort(mut self) -> Result<()> {
        let result = self.cancel_gap().await;
        self.finished = result.is_ok();
        result
    }
}
impl Drop for BulkWriter<'_> {
    fn drop(&mut self) {
        if !self.finished && self.channel.life.pending_bulk.load(Ordering::Acquire) {
            self.channel.endpoint.revoke_epoch(self.epoch);
        }
    }
}
