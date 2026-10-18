//! Pool ownership, cancellation and protocol return through a controlled TLS peer.
#![cfg(feature = "tokio")]
mod support;
use std::{sync::Arc, time::Duration};
use support::{Peer, done, listener};
use tds_client::{
    Batch, ErrorKind, Pool, ReleaseOutcome, Step,
    mars::{self, Frame},
    packet,
};
const VERSION: u32 = 0x74000004;
async fn deadline<F: std::future::Future>(future: F) -> F::Output {
    tokio::time::timeout(Duration::from_secs(5), future)
        .await
        .expect("pool test deadline")
}
fn database(name: &str) -> Vec<u8> {
    let mut body = vec![1, name.len() as u8];
    body.extend(name.encode_utf16().flat_map(u16::to_le_bytes));
    body.push(0);
    let mut bytes = vec![0xe3];
    bytes.extend((body.len() as u16).to_le_bytes());
    bytes.extend(body);
    bytes
}
#[tokio::test]
async fn explicit_release_resets_once_and_revokes_old_channels_and_controls() {
    deadline(async {
        let (listener, options) = listener().await;
        let server = tokio::spawn(async move {
            let mut peer = Peer::login(listener).await;
            peer.message().await;
            assert_eq!(peer.message_status & 8, 0);
            let mut response = database("changed");
            response.extend(done(0));
            peer.reply(&response).await;
            peer.message().await;
            assert_eq!(peer.message_status & 8, 8);
            let mut response = vec![0xe3, 3, 0, 18, 0, 0];
            response.extend(done(0));
            peer.reply(&response).await;
            peer.message().await;
            assert_eq!(peer.message_status & 8, 0);
            peer.reply(&done(0)).await;
            peer.drain_to_eof().await;
        });
        let pool = Pool::new(options, 1).unwrap();
        assert_eq!(pool.idle(), 0);
        let lease = pool.acquire().await.unwrap();
        let baseline = lease.session().await.unwrap();
        let mut old = lease.serial_channel().await.unwrap();
        let old_close = lease.close_handle();
        let channel_close = old.close_handle();
        let mut response = old.exchange(Batch::new("first")).await.unwrap();
        let cancel = response.cancel_handle();
        response.finish().await.unwrap();
        drop(response);
        assert_eq!(
            lease.session().await.unwrap().database.to_string().unwrap(),
            "changed"
        );
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
        assert_eq!((pool.in_use(), pool.idle()), (0, 1));
        let next = pool.acquire().await.unwrap();
        assert!(old.exchange(Batch::new("must not send")).await.is_err());
        old_close.close();
        channel_close.close().await.unwrap();
        cancel.cancel();
        assert!(!next.is_closed());
        let mut ch = next.serial_channel().await.unwrap();
        ch.exchange(Batch::new("reset"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert_eq!(next.session().await.unwrap().database, baseline.database);
        ch.exchange(Batch::new("no second reset"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        assert_eq!(next.release().await.unwrap(), ReleaseOutcome::Returned);
        pool.close().await.unwrap();
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn saturation_canceled_waiters_and_drop_release_capacity_without_reuse() {
    deadline(async {
        let (listener, options) = listener().await;
        let server = tokio::spawn(async move {
            Peer::login_next(&listener, VERSION, false)
                .await
                .drain_to_eof()
                .await;
            Peer::login_next(&listener, VERSION, false)
                .await
                .drain_to_eof()
                .await;
        });
        let pool = Pool::new(options, 1).unwrap();
        let lease = pool.acquire().await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(20), pool.acquire())
                .await
                .is_err()
        );
        assert_eq!((pool.in_use(), pool.idle()), (1, 0));
        drop(lease);
        assert_eq!((pool.in_use(), pool.idle()), (0, 0));
        let next = pool.acquire().await.unwrap();
        assert_eq!(pool.in_use(), 1);
        pool.close().await.unwrap();
        assert!(!next.is_closed());
        assert_eq!(next.release().await.unwrap(), ReleaseOutcome::Discarded);
        assert!(pool.acquire().await.is_err());
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn dirty_return_discards_instead_of_draining_an_active_exchange() {
    deadline(async {
        let (listener, options) = listener().await;
        let server = tokio::spawn(async move {
            let mut peer = Peer::login_next(&listener, VERSION, false).await;
            peer.message().await;
            peer.drain_to_eof().await;
            Peer::login_next(&listener, VERSION, false)
                .await
                .drain_to_eof()
                .await;
        });
        let pool = Pool::new(options, 1).unwrap();
        let lease = pool.acquire().await.unwrap();
        let mut ch = lease.serial_channel().await.unwrap();
        let mut response = ch.exchange(Batch::new("still running")).await.unwrap();
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Discarded);
        assert_eq!(pool.idle(), 0);
        assert!(response.next().await.is_err());
        drop(response);
        let next = pool.acquire().await.unwrap();
        drop(next);
        pool.close().await.unwrap();
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn canceled_opening_and_failed_login_do_not_leak_reservations() {
    deadline(async {
        let (listener, options) = listener().await;
        let pool = Arc::new(Pool::new(options, 1).unwrap());
        let (accepted, waiting) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.unwrap();
            accepted.send(()).unwrap();
            let mut bytes = [0; 16384];
            use tokio::io::AsyncReadExt;
            while socket.read(&mut bytes).await.unwrap() != 0 {}
            Peer::login_next(&listener, 0x73000003, false)
                .await
                .drain_to_eof()
                .await;
            Peer::login_next(&listener, VERSION, false)
                .await
                .drain_to_eof()
                .await;
        });
        let opener = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire().await })
        };
        waiting.await.unwrap();
        opener.abort();
        assert!(opener.await.err().unwrap().is_cancelled());
        assert_eq!(pool.in_use(), 0);
        let error = pool.acquire().await.err().unwrap();
        assert!(matches!(
            error.cause().kind,
            ErrorKind::Unsupported("server TDS version")
        ));
        assert_eq!(pool.in_use(), 0);
        let next = pool.acquire().await.unwrap();
        drop(next);
        pool.close().await.unwrap();
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn shutdown_wakes_waiters_and_refuses_a_login_that_finishes_late() {
    deadline(async {
        let (listener, options) = listener().await;
        let pool = Arc::new(Pool::new(options, 1).unwrap());
        let (accepted, waiting) = tokio::sync::oneshot::channel();
        let (continue_login, go) = tokio::sync::oneshot::channel();
        let server = tokio::spawn(async move {
            let (socket, _) = listener.accept().await.unwrap();
            accepted.send(()).unwrap();
            go.await.unwrap();
            // Shutdown cancels an in-flight handshake rather than waiting for
            // this peer to finish it. Drain its already-written TLS flight.
            use tokio::io::AsyncReadExt;
            let mut socket = socket;
            let mut bytes = [0; 16384];
            while socket.read(&mut bytes).await.unwrap() != 0 {}
        });
        let opener = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire().await })
        };
        waiting.await.unwrap();
        let waiter = {
            let pool = pool.clone();
            tokio::spawn(async move { pool.acquire().await })
        };
        pool.close().await.unwrap();
        let error = waiter.await.unwrap().err().unwrap();
        assert_eq!(error.step, Step::Pool);
        continue_login.send(()).unwrap();
        assert!(opener.await.unwrap().is_err());
        assert_eq!((pool.in_use(), pool.idle()), (0, 0));
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn unresolved_mars_fin_times_out_or_canceled_return_discards_both_endpoints() {
    for cancel_return in [false, true] {
        deadline(async {
        let (listener,mut options)=listener().await;options.mars=true;options.cleanup_timeout=Duration::from_millis(50);
        let (fin_sent,fin_seen)=tokio::sync::oneshot::channel();
        let server=tokio::spawn(async move {
            let mut peer=Peer::login_next(&listener,VERSION,true).await;
            assert_eq!(peer.frame().await.flags,mars::SYN);assert_eq!(peer.frame().await.flags,mars::FIN);
            fin_sent.send(()).unwrap();peer.drain_to_eof().await;
            Peer::login_next(&listener,VERSION,true).await.drain_to_eof().await;
        });
        let pool=Pool::new(options,1).unwrap();let lease=pool.acquire().await.unwrap();let old_channel=lease.serial_channel().await.unwrap();
        let mut returning=Box::pin(lease.release());
        tokio::select! {biased; _=&mut returning=>panic!("FIN must be acknowledged"), _=fin_seen=>{}}
        if cancel_return {drop(returning);} else {let error=returning.await.unwrap_err();assert!(matches!(error.cause().kind,ErrorKind::Timeout));}
        drop(old_channel);assert_eq!((pool.in_use(),pool.idle()),(0,0));
        let next=pool.acquire().await.unwrap();drop(next);pool.close().await.unwrap();server.await.unwrap();
    }).await;
    }
}

#[tokio::test]
async fn completed_mars_fin_allows_reuse_with_a_new_authority_endpoint() {
    deadline(async {
        let (listener, mut options) = listener().await;
        options.mars = true;
        let server = tokio::spawn(async move {
            let mut peer = Peer::login_mars(listener).await;
            let syn = peer.frame().await;
            assert_eq!((syn.flags, syn.channel), (mars::SYN, 0));
            let fin = peer.frame().await;
            assert_eq!(fin.flags, mars::FIN);
            peer.send_frame(Frame {
                flags: mars::FIN,
                channel: 0,
                sequence: 0,
                window: 4,
                body: vec![],
            })
            .await;
            let syn = peer.frame().await;
            assert_eq!((syn.flags, syn.channel), (mars::SYN, 1));
            let data = peer.frame().await;
            assert_eq!(data.body[1] & 8, 8);
            let mut reply = vec![0xe3, 3, 0, 18, 0, 0];
            reply.extend(done(0));
            peer.send_frame(Frame {
                flags: mars::DATA,
                channel: 1,
                sequence: 1,
                window: 4,
                body: packet::split(packet::REPLY, &reply, 4096).unwrap(),
            })
            .await;
            peer.drain_to_eof().await;
        });
        let pool = Pool::new(options, 1).unwrap();
        let lease = pool.acquire().await.unwrap();
        let _old = lease.serial_channel().await.unwrap();
        assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Returned);
        let next = pool.acquire().await.unwrap();
        next.serial_channel()
            .await
            .unwrap()
            .exchange(Batch::new("reset"))
            .await
            .unwrap()
            .finish()
            .await
            .unwrap();
        drop(next);
        pool.close().await.unwrap();
        server.await.unwrap();
    })
    .await;
}

#[tokio::test]
async fn failed_response_cleanup_discards_and_a_new_borrower_gets_a_new_login() {
    for mars_enabled in [false, true] {
        deadline(async {
            let (listener, mut options) = listener().await;
            options.mars = mars_enabled;
            options.cleanup_timeout = Duration::from_millis(50);
            let server = tokio::spawn(async move {
                let mut peer = Peer::login_next(&listener, VERSION, mars_enabled).await;
                if mars_enabled {
                    assert_eq!(peer.frame().await.flags, mars::SYN);
                    assert_eq!(peer.frame().await.body[0], packet::BATCH);
                    assert_eq!(peer.frame().await.body[0], packet::ATTENTION);
                } else {
                    assert_eq!(peer.message().await.0, packet::BATCH);
                    assert_eq!(peer.message().await.0, packet::ATTENTION);
                }
                peer.drain_to_eof().await;
                Peer::login_next(&listener, VERSION, mars_enabled)
                    .await
                    .drain_to_eof()
                    .await;
            });
            let pool = Pool::new(options, 1).unwrap();
            let lease = pool.acquire().await.unwrap();
            let mut channel = lease.serial_channel().await.unwrap();
            let response = channel
                .exchange(Batch::new("no acknowledgement"))
                .await
                .unwrap();
            let error = response.close().await.unwrap_err();
            let ErrorKind::Cleanup { cleanup, .. } = error.kind else {
                panic!("cleanup pair")
            };
            assert!(matches!(cleanup.cause().kind, ErrorKind::Timeout));
            assert_eq!(lease.release().await.unwrap(), ReleaseOutcome::Discarded);
            assert_eq!(pool.idle(), 0);
            let fresh = pool.acquire().await.unwrap();
            drop(fresh);
            pool.close().await.unwrap();
            server.await.unwrap();
        })
        .await;
    }
}
