//! Spike: two LAN-only endpoints on loopback (no relay, no address publishing, no port mapping).

use std::time::Duration;

use anyhow::{Context, Result, ensure};
use gimmecores_net::{PEER_ALPN, lan_only_endpoint};
use iroh::{SecretKey, TransportAddr};

fn key(seed: u8) -> SecretKey {
    SecretKey::from_bytes(&[seed; 32])
}

#[tokio::test]
async fn hello_round_trip_with_mutual_authentication() -> Result<()> {
    let lender = lan_only_endpoint(key(1), "127.0.0.1:0".parse()?).await?;
    let borrower = lan_only_endpoint(key(2), "127.0.0.1:0".parse()?).await?;

    // The lender's address must contain only direct IP addresses: no relay URL.
    let lender_addr = lender.addr();
    ensure!(
        lender_addr
            .addrs
            .iter()
            .all(|a| matches!(a, TransportAddr::Ip(_))),
        "LAN-only endpoint advertised a non-IP (relay) address: {:?}",
        lender_addr.addrs
    );

    let borrower_id = borrower.id();
    let server = tokio::spawn(async move {
        let incoming = lender.accept().await.context("endpoint closed")?;
        let conn = incoming.await?;
        // Mutual authentication: the lender sees the borrower's real public key.
        ensure!(conn.remote_id() == borrower_id, "unexpected remote id");
        let (mut send, mut recv) = conn.accept_bi().await?;
        let msg = recv.read_to_end(1024).await?;
        send.write_all(&[b"ack:".as_slice(), &msg].concat()).await?;
        send.finish()?;
        conn.closed().await;
        lender.close().await;
        anyhow::Ok(())
    });

    let conn = tokio::time::timeout(
        Duration::from_secs(10),
        borrower.connect(lender_addr.clone(), PEER_ALPN),
    )
    .await
    .context("connect timed out")??;
    ensure!(
        conn.remote_id() == lender_addr.id,
        "dialed key does not match"
    );
    let (mut send, mut recv) = conn.open_bi().await?;
    send.write_all(b"hello").await?;
    send.finish()?;
    let reply = recv.read_to_end(1024).await?;
    assert_eq!(reply, b"ack:hello");

    conn.close(0u32.into(), b"done");
    server.await??;
    borrower.close().await;
    Ok(())
}

#[tokio::test]
async fn wrong_alpn_is_refused() -> Result<()> {
    let lender = lan_only_endpoint(key(3), "127.0.0.1:0".parse()?).await?;
    let stranger = lan_only_endpoint(key(4), "127.0.0.1:0".parse()?).await?;
    let addr = lender.addr();

    // Keep accepting so the handshake can be processed (and rejected).
    let accept = tokio::spawn(async move {
        if let Some(incoming) = lender.accept().await {
            let _ = incoming.await;
        }
        lender
    });

    let result = tokio::time::timeout(
        Duration::from_secs(10),
        stranger.connect(addr, b"not-gimmecores/1"),
    )
    .await;
    ensure!(
        matches!(result, Ok(Err(_))),
        "connection with a foreign ALPN must fail, got {result:?}"
    );

    stranger.close().await;
    accept.abort();
    Ok(())
}

#[tokio::test]
async fn endpoint_listens_only_on_the_requested_address() -> Result<()> {
    let ep = lan_only_endpoint(key(5), "127.0.0.1:0".parse()?).await?;
    let sockets = ep.bound_sockets();
    ensure!(!sockets.is_empty(), "no socket bound");
    ensure!(
        sockets.iter().all(|s| s.ip().is_loopback()),
        "endpoint also listens beyond loopback: {sockets:?}"
    );
    ep.close().await;
    Ok(())
}
