//! Sending and receiving `PeerMessage` frames on QUIC streams.

use anyhow::{Result, anyhow, bail};
use gimmecores_core::MessageKind;
use gimmecores_proto::framing::{read_frame, write_frame};
use gimmecores_proto::peer::v1::{
    Error as WireError, PeerMessage, error::Code, peer_message::Body,
};
use iroh::endpoint::{RecvStream, SendStream};

pub async fn send(stream: &mut SendStream, body: Body) -> Result<()> {
    write_frame(stream, &PeerMessage { body: Some(body) }).await?;
    Ok(())
}

/// Reads the next message body; an `Error` from the peer becomes an `Err`.
pub async fn recv(stream: &mut RecvStream) -> Result<Body> {
    let msg: Option<PeerMessage> = read_frame(stream).await?;
    match msg.and_then(|m| m.body) {
        Some(Body::Error(e)) => bail!("peer refused: {} ({:?})", e.message, Code::try_from(e.code)),
        Some(body) => Ok(body),
        None => Err(anyhow!("stream closed")),
    }
}

pub async fn send_error(stream: &mut SendStream, code: Code, message: &str) -> Result<()> {
    send(
        stream,
        Body::Error(WireError {
            code: code as i32,
            message: message.to_string(),
        }),
    )
    .await?;
    stream.finish()?;
    Ok(())
}

/// Classifies a message for the admission gate (threat model I2).
pub fn kind(body: &Body) -> MessageKind {
    match body {
        Body::Hello(_) => MessageKind::Hello,
        Body::PairRequest(_)
        | Body::PairChallenge(_)
        | Body::PairReveal(_)
        | Body::PairConfirm(_) => MessageKind::Pairing,
        Body::Unpair(_) => MessageKind::Unpair,
        Body::LinkTestRequest(_) | Body::LinkTestResponse(_) => MessageKind::LinkTest,
        Body::GrantRequest(_)
        | Body::GrantOffer(_)
        | Body::GrantAccept(_)
        | Body::GrantDecline(_)
        | Body::GrantRevoke(_)
        | Body::GrantState(_) => MessageKind::Grant,
        Body::FindMissing(_) | Body::Missing(_) | Body::BlobChunk(_) | Body::BlobGet(_) => {
            MessageKind::Blob
        }
        Body::SubmitTask(_) | Body::TaskEvent(_) | Body::CancelTask(_) => MessageKind::Task,
        Body::Error(_) => MessageKind::Hello,
    }
}

/// Peer-supplied text shown to the user (names, request reasons, notifications): drops control
/// characters and the invisible format characters (bidi overrides, zero-width joiners, ...)
/// that can make text display as something else; keeps at most `max` characters.
pub fn clean_text(raw: &str, max: usize) -> String {
    let invisible = |c: char| {
        c.is_control()
            || matches!(c, '\u{200B}'..='\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2060}'..='\u{2069}' | '\u{FEFF}' | '\u{061C}')
    };
    raw.chars().filter(|c| !invisible(*c)).take(max).collect()
}

/// Peer-supplied display text: printable characters only, at most 64 of them.
pub fn clean_name(raw: &str) -> String {
    let cleaned = clean_text(raw, 64);
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "Unnamed device".to_string()
    } else {
        trimmed.to_string()
    }
}

pub fn nonce32(bytes: &[u8]) -> Result<[u8; 32]> {
    bytes
        .try_into()
        .map_err(|_| anyhow!("expected 32 bytes, got {}", bytes.len()))
}

pub fn random32() -> Result<[u8; 32]> {
    let mut b = [0u8; 32];
    getrandom::fill(&mut b).map_err(|e| anyhow!("OS random generator failed: {e}"))?;
    Ok(b)
}

/// Parses a pairing ticket `gmc1:<key-hex>@<ip:port>[,<ip:port>…]`.
pub fn parse_ticket(ticket: &str) -> Result<iroh::EndpointAddr> {
    let rest = ticket
        .trim()
        .strip_prefix("gmc1:")
        .ok_or_else(|| anyhow!("not a GimmeCores pairing ticket"))?;
    let (key, addrs) = rest
        .split_once('@')
        .ok_or_else(|| anyhow!("ticket has no address"))?;
    let key: [u8; 32] = hex::decode(key)?
        .try_into()
        .map_err(|_| anyhow!("ticket key must be 32 bytes"))?;
    let pk = iroh::PublicKey::from_bytes(&key)?;
    // Skip addresses this machine cannot use rather than rejecting the whole ticket.
    let addrs: Vec<_> = addrs
        .split(',')
        .filter_map(|a| a.parse::<std::net::SocketAddr>().ok())
        .map(iroh::TransportAddr::Ip)
        .collect();
    anyhow::ensure!(!addrs.is_empty(), "ticket has no usable address");
    Ok(iroh::EndpointAddr::from_parts(pk, addrs))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_lose_control_and_invisible_format_characters() {
        assert_eq!(clean_name("Laptop\n\u{202E}kcatta"), "Laptopkcatta");
        assert_eq!(clean_name("a\u{200B}b\u{FEFF}"), "ab");
        assert_eq!(clean_name("\u{2066}\u{2069}  "), "Unnamed device");
        assert_eq!(clean_name(&"x".repeat(100)).len(), 64);
    }
}
