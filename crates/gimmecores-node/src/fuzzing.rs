//! Entry points for fuzzing everything that decodes bytes another device (or a lender's task
//! output) controls. Used by the `fuzz/` cargo-fuzz targets and by a stable smoke test; each
//! must never panic, whatever the input, and checks the invariants its callers rely on.
#![doc(hidden)]

use std::path::{Path, PathBuf};

use gimmecores_core::PeerKey;
use gimmecores_proto::peer::v1 as pb;
use prost::Message;

thread_local! {
    static RT: tokio::runtime::Runtime = tokio::runtime::Builder::new_current_thread()
        .build()
        .expect("a current-thread runtime");
}

/// Peer protocol frames, as read from a QUIC stream: length-prefixed `PeerMessage`s.
pub fn frames(data: &[u8]) {
    RT.with(|rt| {
        rt.block_on(async {
            let mut reader = data;
            for _ in 0..64 {
                match gimmecores_proto::framing::read_frame::<_, pb::PeerMessage>(&mut reader).await
                {
                    Ok(Some(msg)) => {
                        if let Some(body) = &msg.body {
                            let _ = crate::wire::kind(body);
                        }
                        // What we decode, we can encode again within the frame limit.
                        assert!(msg.encoded_len() <= gimmecores_proto::framing::MAX_FRAME_LEN);
                    }
                    Ok(None) | Err(_) => break,
                }
            }
        });
    });
}

/// A directory listing from a peer: unpacked on the lender, or returned as task outputs to the
/// borrower (which accepts only declared paths, within a size budget).
pub fn directory(data: &[u8]) {
    if let Ok(dir) = crate::tree::decode_dir(data) {
        for f in &dir.files {
            assert!(crate::tree::validate_output_path(&f.name).is_ok());
            assert!(!f.name.contains('/'));
        }
    }
    let declared = [PathBuf::from("out"), PathBuf::from(".gmc-out")];
    let mut budget = 1u64 << 30;
    let before = budget;
    if let Ok(level) = crate::tree::inspect_output_dir(Path::new(""), data, &declared, &mut budget)
    {
        assert!(budget <= before);
        for (p, _) in &level.files {
            assert!(declared.iter().any(|d| p.starts_with(d)), "{p:?} accepted");
        }
    }
}

/// A line of a package's RECORD (borrower side: decides what skips the secret scan).
pub fn record(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    for line in text.lines() {
        if let Some((path, _, _)) = crate::tree::record_line(line) {
            assert!(path.is_relative());
            assert!(
                !path
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir))
            );
        }
    }
}

/// A pairing ticket someone pasted.
pub fn ticket(data: &[u8]) {
    let _ = crate::wire::parse_ticket(&String::from_utf8_lossy(data));
}

/// A signed grant from a peer: must never verify unless signed by that lender for this device.
pub fn grant(data: &[u8]) {
    let Ok(signed) = pb::SignedGrant::decode(data) else {
        return;
    };
    let lender = PeerKey([7u8; 32]);
    let me = PeerKey([9u8; 32]);
    assert!(
        crate::grants_flow::verify_signed(&signed, &lender, &me).is_err(),
        "a grant verified without the lender's key"
    );
}

/// An mDNS advert from anyone on the network.
pub fn advert(data: &[u8]) {
    let text = String::from_utf8_lossy(data);
    let mut parts = text.splitn(3, '\n');
    let (a, b, c) = (parts.next(), parts.next(), parts.next());
    if let Some(crate::discovery::Advert::ReadyToPair { name, .. }) =
        crate::discovery::decode(a.unwrap_or(""), b, c)
    {
        assert!(name.chars().count() <= 64);
        assert!(!name.chars().any(char::is_control));
    }
}

/// Peer-supplied text shown to the user.
pub fn text(data: &[u8]) {
    let s = String::from_utf8_lossy(data);
    let clean = crate::wire::clean_text(&s, 64);
    assert!(clean.chars().count() <= 64);
    assert!(!clean.chars().any(|c| c.is_control() || c == '\u{202E}'));
    let _ = crate::secrets::scan_text(Path::new("f"), &s);
}

/// A fuzz entry point.
pub type Target = fn(&[u8]);

/// Every entry point, for the smoke test.
pub const ALL: &[(&str, Target)] = &[
    ("frames", frames),
    ("directory", directory),
    ("record", record),
    ("ticket", ticket),
    ("grant", grant),
    ("advert", advert),
    ("text", text),
];
