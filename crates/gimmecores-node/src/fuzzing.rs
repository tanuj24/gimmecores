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

/// The lender, the borrower and a grant the lender really signed, for the `grant` target.
pub fn signed_grant_seed() -> (iroh::SecretKey, PeerKey, pb::SignedGrant) {
    let lender = iroh::SecretKey::from_bytes(&[5u8; 32]);
    let me = PeerKey([9u8; 32]);
    let grant = pb::Grant {
        lender_key: lender.public().as_bytes().to_vec(),
        borrower_key: me.0.to_vec(),
        grant_id: vec![1; 16],
        ..Default::default()
    }
    .encode_to_vec();
    let signed = crate::grants_flow::sign_grant_bytes(&lender, grant);
    (lender, me, signed)
}

/// A signed grant from a peer: verifies only if it is exactly what the lender signed, for this
/// device (any other bytes, signature or borrower fail).
pub fn grant(data: &[u8]) {
    let Ok(signed) = pb::SignedGrant::decode(data) else {
        return;
    };
    let (lender, me, real) = signed_grant_seed();
    let lender_key = PeerKey(*lender.public().as_bytes());
    if crate::grants_flow::verify_signed(&signed, &lender_key, &me).is_ok() {
        assert_eq!(signed.grant, real.grant, "a changed grant verified");
    }
    // Never for another device, or from another lender.
    assert!(crate::grants_flow::verify_signed(&signed, &lender_key, &PeerKey([8u8; 32])).is_err());
    assert!(crate::grants_flow::verify_signed(&signed, &PeerKey([7u8; 32]), &me).is_err());
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
    // Commands, labels and image names from another device.
    let argv: Vec<String> = s.split('\0').map(str::to_owned).collect();
    let shown = crate::activity::show_command(&argv);
    assert!(shown.args.len() <= crate::activity::SHOWN_ARGS);
    assert_eq!(shown.args.len(), shown.hidden_at.len());
    for (a, hidden) in shown.args.iter().zip(&shown.hidden_at) {
        // Hidden or not, nothing shown is longer than its cut, and nothing is raw.
        let max = if *hidden {
            32 + 2 + crate::activity::HIDDEN.chars().count()
        } else {
            crate::activity::SHOWN_CHARS + 1
        };
        assert!(a.chars().count() <= max, "{a:?}");
        assert!(
            !a.chars()
                .any(|c| c.is_control() || c == '\u{202E}' || c == '\u{2028}')
        );
    }
    if let Some(label) = crate::activity::show_label(&s) {
        assert!(label.chars().count() <= crate::activity::SHOWN_CHARS + 1);
    }
    if crate::activity::validate_image(&s).is_ok() {
        assert!(s.len() <= 255 && s.is_ascii());
    }
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
