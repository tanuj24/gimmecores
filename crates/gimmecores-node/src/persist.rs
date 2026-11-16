//! Grants survive a daemon restart.
//!
//! `grants.json` (owner-only) holds the *signed* grants: those this device gave (as lender) and
//! those it holds (as borrower). On start each one is verified again (the lender's own
//! signature for lent grants, so editing the file cannot enlarge a grant) and dropped if it
//! expired, its device is no longer paired, or (lent grants) lending is off. Lent grants keep
//! only the ways of running tasks still lent. Running tasks are not restored.
//!
//! The file is rewritten right after every change that reduces access (revoke, expiry, stop,
//! unpair, lending off), so a revoked grant cannot come back after a restart except in the
//! instant between the revoke and the write (both happen before the call returns).

use anyhow::{Context, Result};
use gimmecores_core::{GrantId, GrantState, PeerKey};
use gimmecores_proto::peer::v1 as pb;
use prost::Message;
use serde::{Deserialize, Serialize};

use crate::grants_flow::{Borrowed, terms_from_grant, verify_signed};
use crate::node::Node;
use crate::now;

#[derive(Default, Serialize, Deserialize)]
struct File {
    version: u32,
    #[serde(default)]
    lent: Vec<Lent>,
    #[serde(default)]
    borrowed: Vec<Held>,
    /// Lent grants already renewed by a standing grant (hex ids): each is renewed once.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    renewed: Vec<String>,
}

#[derive(Serialize, Deserialize)]
struct Lent {
    /// Hex of the encoded `SignedGrant`.
    signed: String,
}

#[derive(Serialize, Deserialize)]
struct Held {
    lender: String,
    signed: String,
}

fn decode_signed(hex_str: &str) -> Result<pb::SignedGrant> {
    Ok(pb::SignedGrant::decode(
        hex::decode(hex_str).context("bad hex")?.as_slice(),
    )?)
}

impl Node {
    /// Writes the live grants to disk. Failure is logged, never fatal: grants then simply do
    /// not survive a restart (the safe direction).
    pub(crate) fn save_grants(&self) {
        let t = now();
        let file = {
            let s = self.state();
            let lent = s
                .grants
                .list()
                .into_iter()
                .filter(|(_, _, state, terms, _)| {
                    matches!(state, GrantState::Active | GrantState::Paused) && terms.not_after > t
                })
                .filter_map(|(id, ..)| s.issued.get(&id))
                .map(|signed| Lent {
                    signed: hex::encode(signed.encode_to_vec()),
                })
                .collect();
            let borrowed = s
                .borrowed
                .values()
                .filter(|b| b.terms.not_after > t)
                .map(|b| Held {
                    lender: b.lender.to_hex(),
                    signed: hex::encode(b.signed.encode_to_vec()),
                })
                .collect();
            // Only grants still lent need remembering.
            let renewed = s
                .renewed
                .iter()
                .filter(|id| s.issued.contains_key(id))
                .map(|id| hex::encode(id.0))
                .collect();
            File {
                version: 1,
                lent,
                borrowed,
                renewed,
            }
        };
        let result = serde_json::to_vec_pretty(&file)
            .map_err(anyhow::Error::from)
            .and_then(|data| crate::fsutil::write_private(&self.paths().grants_file(), &data));
        if let Err(e) = result {
            // Fail closed: an old file could still hold a grant just revoked. Without it,
            // grants simply do not survive a restart.
            let _ = std::fs::remove_file(self.paths().grants_file());
            tracing::warn!("could not save grants (saved grants removed): {e:#}");
        }
    }

    /// Restores saved grants (called once at start, before any connection is accepted).
    pub(crate) fn load_grants(&self) -> Result<()> {
        let path = self.paths().grants_file();
        if !path.exists() {
            return Ok(());
        }
        crate::fsutil::check_private(&path)?;
        let file: File = serde_json::from_slice(&std::fs::read(&path)?)?;
        let (me, t) = (self.key(), now());
        let lending = self.lending_enabled();
        let lent_modes = self.lend_modes().0;
        let (mut restored, mut dropped) = (0usize, 0usize);
        {
            let mut s = self.state();
            for r in &file.renewed {
                if let Ok(Ok(id)) = hex::decode(r).map(|b| <[u8; 16]>::try_from(b.as_slice())) {
                    s.renewed.insert(GrantId(id));
                }
            }
        }
        for l in file.lent {
            let ok = (|| -> Result<bool> {
                let signed = decode_signed(&l.signed)?;
                let grant = pb::Grant::decode(signed.grant.as_slice())?;
                let borrower = PeerKey(
                    grant
                        .borrower_key
                        .as_slice()
                        .try_into()
                        .context("bad borrower key")?,
                );
                // Our own signature: the file cannot grant more than we signed.
                let grant = verify_signed(&signed, &me, &borrower)?;
                let mut terms = terms_from_grant(&grant)?;
                terms.modes = terms.modes.intersect(lent_modes);
                if !lending || !self.is_paired(&borrower) || terms.modes.is_empty() {
                    return Ok(false);
                }
                if terms.trust == gimmecores_core::TrustLevel::Trusted
                    && !self.is_trusted(&borrower)
                {
                    return Ok(false); // Trusted mode was turned off or lapsed
                }
                let id = GrantId(grant.grant_id.as_slice().try_into().context("bad id")?);
                let mut s = self.state();
                if s.grants.restore(id, borrower, terms, t).is_err() {
                    return Ok(false);
                }
                s.issued.insert(id, signed);
                Ok(true)
            })();
            match ok {
                Ok(true) => restored += 1,
                _ => dropped += 1,
            }
        }
        for h in file.borrowed {
            let ok = (|| -> Result<bool> {
                let lender = PeerKey(
                    hex::decode(&h.lender)?
                        .as_slice()
                        .try_into()
                        .context("bad lender key")?,
                );
                let signed = decode_signed(&h.signed)?;
                let grant = verify_signed(&signed, &lender, &me)?;
                let terms = terms_from_grant(&grant)?;
                if terms.not_after <= t || !self.is_paired(&lender) {
                    return Ok(false);
                }
                if terms.trust == gimmecores_core::TrustLevel::Trusted && !self.is_trusted(&lender)
                {
                    return Ok(false);
                }
                let id = GrantId(grant.grant_id.as_slice().try_into().context("bad id")?);
                self.state().borrowed.insert(
                    id,
                    Borrowed {
                        lender,
                        terms,
                        signed,
                    },
                );
                Ok(true)
            })();
            match ok {
                Ok(true) => restored += 1,
                _ => dropped += 1,
            }
        }
        if restored + dropped > 0 {
            self.audit_best_effort(
                "grant",
                None,
                format!("after restart: {restored} grant(s) restored, {dropped} dropped"),
                serde_json::json!({ "restored": restored, "dropped": dropped }),
            );
        }
        self.save_grants();
        Ok(())
    }
}
