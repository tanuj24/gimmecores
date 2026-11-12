//! Which peer messages are admitted before any grant check (threat model I2).

use crate::types::Denied;

/// Families of `PeerMessage` bodies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MessageKind {
    Hello,
    /// PairRequest / PairChallenge / PairReveal / PairConfirm.
    Pairing,
    Unpair,
    LinkTest,
    /// GrantRequest / Offer / Accept / Decline / Revoke / StateChanged.
    Grant,
    /// FindMissingBlobs / BlobChunk / BlobGet — also needs an active grant (I14).
    Blob,
    /// SubmitTask / CancelTask — also needs an active grant (I1).
    Task,
}

/// What this device knows about the sender's key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PeerStatus {
    Paired,
    Unpaired { pairing_open: bool },
}

/// First gate for every incoming message.
///
/// - Unpaired senders may only say Hello and run the pairing exchange, and only while the local
///   user has pairing mode open (I2).
/// - Paired senders may not restart pairing (unpair first).
/// - `Blob` and `Task` pass this gate but must then pass the grant book.
pub fn admit(kind: MessageKind, peer: PeerStatus) -> Result<(), Denied> {
    match peer {
        PeerStatus::Unpaired { pairing_open } => match kind {
            MessageKind::Hello | MessageKind::Pairing if pairing_open => Ok(()),
            MessageKind::Hello | MessageKind::Pairing => Err(Denied::PairingClosed),
            _ => Err(Denied::NotPaired),
        },
        PeerStatus::Paired => match kind {
            MessageKind::Pairing => Err(Denied::Invalid),
            _ => Ok(()),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ALL: [MessageKind; 7] = [
        MessageKind::Hello,
        MessageKind::Pairing,
        MessageKind::Unpair,
        MessageKind::LinkTest,
        MessageKind::Grant,
        MessageKind::Blob,
        MessageKind::Task,
    ];

    #[test]
    fn i2_unpaired_with_pairing_closed_can_do_nothing() {
        for kind in ALL {
            assert!(
                admit(
                    kind,
                    PeerStatus::Unpaired {
                        pairing_open: false
                    }
                )
                .is_err(),
                "{kind:?} admitted from an unpaired peer with pairing closed"
            );
        }
    }

    #[test]
    fn i2_unpaired_with_pairing_open_can_only_hello_and_pair() {
        for kind in ALL {
            let allowed = admit(kind, PeerStatus::Unpaired { pairing_open: true }).is_ok();
            let expected = matches!(kind, MessageKind::Hello | MessageKind::Pairing);
            assert_eq!(allowed, expected, "{kind:?}");
        }
    }

    #[test]
    fn paired_peers_cannot_restart_pairing() {
        assert_eq!(
            admit(MessageKind::Pairing, PeerStatus::Paired),
            Err(Denied::Invalid)
        );
        assert!(admit(MessageKind::Task, PeerStatus::Paired).is_ok());
    }
}
