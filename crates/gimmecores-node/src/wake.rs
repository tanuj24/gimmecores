//! Wake-on-LAN between paired devices (#30), opt-in by the owner of the computer to be woken.
//!
//! The owner lets one paired device wake this computer (`gmc allow-wake <device> on`, with
//! presence, audited). From then on this computer's network card addresses (MACs, at most 4)
//! go to that device only, inside the encrypted `Hello` the two devices swap, and an empty
//! list tells it to forget them. That device sends the standard "magic packet" when it needs
//! this computer and cannot reach it: `gmc wake <device>`, or by itself before a task or a
//! grant request. Unpairing deletes the addresses on both sides.
//!
//! A magic packet carries no secret: anyone on the network who knows a card's address can
//! send one, and the address is visible on the local network anyway. What the opt-in limits
//! is which devices keep it, so a device carried to other networks does not hold this
//! computer's hardware identifier unless its owner allowed that. Waking only works where the
//! computer supports it (macOS: "Wake for network access"; often wired Ethernet only).

use std::net::{IpAddr, Ipv4Addr, SocketAddr, UdpSocket};
use std::time::Duration;

use anyhow::{Context, Result, bail};
use gimmecores_core::PeerKey;

use crate::node::Node;

/// At most this many addresses are sent or kept.
pub const MAX_MACS: usize = 4;

/// The port magic packets go to (the usual "discard" port).
const WOL_PORT: u16 = 9;

/// How long a borrower waits for a computer it woke to answer.
pub const WAKE_WAIT: Duration = Duration::from_secs(45);

/// "aa:bb:cc:dd:ee:ff" as bytes; anything else (or all zeros, all ones) is refused.
pub fn parse_mac(s: &str) -> Option<[u8; 6]> {
    let parts: Vec<&str> = s.split(':').collect();
    if parts.len() != 6 {
        return None;
    }
    let mut mac = [0u8; 6];
    for (b, p) in mac.iter_mut().zip(parts) {
        if p.len() != 2 {
            return None;
        }
        *b = u8::from_str_radix(p, 16).ok()?;
    }
    (mac != [0; 6] && mac != [0xff; 6]).then_some(mac)
}

fn format_mac(mac: [u8; 6]) -> String {
    mac.iter()
        .map(|b| format!("{b:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

/// Keeps only well-formed addresses, at most [`MAX_MACS`], normalised, sorted, without repeats.
pub fn clean_macs(macs: &[String]) -> Vec<String> {
    let mut v: Vec<String> = macs
        .iter()
        .filter_map(|m| parse_mac(m))
        .map(format_mac)
        .collect();
    v.sort();
    v.dedup();
    v.truncate(MAX_MACS);
    v
}

/// Six 0xFF bytes, then the address sixteen times.
pub fn magic_packet(mac: [u8; 6]) -> [u8; 102] {
    let mut p = [0xffu8; 102];
    for chunk in p[6..].chunks_mut(6) {
        chunk.copy_from_slice(&mac);
    }
    p
}

fn private_v4(ip: Ipv4Addr) -> bool {
    ip.is_private() || ip.is_link_local()
}

/// This computer's network cards that are up and on a local network: their addresses.
pub fn local_macs() -> Vec<String> {
    let macs: Vec<String> = netdev::get_interfaces()
        .into_iter()
        .filter(|i| i.is_up() && !i.is_loopback())
        .filter(|i| i.ipv4.iter().any(|n| private_v4(n.addr())))
        .filter_map(|i| i.mac_addr.map(|m| format_mac(m.octets())))
        .collect();
    clean_macs(&macs)
}

/// Where to send: everywhere on the local network (255.255.255.255) and the broadcast address
/// of each of this computer's local networks, the one `near` is on first.
fn targets(near: Option<IpAddr>) -> Vec<SocketAddr> {
    let mut out = vec![SocketAddr::from((Ipv4Addr::BROADCAST, WOL_PORT))];
    let mut nets: Vec<(bool, Ipv4Addr)> = if_addrs::get_if_addrs()
        .unwrap_or_default()
        .into_iter()
        .filter(|i| !i.is_loopback())
        .filter_map(|i| match i.addr {
            if_addrs::IfAddr::V4(v4) if private_v4(v4.ip) => {
                let mask = u32::from(v4.netmask);
                let on = match near {
                    Some(IpAddr::V4(n)) => u32::from(n) & mask == u32::from(v4.ip) & mask,
                    _ => false,
                };
                let bcast = v4
                    .broadcast
                    .unwrap_or(Ipv4Addr::from(u32::from(v4.ip) | !mask));
                Some((on, bcast))
            }
            _ => None,
        })
        .collect();
    nets.sort_by_key(|(on, _)| !on);
    for (_, b) in nets {
        let a = SocketAddr::from((b, WOL_PORT));
        if !out.contains(&a) {
            out.push(a);
        }
    }
    out
}

/// Sends magic packets for `macs` (three rounds). Returns how many were sent.
pub fn send_magic(macs: &[String], near: Option<IpAddr>) -> Result<usize> {
    let macs: Vec<[u8; 6]> = macs.iter().filter_map(|m| parse_mac(m)).collect();
    if macs.is_empty() {
        bail!("no network card address to wake");
    }
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).context("opening a UDP socket")?;
    socket.set_broadcast(true)?;
    let mut sent = 0;
    for _ in 0..3 {
        for mac in &macs {
            let p = magic_packet(*mac);
            for t in targets(near) {
                if socket.send_to(&p, t).is_ok() {
                    sent += 1;
                }
            }
        }
    }
    if sent == 0 {
        bail!("could not send a wake-up on this network");
    }
    Ok(sent)
}

impl Node {
    /// This computer's owner lets `peer` wake it, or stops letting it (saved, audited). Allowing
    /// needs presence; stopping never does. The peer is told at once when it can be reached,
    /// otherwise the next time the two devices talk.
    pub async fn set_wake_allowed(&self, peer: &PeerKey, allowed: bool) -> Result<()> {
        let name = self.peer_name(peer);
        if allowed && !self.wake_allowed(peer) {
            self.require_presence(&format!(
                "let {name:?} wake this computer from sleep (it receives this computer's network \
                 card addresses)"
            ))
            .await?;
        }
        self.state().trust.set_wake_allowed(peer, allowed)?;
        self.audit_best_effort(
            "trust",
            Some(peer),
            if allowed {
                format!("{name} may wake this computer (Wake-on-LAN)")
            } else {
                format!("{name} may no longer wake this computer")
            },
            serde_json::json!({ "wake_allowed": allowed }),
        );
        let (node, peer) = (self.clone(), *peer);
        tokio::spawn(async move {
            if let Ok(conn) = node.dial(&peer).await {
                node.exchange_hello(&peer, &conn).await;
            }
        });
        Ok(())
    }

    /// This computer's owner lets `peer` wake it.
    pub fn wake_allowed(&self, peer: &PeerKey) -> bool {
        self.state().trust.get(peer).is_some_and(|p| p.wake_allowed)
    }

    /// `peer` let this device wake it: its network card addresses, if any.
    pub fn wake_macs(&self, peer: &PeerKey) -> Vec<String> {
        self.state()
            .trust
            .get(peer)
            .map(|p| p.wake_macs.clone())
            .unwrap_or_default()
    }

    /// What this computer tells `peer` in a Hello: its addresses only if the owner allows it.
    pub(crate) fn wake_macs_for(&self, peer: &PeerKey) -> Vec<String> {
        if self.wake_allowed(peer) {
            local_macs()
        } else {
            Vec::new()
        }
    }

    /// Sends `peer` a wake-up, if it let this device wake it.
    pub fn wake(&self, peer: &PeerKey) -> Result<usize> {
        let macs = self.wake_macs(peer);
        if macs.is_empty() {
            bail!(
                "{:?} has not let this device wake it (its owner can: `gmc allow-wake <this \
                 device> on` there)",
                self.peer_name(peer)
            );
        }
        let near = self
            .state()
            .trust
            .get(peer)
            .and_then(|p| p.last_addrs.first().map(SocketAddr::ip));
        let sent = send_magic(&macs, near)?;
        self.audit_best_effort(
            "trust",
            Some(peer),
            format!("sent a wake-up to {}", self.peer_name(peer)),
            serde_json::json!({}),
        );
        Ok(sent)
    }

    /// Connects to `peer`; if it does not answer and it let this device wake it, wakes it and
    /// tries again for up to [`WAKE_WAIT`].
    pub(crate) async fn dial_waking(&self, peer: &PeerKey) -> Result<iroh::endpoint::Connection> {
        let first = match self.dial(peer).await {
            Ok(c) => return Ok(c),
            Err(e) => e,
        };
        if self.wake_macs(peer).is_empty() || self.wake(peer).is_err() {
            return Err(first);
        }
        let deadline = tokio::time::Instant::now() + WAKE_WAIT;
        loop {
            tokio::time::sleep(Duration::from_secs(3)).await;
            match self.dial(peer).await {
                Ok(c) => return Ok(c),
                Err(e) if tokio::time::Instant::now() >= deadline => {
                    return Err(e.context("woke it (Wake-on-LAN), but it did not answer"));
                }
                Err(_) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_magic_packet_is_six_ff_then_the_address_sixteen_times() {
        let mac = [0x00, 0x1b, 0x63, 0x84, 0x45, 0xe6];
        let p = magic_packet(mac);
        assert_eq!(&p[..6], &[0xff; 6]);
        for i in 0..16 {
            assert_eq!(&p[6 + i * 6..12 + i * 6], &mac);
        }
    }

    #[test]
    fn only_well_formed_addresses_are_kept() {
        assert_eq!(
            parse_mac("00:1B:63:84:45:E6"),
            Some([0, 0x1b, 0x63, 0x84, 0x45, 0xe6])
        );
        for bad in [
            "",
            "00:1b:63:84:45",
            "00:1b:63:84:45:e6:00",
            "0:1b:63:84:45:e6",
            "zz:1b:63:84:45:e6",
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad}");
        }
        let many: Vec<String> = (1..=9).map(|i| format!("02:00:00:00:00:0{i}")).collect();
        let mut sent = many.clone();
        sent.push("02:00:00:00:00:01".into());
        sent.push("not a mac".into());
        let kept = clean_macs(&sent);
        assert_eq!(kept.len(), MAX_MACS);
        assert_eq!(kept[0], "02:00:00:00:00:01");
    }

    #[test]
    fn packets_go_to_the_whole_local_network_first() {
        let t = targets(None);
        assert_eq!(t[0], SocketAddr::from((Ipv4Addr::BROADCAST, WOL_PORT)));
        assert!(t.iter().all(|a| a.port() == WOL_PORT));
    }
}
