//! Finding devices on the local network (mDNS, `_gimmecores._udp`), without making this device
//! trackable (threat model, "Tracking the user across networks via mDNS").
//!
//! - **Paired devices only** (default): for each paired device, an advert whose name is a
//!   16-byte identifier only that device can recognise ([`rotating_id`], new every 15 minutes).
//!   No device name, no permanent key. When this device hears an identifier it recognises, it
//!   learns that peer's current addresses (an IP that changed is found again).
//! - **While pairing mode is open** (2 minutes, opened by the user): also an advert with this
//!   device's name and key, so a nearby device can pair without a ticket.
//! - **Off**: no adverts, no listening.
//!
//! An advert is only a hint: identity is proven by the key when connecting, so a spoofed advert
//! cannot impersonate a paired device.

use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use anyhow::Result;
use gimmecores_core::PeerKey;
use gimmecores_core::pairing::{ROTATION_SECONDS, rotating_id};
use mdns_sd::{IfKind, ServiceDaemon, ServiceEvent, ServiceInfo};

use crate::node::Node;
use crate::{now, wire};

pub const SERVICE: &str = "_gimmecores._udp.local.";
/// How long a "ready to pair" device stays listed after its last advert.
const NEARBY_TTL: Duration = Duration::from_secs(150);
const REFRESH: Duration = Duration::from_secs(20);

#[derive(Clone, Copy, Debug, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiscoveryMode {
    Off,
    PairedOnly,
}

/// A device advertising that it is ready to pair.
#[derive(Clone, Debug)]
pub struct Nearby {
    pub key: PeerKey,
    pub name: String,
    pub addrs: Vec<SocketAddr>,
    pub seen: Instant,
}

/// What an advert says, decoded.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Advert {
    /// A rotating identifier (paired devices only).
    Rotating([u8; 16]),
    /// A device in pairing mode.
    ReadyToPair { key: PeerKey, name: String },
}

/// Decodes an advert from its instance name and TXT properties.
pub fn decode(instance: &str, key: Option<&str>, name: Option<&str>) -> Option<Advert> {
    if let (Some(k), Some(n)) = (key, name) {
        let bytes: [u8; 32] = hex::decode(k).ok()?.try_into().ok()?;
        return Some(Advert::ReadyToPair {
            key: PeerKey(bytes),
            name: wire::clean_name(n),
        });
    }
    let id: [u8; 16] = hex::decode(instance).ok()?.try_into().ok()?;
    Some(Advert::Rotating(id))
}

/// Which paired peer (if any) advertised `id`, allowing one window of clock skew.
pub fn match_rotating(id: &[u8; 16], peers: &[(PeerKey, [u8; 32])], now: u64) -> Option<PeerKey> {
    let windows = [
        now.saturating_sub(ROTATION_SECONDS),
        now,
        now + ROTATION_SECONDS,
    ];
    peers
        .iter()
        .find(|(peer, k)| windows.iter().any(|t| rotating_id(k, peer, *t) == *id))
        .map(|(p, _)| *p)
}

/// At most this many addresses are remembered per peer.
pub const MAX_ADDRS: usize = 8;
/// At most this many "ready to pair" devices are listed.
pub const MAX_NEARBY: usize = 32;

/// Known addresses first (the ones that connected), then newly heard ones, deduplicated and
/// capped.
pub fn merge_addrs(known: &[SocketAddr], heard: &[SocketAddr]) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::new();
    for a in known.iter().chain(heard) {
        if !out.contains(a) && out.len() < MAX_ADDRS {
            out.push(*a);
        }
    }
    out
}

pub(crate) struct Mdns {
    daemon: ServiceDaemon,
    /// Instance name -> registered full name.
    registered: BTreeMap<String, String>,
    /// Random instance name for the pairing advert of the current pairing window.
    pairing_instance: Option<String>,
}

impl Node {
    /// Paired peers that share a discovery key with this device.
    fn discovery_keys(&self) -> Vec<(PeerKey, [u8; 32])> {
        let s = self.state();
        s.trust
            .list()
            .filter_map(|(k, p)| {
                let key: [u8; 32] = hex::decode(p.discovery_key.as_ref()?)
                    .ok()?
                    .try_into()
                    .ok()?;
                Some((*k, key))
            })
            .collect()
    }

    /// Devices nearby that are ready to pair (seen recently, not paired yet).
    pub fn nearby(&self) -> Vec<Nearby> {
        let mut s = self.state();
        s.nearby.retain(|_, n| n.seen.elapsed() < NEARBY_TTL);
        let paired: BTreeSet<PeerKey> = s.trust.list().map(|(k, _)| *k).collect();
        s.nearby
            .values()
            .filter(|n| !paired.contains(&n.key))
            .cloned()
            .collect()
    }

    fn advertised_addrs(&self) -> (Vec<IpAddr>, u16) {
        let addrs: Vec<SocketAddr> = self
            .addr()
            .ip_addrs()
            .copied()
            .filter(|a| match a.ip() {
                IpAddr::V4(_) => true,
                IpAddr::V6(v6) => (v6.segments()[0] & 0xffc0) != 0xfe80,
            })
            .collect();
        let port = addrs.first().map_or(0, SocketAddr::port);
        (addrs.iter().map(SocketAddr::ip).collect(), port)
    }

    fn start_mdns(&self) -> Result<Mdns> {
        let daemon = ServiceDaemon::new()?;
        if self.inner.bind.ip().is_loopback() {
            // Tests and local demos: never announce anything on a real network.
            daemon.disable_interface(IfKind::All)?;
            daemon.enable_interface(IfKind::LoopbackV4)?;
        } else {
            daemon.disable_interface(vec![IfKind::LoopbackV4, IfKind::LoopbackV6])?;
        }
        let events = daemon.browse(SERVICE)?;
        // A weak handle: the listener must not keep a stopped node (and its socket) alive.
        let weak = std::sync::Arc::downgrade(&self.inner);
        tokio::spawn(async move {
            while let Ok(ev) = events.recv_async().await {
                let Some(inner) = weak.upgrade() else { return };
                let node = Node { inner };
                if let ServiceEvent::ServiceResolved(r) = ev {
                    let instance = r
                        .fullname
                        .strip_suffix(&format!(".{SERVICE}"))
                        .unwrap_or(&r.fullname)
                        .to_string();
                    let port = r.get_port();
                    let addrs: Vec<SocketAddr> = r
                        .get_addresses()
                        .iter()
                        .map(|ip| SocketAddr::new(ip.to_ip_addr(), port))
                        .collect();
                    node.heard(
                        &instance,
                        r.get_property_val_str("k"),
                        r.get_property_val_str("n"),
                        addrs,
                    );
                }
            }
        });
        Ok(Mdns {
            daemon,
            registered: BTreeMap::new(),
            pairing_instance: None,
        })
    }

    fn heard(&self, instance: &str, key: Option<&str>, name: Option<&str>, addrs: Vec<SocketAddr>) {
        if addrs.is_empty() {
            return;
        }
        match decode(instance, key, name) {
            Some(Advert::ReadyToPair { key, name }) if key != self.key() => {
                let mut s = self.state();
                s.nearby.retain(|_, n| n.seen.elapsed() < NEARBY_TTL);
                if s.nearby.len() >= MAX_NEARBY && !s.nearby.contains_key(&key) {
                    return;
                }
                s.nearby.insert(
                    key,
                    Nearby {
                        key,
                        name,
                        addrs: addrs.into_iter().take(MAX_ADDRS).collect(),
                        seen: Instant::now(),
                    },
                );
            }
            Some(Advert::Rotating(id)) => {
                if let Some(peer) = match_rotating(&id, &self.discovery_keys(), now()) {
                    // Added as extra candidates, never replacing known addresses: anyone on the
                    // network can replay an advert, and must not be able to cut a peer off.
                    let mut s = self.state();
                    if let Some(known) = s.trust.get(&peer).map(|p| p.last_addrs.clone()) {
                        let merged = merge_addrs(&known, &addrs);
                        if merged != known {
                            let _ = s.trust.set_addrs(&peer, merged);
                        }
                    }
                }
            }
            _ => {}
        }
    }

    /// Brings the adverts in line with the mode, the paired devices and the pairing window.
    fn refresh_adverts(&self, m: &mut Mdns) {
        let (ips, port) = self.advertised_addrs();
        if ips.is_empty() || port == 0 {
            return;
        }
        let t = now();
        let mut wanted: BTreeMap<String, Vec<(String, String)>> = BTreeMap::new();
        for (peer, key) in self.discovery_keys() {
            let _ = peer;
            wanted.insert(hex::encode(rotating_id(&key, &self.key(), t)), vec![]);
        }
        let pairing_open = self.state().window.is_open(t);
        if pairing_open {
            let inst = m
                .pairing_instance
                .get_or_insert_with(|| {
                    format!(
                        "pair-{}",
                        hex::encode(&wire::random32().unwrap_or_default()[..6])
                    )
                })
                .clone();
            wanted.insert(
                inst,
                vec![
                    ("k".into(), self.key().to_hex()),
                    ("n".into(), self.inner.name.clone()),
                ],
            );
        } else {
            m.pairing_instance = None;
        }
        // Withdraw adverts no longer wanted (an old window, a closed pairing window).
        let stale: Vec<String> = m
            .registered
            .keys()
            .filter(|k| !wanted.contains_key(*k))
            .cloned()
            .collect();
        for inst in stale {
            if let Some(full) = m.registered.remove(&inst) {
                let _ = m.daemon.unregister(&full);
            }
        }
        for (inst, props) in wanted {
            if m.registered.contains_key(&inst) {
                continue;
            }
            // The host name is the instance name too: never this machine's real name.
            let host = format!("{inst}.local.");
            let props: Vec<(&str, &str)> = props
                .iter()
                .map(|(k, v)| (k.as_str(), v.as_str()))
                .collect();
            if let Ok(info) =
                ServiceInfo::new(SERVICE, &inst, &host, ips.as_slice(), port, &props[..])
                && m.daemon.register(info.clone()).is_ok()
            {
                m.registered.insert(inst, info.get_fullname().to_string());
            }
        }
    }

    /// Runs discovery for the life of the node, following the user's mode.
    pub(crate) async fn discovery_loop(self) {
        let weak = std::sync::Arc::downgrade(&self.inner);
        drop(self);
        let mut mdns: Option<Mdns> = None;
        loop {
            let Some(inner) = weak.upgrade() else {
                if let Some(m) = mdns {
                    let _ = m.daemon.shutdown();
                }
                return;
            };
            let node = Node { inner };
            match node.discovery_mode() {
                DiscoveryMode::Off => {
                    if let Some(m) = mdns.take() {
                        let _ = m.daemon.shutdown();
                    }
                    node.state().nearby.clear();
                }
                DiscoveryMode::PairedOnly => {
                    if mdns.is_none() {
                        match node.start_mdns() {
                            Ok(m) => mdns = Some(m),
                            Err(e) => tracing::warn!("local discovery unavailable: {e:#}"),
                        }
                    }
                    if let Some(m) = mdns.as_mut() {
                        node.refresh_adverts(m);
                    }
                }
            }
            let wake = node.inner.discovery_wake.clone();
            drop(node);
            tokio::select! {
                () = wake.notified() => {}
                () = tokio::time::sleep(REFRESH) => {}
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn adverts_decode_and_rotating_ids_match_only_their_peer() {
        let k = [7u8; 32];
        let peer = PeerKey([1; 32]);
        let other = PeerKey([2; 32]);
        let t = 1_800_000_000;
        let id = rotating_id(&k, &peer, t);
        assert_eq!(
            decode(&hex::encode(id), None, None),
            Some(Advert::Rotating(id))
        );
        let peers = [(other, [8u8; 32]), (peer, k)];
        assert_eq!(match_rotating(&id, &peers, t), Some(peer));
        assert_eq!(
            match_rotating(&id, &peers, t + ROTATION_SECONDS),
            Some(peer),
            "one window of clock skew"
        );
        assert_eq!(match_rotating(&id, &peers, t + 3 * ROTATION_SECONDS), None);
        assert_eq!(match_rotating(&id, &[(other, [8u8; 32])], t), None);
        let key_hex = hex::encode([3u8; 32]);
        assert_eq!(
            decode("pair-abc", Some(&key_hex), Some("Studio\n\u{202e}x")),
            Some(Advert::ReadyToPair {
                key: PeerKey([3; 32]),
                name: "Studiox".into()
            })
        );
        assert_eq!(decode("not-hex", None, None), None);
    }

    #[test]
    fn heard_addresses_never_replace_known_ones() {
        let a: SocketAddr = "192.168.1.5:47474".parse().unwrap();
        let b: SocketAddr = "10.0.0.9:47474".parse().unwrap();
        assert_eq!(merge_addrs(&[a], &[b]), [a, b]);
        assert_eq!(merge_addrs(&[a], &[a]), [a]);
        let many: Vec<SocketAddr> = (0..20)
            .map(|i| SocketAddr::from(([10, 0, 0, i], 1)))
            .collect();
        let m = merge_addrs(&[a], &many);
        assert_eq!(m.len(), MAX_ADDRS);
        assert_eq!(m[0], a, "the known address stays first");
    }
}
