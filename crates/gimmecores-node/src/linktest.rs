//! Link test (docs/design/links-and-performance.md): real round-trip time and encrypted
//! throughput between two paired devices, plus which kind of link carries the traffic.
//!
//! Wire use of `LinkTestRequest.id` (one mode per stream):
//! - `0` ping: answered immediately with an empty `LinkTestResponse`;
//! - `1` upload: the sender streams payload frames, finishes, and gets one response whose `id`
//!   is the number of bytes received;
//! - `2` download: `payload` holds a big-endian u64 byte count (max 64 MiB) that the lender
//!   streams back in 1 MiB `LinkTestResponse` frames.

use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use gimmecores_core::PeerKey;
use gimmecores_proto::peer::v1 as pb;
use gimmecores_proto::peer::v1::peer_message::Body;
use iroh::endpoint::{RecvStream, SendStream};

use crate::node::Node;
use crate::{now, wire};

const PINGS: usize = 30;
const CHUNK: usize = 1 << 20;
const MAX_DOWNLOAD: u64 = 64 << 20;
const PHASE: Duration = Duration::from_secs(2);

#[derive(Clone, Debug)]
pub struct LinkStats {
    /// wifi, ethernet, thunderbolt, loopback or other
    pub interface: String,
    pub rtt_min: Duration,
    pub rtt_median: Duration,
    pub rtt_p95: Duration,
    pub upload_bps: u64,
    pub download_bps: u64,
    pub measured_at: u64,
    pub good_for: Vec<&'static str>,
}

impl LinkStats {
    pub fn to_proto(&self) -> gimmecores_proto::local::v1::LinkStats {
        let d = |d: Duration| prost_types::Duration {
            seconds: i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
            nanos: i32::try_from(d.subsec_nanos()).unwrap_or(0),
        };
        gimmecores_proto::local::v1::LinkStats {
            interface_kind: self.interface.clone(),
            rtt_min: Some(d(self.rtt_min)),
            rtt_median: Some(d(self.rtt_median)),
            rtt_p95: Some(d(self.rtt_p95)),
            upload_bits_per_second: self.upload_bps,
            download_bits_per_second: self.download_bps,
            measured_at: Some(prost_types::Timestamp {
                seconds: i64::try_from(self.measured_at).unwrap_or(i64::MAX),
                nanos: 0,
            }),
            good_for: self.good_for.iter().map(|s| (*s).to_string()).collect(),
        }
    }
}

/// What a link is good for (thresholds from links-and-performance.md).
pub fn good_for(rtt_median: Duration, bps: u64) -> Vec<&'static str> {
    if bps >= 5_000_000_000 && rtt_median < Duration::from_millis(1) {
        vec!["builds", "tests", "containers", "model sharding"]
    } else if bps >= 500_000_000 && rtt_median < Duration::from_millis(5) {
        vec!["builds", "tests", "containers"]
    } else {
        vec!["whole jobs with small or cached inputs"]
    }
}

/// Which local interface traffic to `remote` leaves through (no packet is sent).
fn local_interface(remote: SocketAddr) -> Option<String> {
    let bind: SocketAddr = match remote.ip() {
        IpAddr::V4(_) => "0.0.0.0:0".parse().ok()?,
        IpAddr::V6(_) => "[::]:0".parse().ok()?,
    };
    let sock = UdpSocket::bind(bind).ok()?;
    sock.connect(remote).ok()?;
    let local = sock.local_addr().ok()?.ip();
    if_addrs::get_if_addrs()
        .ok()?
        .into_iter()
        .find(|i| i.ip() == local)
        .map(|i| {
            if i.is_loopback() {
                "lo".to_string()
            } else {
                i.name
            }
        })
}

/// Maps an interface name to wifi / ethernet / thunderbolt / loopback / other.
pub fn classify(ifname: &str, macos_ports: Option<&str>) -> &'static str {
    if ifname == "lo" || ifname.starts_with("lo0") {
        return "loopback";
    }
    if let Some(ports) = macos_ports {
        // `networksetup -listallhardwareports`: "Hardware Port: X" followed by "Device: name".
        let mut port = "";
        for line in ports.lines() {
            if let Some(p) = line.strip_prefix("Hardware Port: ") {
                port = p;
            } else if line.strip_prefix("Device: ") == Some(ifname) {
                let p = port.to_ascii_lowercase();
                return if p.contains("wi-fi") || p.contains("airport") {
                    "wifi"
                } else if p.contains("thunderbolt") {
                    "thunderbolt"
                } else if p.contains("ethernet") || p.contains("lan") || p.contains("usb") {
                    "ethernet"
                } else {
                    "other"
                };
            }
        }
        return "other";
    }
    if ifname.starts_with("thunderbolt") {
        "thunderbolt"
    } else if std::path::Path::new(&format!("/sys/class/net/{ifname}/wireless")).exists() {
        "wifi"
    } else if ifname.starts_with("en") || ifname.starts_with("eth") {
        "ethernet"
    } else {
        "other"
    }
}

async fn interface_kind(remote: Option<SocketAddr>) -> String {
    let Some(name) = remote.and_then(local_interface) else {
        return "other".into();
    };
    let ports = if cfg!(target_os = "macos") {
        tokio::process::Command::new("networksetup")
            .arg("-listallhardwareports")
            .output()
            .await
            .ok()
            .map(|o| String::from_utf8_lossy(&o.stdout).into_owned())
    } else {
        None
    };
    classify(&name, ports.as_deref()).to_string()
}

fn req(id: u64, payload: Vec<u8>) -> Body {
    Body::LinkTestRequest(pb::LinkTestRequest {
        id,
        payload,
        echo_payload: false,
    })
}

impl Node {
    /// Lender side of a link test stream.
    pub(crate) async fn handle_link_test(
        &self,
        first: pb::LinkTestRequest,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        match first.id {
            0 => {
                let mut next = Some(first);
                while next.take().is_some() {
                    wire::send(
                        &mut send,
                        Body::LinkTestResponse(pb::LinkTestResponse::default()),
                    )
                    .await?;
                    if let Ok(Body::LinkTestRequest(r)) = wire::recv(&mut recv).await {
                        next = Some(r);
                    }
                }
            }
            1 => {
                let mut total = first.payload.len() as u64;
                while let Ok(Body::LinkTestRequest(r)) = wire::recv(&mut recv).await {
                    total += r.payload.len() as u64;
                }
                wire::send(
                    &mut send,
                    Body::LinkTestResponse(pb::LinkTestResponse {
                        id: total,
                        payload: vec![],
                    }),
                )
                .await?;
            }
            2 => {
                let want = <[u8; 8]>::try_from(first.payload.as_slice())
                    .map(u64::from_be_bytes)
                    .unwrap_or(0)
                    .min(MAX_DOWNLOAD);
                let chunk = vec![0u8; CHUNK];
                let mut sent = 0u64;
                while sent < want {
                    let n = usize::try_from((want - sent).min(CHUNK as u64)).unwrap_or(CHUNK);
                    if wire::send(
                        &mut send,
                        Body::LinkTestResponse(pb::LinkTestResponse {
                            id: 2,
                            payload: chunk[..n].to_vec(),
                        }),
                    )
                    .await
                    .is_err()
                    {
                        break; // the tester stopped reading
                    }
                    sent += n as u64;
                }
            }
            _ => bail!("unknown link test mode"),
        }
        send.finish()?;
        send.stopped().await.ok();
        Ok(())
    }

    /// Measures the link to a paired device.
    pub async fn link_test(&self, peer: &PeerKey) -> Result<LinkStats> {
        let remote = self
            .state()
            .trust
            .get(peer)
            .and_then(|p| p.last_addrs.first().copied());
        let conn = self.dial(peer).await?;
        self.exchange_hello(peer, &conn).await;

        // Round-trip time.
        let (mut send, mut recv) = conn.open_bi().await?;
        let mut rtts = Vec::with_capacity(PINGS);
        for _ in 0..PINGS {
            let t = Instant::now();
            wire::send(&mut send, req(0, vec![])).await?;
            match wire::recv(&mut recv).await? {
                Body::LinkTestResponse(_) => rtts.push(t.elapsed()),
                _ => bail!("unexpected link test reply"),
            }
        }
        send.finish()?;
        rtts.sort();

        // Upload: stream for up to PHASE, then wait for the lender's byte count.
        let (mut send, mut recv) = conn.open_bi().await?;
        let payload = vec![0u8; CHUNK];
        let t = Instant::now();
        while t.elapsed() < PHASE {
            wire::send(&mut send, req(1, payload.clone())).await?;
        }
        send.finish()?;
        let received = match wire::recv(&mut recv).await? {
            Body::LinkTestResponse(r) => r.id,
            _ => bail!("unexpected link test reply"),
        };
        let upload_bps = bits_per_second(received, t.elapsed());

        // Download: ask for up to MAX_DOWNLOAD and read for at most PHASE.
        let (mut send, mut recv) = conn.open_bi().await?;
        wire::send(&mut send, req(2, MAX_DOWNLOAD.to_be_bytes().to_vec())).await?;
        send.finish()?;
        let t = Instant::now();
        let mut got = 0u64;
        while t.elapsed() < PHASE && got < MAX_DOWNLOAD {
            match tokio::time::timeout(PHASE, wire::recv(&mut recv)).await {
                Ok(Ok(Body::LinkTestResponse(r))) => got += r.payload.len() as u64,
                _ => break,
            }
        }
        let download_bps = bits_per_second(got, t.elapsed());
        drop(recv);
        conn.close(0u32.into(), b"link test done");

        let rtt_median = rtts[rtts.len() / 2];
        let stats = LinkStats {
            interface: interface_kind(remote).await,
            rtt_min: *rtts.first().context("no samples")?,
            rtt_median,
            rtt_p95: rtts[(rtts.len() * 95 / 100).min(rtts.len() - 1)],
            upload_bps,
            download_bps,
            measured_at: now(),
            good_for: good_for(rtt_median, upload_bps.min(download_bps)),
        };
        self.state().links.insert(*peer, stats.clone());
        Ok(stats)
    }
}

fn bits_per_second(bytes: u64, elapsed: Duration) -> u64 {
    let secs = elapsed.as_secs_f64().max(1e-6);
    (bytes as f64 * 8.0 / secs) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_follow_the_documented_thresholds() {
        let ms = Duration::from_millis;
        assert_eq!(
            good_for(ms(13), 180_000_000),
            ["whole jobs with small or cached inputs"]
        );
        assert_eq!(
            good_for(Duration::from_micros(300), 940_000_000),
            ["builds", "tests", "containers"]
        );
        assert_eq!(
            good_for(Duration::from_micros(300), 16_000_000_000),
            ["builds", "tests", "containers", "model sharding"]
        );
    }

    #[test]
    fn classifies_macos_hardware_ports() {
        let ports = "Hardware Port: Wi-Fi\nDevice: en0\nEthernet Address: x\n\nHardware Port: Thunderbolt Bridge\nDevice: bridge0\n\nHardware Port: USB 10/100/1000 LAN\nDevice: en7\n";
        assert_eq!(classify("en0", Some(ports)), "wifi");
        assert_eq!(classify("bridge0", Some(ports)), "thunderbolt");
        assert_eq!(classify("en7", Some(ports)), "ethernet");
        assert_eq!(classify("lo", Some(ports)), "loopback");
        assert_eq!(classify("utun3", Some(ports)), "other");
    }
}
