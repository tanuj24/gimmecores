//! The running node: one iroh endpoint, an accept loop that admits every message before acting
//! on it, and the shared state used by the local API.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Context, Result, anyhow};
use gimmecores_core::pairing::{Confirmation, Initiator, PairingWindow, Responder, ShortCode};
use gimmecores_core::{GrantBook, PeerKey, PeerStatus, admit, pairing};
use gimmecores_net::{PEER_ALPN, lan_only_endpoint};
use gimmecores_proto::peer::v1::{
    Hello, PairChallenge, PairConfirm, PairRequest, PairReveal, error::Code, peer_message::Body,
};
use iroh::endpoint::{Connection, RecvStream, SendStream};
use iroh::{Endpoint, EndpointAddr};
use tokio::sync::oneshot;

use crate::identity::{FileKeyStore, KeyStore, peer_key};
use crate::paths::Paths;
use crate::trust::TrustList;
use crate::{now, wire};

pub const PROTOCOL_VERSION: u32 = 1;

pub struct NodeConfig {
    pub paths: Paths,
    pub device_name: String,
    pub bind: SocketAddr,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PairStatus {
    Waiting,
    CompareCode,
    Paired,
    Failed(String),
}

/// What the UI shows for a pairing in progress.
#[derive(Clone, Debug)]
pub struct PairingView {
    pub id: u64,
    pub peer: PeerKey,
    pub peer_name: String,
    pub code: Option<ShortCode>,
    pub status: PairStatus,
    pub name_previously_seen_with_other_key: bool,
}

struct Session {
    view: PairingView,
    decide: Option<oneshot::Sender<bool>>,
}

pub(crate) struct State {
    pub trust: TrustList,
    pub window: PairingWindow,
    pub grants: GrantBook,
    sessions: BTreeMap<u64, Session>,
    next_session: u64,
    pub(crate) incoming: BTreeMap<gimmecores_core::GrantId, crate::grants_flow::Pending>,
    pub(crate) borrowed: BTreeMap<gimmecores_core::GrantId, crate::grants_flow::Borrowed>,
}

pub(crate) struct Inner {
    pub endpoint: Endpoint,
    pub secret: iroh::SecretKey,
    pub me: PeerKey,
    pub name: String,
    pub paths: Paths,
    state: Mutex<State>,
}

/// A handle to the running node. Cheap to clone.
#[derive(Clone)]
pub struct Node {
    pub(crate) inner: Arc<Inner>,
}

impl Node {
    pub async fn start(cfg: NodeConfig) -> Result<Self> {
        cfg.paths.ensure()?;
        let secret = FileKeyStore::new(cfg.paths.identity_key()).load_or_create()?;
        let me = peer_key(&secret.public());
        let trust = TrustList::load(cfg.paths.peers_file())?;
        let endpoint = lan_only_endpoint(secret.clone(), cfg.bind).await?;
        let node = Node {
            inner: Arc::new(Inner {
                endpoint,
                secret,
                me,
                name: wire::clean_name(&cfg.device_name),
                paths: cfg.paths,
                state: Mutex::new(State {
                    trust,
                    window: PairingWindow::closed(),
                    grants: GrantBook::new(),
                    sessions: BTreeMap::new(),
                    next_session: 1,
                    incoming: BTreeMap::new(),
                    borrowed: BTreeMap::new(),
                }),
            }),
        };
        tokio::spawn(node.clone().accept_loop());
        Ok(node)
    }

    pub(crate) fn state(&self) -> MutexGuard<'_, State> {
        // A panic while holding the lock is a bug; keep serving with the last consistent state.
        self.inner.state.lock().unwrap_or_else(|p| p.into_inner())
    }

    pub fn key(&self) -> PeerKey {
        self.inner.me
    }

    pub fn name(&self) -> &str {
        &self.inner.name
    }

    pub fn addr(&self) -> EndpointAddr {
        self.inner.endpoint.addr()
    }

    pub fn paths(&self) -> &Paths {
        &self.inner.paths
    }

    pub fn is_paired(&self, peer: &PeerKey) -> bool {
        self.state().trust.is_paired(peer)
    }

    pub fn paired_peers(&self) -> Vec<(PeerKey, String)> {
        self.state()
            .trust
            .list()
            .map(|(k, p)| (*k, p.name.clone()))
            .collect()
    }

    pub async fn shutdown(&self) {
        self.inner.endpoint.close().await;
    }

    fn peer_status(&self, peer: &PeerKey) -> PeerStatus {
        let s = self.state();
        if s.trust.is_paired(peer) {
            PeerStatus::Paired
        } else {
            PeerStatus::Unpaired {
                pairing_open: s.window.is_open(now()),
            }
        }
    }

    // ------------------------------------------------------------------ accept loop

    async fn accept_loop(self) {
        while let Some(incoming) = self.inner.endpoint.accept().await {
            let node = self.clone();
            let from = match incoming.remote_addr() {
                iroh::endpoint::IncomingAddr::Ip(sa) => Some(sa),
                _ => None,
            };
            tokio::spawn(async move {
                if let Ok(conn) = incoming.await {
                    node.handle_connection(conn, from).await;
                }
            });
        }
    }

    async fn handle_connection(&self, conn: Connection, from: Option<SocketAddr>) {
        let remote = peer_key(&conn.remote_id());
        if let Some(addr) = from {
            self.remember_addr(&remote, addr);
        }
        // Unpaired devices are dropped right after the handshake unless pairing mode is open.
        if let PeerStatus::Unpaired {
            pairing_open: false,
        } = self.peer_status(&remote)
        {
            conn.close(1u32.into(), b"pairing closed");
            return;
        }
        while let Ok((send, recv)) = conn.accept_bi().await {
            let node = self.clone();
            tokio::spawn(async move {
                if let Err(e) = node.handle_stream(remote, from, send, recv).await {
                    tracing::debug!("stream from {remote:?} ended: {e:#}");
                }
            });
        }
    }

    async fn handle_stream(
        &self,
        remote: PeerKey,
        from_addr: Option<SocketAddr>,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let body = wire::recv(&mut recv).await?;
        // I2: decide with the *current* status for every stream, not the one at connect time.
        if let Err(denied) = admit(wire::kind(&body), self.peer_status(&remote)) {
            let code = match denied {
                gimmecores_core::Denied::PairingClosed => Code::PairingClosed,
                gimmecores_core::Denied::NotPaired => Code::NotPaired,
                _ => Code::Invalid,
            };
            return wire::send_error(&mut send, code, "not allowed").await;
        }
        match body {
            Body::Hello(_) => {
                wire::send(&mut send, Body::Hello(self.hello())).await?;
                send.finish()?;
                Ok(())
            }
            Body::PairRequest(req) => {
                self.respond_to_pairing(remote, req, send, recv).await?;
                if let Some(addr) = from_addr {
                    self.remember_addr(&remote, addr);
                }
                Ok(())
            }
            Body::GrantRequest(req) => self.handle_grant_request(remote, req, send).await,
            Body::GrantRevoke(r) => self.handle_remote_revoke(remote, r),
            Body::Unpair(_) => {
                self.forget_peer(&remote)?;
                Ok(())
            }
            _ => wire::send_error(&mut send, Code::Invalid, "unsupported message").await,
        }
    }

    fn hello(&self) -> Hello {
        Hello {
            protocol_version: PROTOCOL_VERSION,
            software_version: env!("CARGO_PKG_VERSION").to_string(),
            device_name: self.inner.name.clone(),
            capabilities: None,
        }
    }

    // ------------------------------------------------------------------ pairing

    /// The local user opened pairing mode (2 minutes). Returns when it closes.
    pub fn open_pairing(&self) -> u64 {
        let t = now();
        self.state().window.open(t);
        t + pairing::WINDOW_SECONDS
    }

    pub fn pairing(&self, id: u64) -> Option<PairingView> {
        self.state().sessions.get(&id).map(|s| s.view.clone())
    }

    pub fn pairings(&self) -> Vec<PairingView> {
        self.state()
            .sessions
            .values()
            .map(|s| s.view.clone())
            .collect()
    }

    /// The local user compared the codes. `true` = they match.
    pub fn confirm_pairing(&self, id: u64, codes_match: bool) -> Result<()> {
        let mut s = self.state();
        let session = s.sessions.get_mut(&id).context("no such pairing")?;
        let tx = session
            .decide
            .take()
            .context("this pairing is not waiting for a decision")?;
        let _ = tx.send(codes_match);
        Ok(())
    }

    fn new_session(&self, peer: PeerKey, peer_name: String) -> (u64, oneshot::Receiver<bool>) {
        let (tx, rx) = oneshot::channel();
        let mut s = self.state();
        let id = s.next_session;
        s.next_session += 1;
        let name_reuse = s.trust.name_used_by_other_key(&peer_name, &peer);
        s.sessions.insert(
            id,
            Session {
                view: PairingView {
                    id,
                    peer,
                    peer_name,
                    code: None,
                    status: PairStatus::Waiting,
                    name_previously_seen_with_other_key: name_reuse,
                },
                decide: Some(tx),
            },
        );
        (id, rx)
    }

    fn update_session(&self, id: u64, f: impl FnOnce(&mut PairingView)) {
        if let Some(s) = self.state().sessions.get_mut(&id) {
            f(&mut s.view);
        }
    }

    /// Device A: pair with the device at `addr`. Returns the session id immediately; the code
    /// appears in [`Node::pairing`] once both nonces are exchanged.
    pub async fn start_pairing(&self, addr: EndpointAddr) -> Result<u64> {
        let peer = PeerKey(*addr.id.as_bytes());
        let dialed: Vec<SocketAddr> = addr.ip_addrs().copied().collect();
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.endpoint.connect(addr, PEER_ALPN),
        )
        .await
        .context("connection timed out")??;
        let (mut send, mut recv) = conn.open_bi().await?;
        let (mut initiator, commitment) = Initiator::start(self.inner.me, peer, wire::random32()?);
        wire::send(
            &mut send,
            Body::PairRequest(PairRequest {
                commitment: commitment.to_vec(),
                device_name: self.inner.name.clone(),
            }),
        )
        .await?;
        let Body::PairChallenge(ch) = wire::recv(&mut recv).await? else {
            return Err(anyhow!("expected PairChallenge"));
        };
        let (id, decision) = self.new_session(peer, wire::clean_name(&ch.device_name));
        let (my_nonce, code) = initiator.on_challenge(&wire::nonce32(&ch.nonce)?)?;
        wire::send(
            &mut send,
            Body::PairReveal(PairReveal {
                nonce: my_nonce.to_vec(),
            }),
        )
        .await?;
        let node = self.clone();
        tokio::spawn(async move {
            let result = node
                .finish_pairing(id, code, decision, dialed, send, recv)
                .await;
            if let Err(e) = result {
                node.update_session(id, |v| v.status = PairStatus::Failed(format!("{e:#}")));
            }
            drop(conn);
        });
        Ok(id)
    }

    /// Device B: answer a pairing request (the admission gate already checked pairing mode).
    async fn respond_to_pairing(
        &self,
        remote: PeerKey,
        req: PairRequest,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        let commitment = wire::nonce32(&req.commitment)?;
        let my_nonce = wire::random32()?;
        let started = {
            let mut s = self.state();
            Responder::on_request(
                &mut s.window,
                now(),
                self.inner.me,
                remote,
                commitment,
                my_nonce,
            )
        };
        let mut responder = match started {
            Ok((r, _)) => r,
            Err(e) => return wire::send_error(&mut send, Code::RateLimited, &e.to_string()).await,
        };
        let (id, decision) = self.new_session(remote, wire::clean_name(&req.device_name));
        wire::send(
            &mut send,
            Body::PairChallenge(PairChallenge {
                nonce: my_nonce.to_vec(),
                device_name: self.inner.name.clone(),
            }),
        )
        .await?;
        let result = async {
            let Body::PairReveal(rev) = wire::recv(&mut recv).await? else {
                return Err(anyhow!("expected PairReveal"));
            };
            let code = {
                let mut s = self.state();
                responder.on_reveal(&mut s.window, &wire::nonce32(&rev.nonce)?)?
            };
            self.finish_pairing(id, code, decision, Vec::new(), send, recv)
                .await
        }
        .await;
        if let Err(e) = &result {
            self.update_session(id, |v| v.status = PairStatus::Failed(format!("{e:#}")));
        }
        result
    }

    /// Both sides: show the code, wait for the local user and the peer, then trust the peer
    /// only if both confirmed.
    async fn finish_pairing(
        &self,
        id: u64,
        code: ShortCode,
        decision: oneshot::Receiver<bool>,
        dialed: Vec<SocketAddr>,
        mut send: SendStream,
        mut recv: RecvStream,
    ) -> Result<()> {
        self.update_session(id, |v| {
            v.code = Some(code);
            v.status = PairStatus::CompareCode;
        });
        let deadline = Duration::from_secs(pairing::WINDOW_SECONDS);
        let local = async {
            let ok = decision.await.unwrap_or(false);
            wire::send(&mut send, Body::PairConfirm(PairConfirm { accepted: ok })).await?;
            send.finish()?;
            anyhow::Ok(ok)
        };
        let remote = async {
            match wire::recv(&mut recv).await? {
                Body::PairConfirm(c) => anyhow::Ok(c.accepted),
                _ => Err(anyhow!("expected PairConfirm")),
            }
        };
        let (local, remote) = tokio::time::timeout(deadline, async { tokio::join!(local, remote) })
            .await
            .context("pairing timed out")?;
        let mut confirmation = Confirmation::default();
        confirmation.set_local(local?);
        confirmation.set_remote(remote?);
        match confirmation.outcome() {
            Some(Ok(())) => {
                let (peer, name) = {
                    let s = self.state();
                    let v = &s.sessions.get(&id).context("session vanished")?.view;
                    (v.peer, v.peer_name.clone())
                };
                let mut s = self.state();
                s.trust.add(peer, name, now())?;
                if !dialed.is_empty() {
                    s.trust.set_addrs(&peer, dialed)?;
                }
                s.window.close();
                drop(s);
                self.update_session(id, |v| v.status = PairStatus::Paired);
                Ok(())
            }
            Some(Err(e)) => {
                self.state().window.close();
                Err(e.into())
            }
            None => Err(anyhow!("pairing incomplete")),
        }
    }

    /// Remembers where a paired peer can be reached (only for already-paired peers).
    fn remember_addr(&self, peer: &PeerKey, addr: SocketAddr) {
        let mut s = self.state();
        let known = s.trust.get(peer).map(|p| p.last_addrs.contains(&addr));
        if known == Some(false) {
            let _ = s.trust.set_addrs(peer, vec![addr]);
        }
    }

    /// Opens a connection to a paired peer using its last known addresses.
    pub(crate) async fn dial(&self, peer: &PeerKey) -> Result<Connection> {
        let addrs = self
            .state()
            .trust
            .get(peer)
            .map(|p| p.last_addrs.clone())
            .context("not paired with that device")?;
        anyhow::ensure!(!addrs.is_empty(), "no known address for that device");
        let pk = iroh::PublicKey::from_bytes(&peer.0)?;
        let addr = EndpointAddr::from_parts(pk, addrs.into_iter().map(iroh::TransportAddr::Ip));
        let conn = tokio::time::timeout(
            Duration::from_secs(10),
            self.inner.endpoint.connect(addr, PEER_ALPN),
        )
        .await
        .context("connection timed out")??;
        Ok(conn)
    }

    /// Unpair: remove the key and revoke everything it holds here (I3).
    pub fn forget_peer(&self, peer: &PeerKey) -> Result<Vec<gimmecores_core::TaskId>> {
        let mut s = self.state();
        s.trust.remove(peer)?;
        Ok(s.grants.revoke_peer(*peer))
    }
}
