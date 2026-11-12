//! A thin client for the local `gmcd`: where its sockets are, and how to connect to them.
//! Used by the CLI and the desktop app, so neither needs to link the daemon itself.
//!
//! The **Client** socket submits work and requests grants; the **Control** socket carries
//! consent actions. Both are owner-only Unix sockets (threat model I13).

use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
pub use gimmecores_proto::local::v1 as api;
use gimmecores_proto::local::v1::client_client::ClientClient;
use gimmecores_proto::local::v1::control_client::ControlClient;
use tonic::transport::Channel;

/// The daemon's state directory: `GMC_HOME` if set, else the platform data directory
/// (macOS: `~/Library/Application Support/GimmeCores`, Linux: `~/.local/share/gimmecores`).
pub fn home() -> Result<PathBuf> {
    if let Some(home) = std::env::var_os("GMC_HOME") {
        return Ok(PathBuf::from(home));
    }
    let base = dirs::data_dir().context("no platform data directory")?;
    let name = if cfg!(target_os = "linux") {
        "gimmecores"
    } else {
        "GimmeCores"
    };
    Ok(base.join(name))
}

pub fn client_socket(home: &Path) -> PathBuf {
    home.join("run").join("client.sock")
}

pub fn control_socket(home: &Path) -> PathBuf {
    home.join("run").join("control.sock")
}

/// A gRPC channel over a Unix socket.
pub async fn channel(path: &Path) -> Result<Channel> {
    let path = Arc::new(path.to_path_buf());
    let channel = tonic::transport::Endpoint::try_from("http://gimmecores.local")?
        .connect_with_connector(tower::service_fn(move |_| {
            let p = path.clone();
            async move {
                let stream = tokio::net::UnixStream::connect(p.as_path()).await?;
                Ok::<_, std::io::Error>(hyper_util::rt::TokioIo::new(stream))
            }
        }))
        .await
        .context("cannot reach gmcd; is it running? (start it with `gmc daemon`)")?;
    Ok(channel)
}

pub async fn client(home: &Path) -> Result<ClientClient<Channel>> {
    Ok(ClientClient::new(channel(&client_socket(home)).await?))
}

pub async fn control(home: &Path) -> Result<ControlClient<Channel>> {
    Ok(ControlClient::new(channel(&control_socket(home)).await?))
}
