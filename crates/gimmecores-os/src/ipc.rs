//! The local API's endpoints. Each is addressed by a path in the daemon's `run/` folder: the
//! Unix socket itself on macOS and Linux; on Windows, a file naming the daemon's pipe (the
//! name is random per start, so it cannot be guessed and taken over in advance).

use std::path::Path;

use anyhow::Result;

#[cfg(unix)]
pub use unix::{Incoming, Stream, bind_private, connect};
#[cfg(windows)]
pub use windows::{Incoming, Stream, bind_private, connect};

#[cfg(unix)]
mod unix {
    use super::*;
    use anyhow::Context;

    pub type Incoming = tokio_stream::wrappers::UnixListenerStream;
    pub type Stream = tokio::net::UnixStream;

    /// Binds a Unix socket readable and writable only by this user.
    pub fn bind_private(path: &Path) -> Result<Incoming> {
        use std::os::unix::fs::PermissionsExt;
        if path.exists() {
            std::fs::remove_file(path)?; // stale socket from a previous run
        }
        let listener = tokio::net::UnixListener::bind(path)
            .with_context(|| format!("binding {}", path.display()))?;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
        Ok(tokio_stream::wrappers::UnixListenerStream::new(listener))
    }

    pub async fn connect(path: &Path) -> std::io::Result<Stream> {
        tokio::net::UnixStream::connect(path).await
    }
}

#[cfg(windows)]
mod windows {
    use super::*;
    use std::io;
    use std::pin::Pin;
    use std::task::{Context as TaskContext, Poll};
    use std::time::Duration;

    use anyhow::Context;
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    use tokio::net::windows::named_pipe::{ClientOptions, NamedPipeClient, NamedPipeServer};
    use tokio_stream::wrappers::ReceiverStream;

    use crate::windows as win;

    const PREFIX: &str = r"\\.\pipe\gimmecores-";
    /// Win32 ERROR_PIPE_BUSY: every instance is in use; try again shortly.
    const ERROR_PIPE_BUSY: i32 = 231;

    /// One accepted connection.
    pub struct Conn(NamedPipeServer);
    pub type Incoming = ReceiverStream<io::Result<Conn>>;
    pub type Stream = NamedPipeClient;

    /// Creates the pipe (only this user may open it, never remotely, refused if the name is
    /// already taken) and writes its name to `path`, which lives in the owner-only `run/`
    /// folder.
    pub fn bind_private(path: &Path) -> Result<Incoming> {
        let name = format!("{PREFIX}{}", win::random_hex(16)?);
        let pipe = win::OwnerOnlyPipe::new(&name)?;
        let mut server = pipe
            .create(true)
            .with_context(|| format!("creating {name}"))?;
        crate::private::write_private(path, name.as_bytes())?;
        let (tx, rx) = tokio::sync::mpsc::channel(16);
        tokio::spawn(async move {
            loop {
                if let Err(e) = server.connect().await {
                    if tx.send(Err(e)).await.is_err() {
                        return;
                    }
                    continue;
                }
                // A new instance before handing this one over, so the name is never free for
                // another program to take.
                let next = match pipe.create(false) {
                    Ok(next) => next,
                    Err(e) => {
                        let _ = tx.send(Err(e)).await;
                        return;
                    }
                };
                let connected = std::mem::replace(&mut server, next);
                if tx.send(Ok(Conn(connected))).await.is_err() {
                    return;
                }
            }
        });
        Ok(ReceiverStream::new(rx))
    }

    /// Opens the daemon's pipe named in `path`, after checking that the program serving it runs
    /// as this user.
    pub async fn connect(path: &Path) -> io::Result<Stream> {
        let name = std::fs::read_to_string(path)?;
        let name = name.trim();
        let valid = name
            .strip_prefix(PREFIX)
            .is_some_and(|hex| hex.len() == 32 && hex.bytes().all(|b| b.is_ascii_hexdigit()));
        if !valid {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("{} does not name a GimmeCores pipe", path.display()),
            ));
        }
        let mut waited = Duration::ZERO;
        let client = loop {
            match ClientOptions::new().open(name) {
                Ok(c) => break c,
                Err(e)
                    if e.raw_os_error() == Some(ERROR_PIPE_BUSY)
                        && waited < Duration::from_secs(5) =>
                {
                    tokio::time::sleep(Duration::from_millis(50)).await;
                    waited += Duration::from_millis(50);
                }
                Err(e) => return Err(e),
            }
        };
        if !win::pipe_server_is_this_user(&client)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "the GimmeCores pipe is served by another user's program; refusing to use it",
            ));
        }
        Ok(client)
    }

    impl tonic::transport::server::Connected for Conn {
        type ConnectInfo = ();
        fn connect_info(&self) -> Self::ConnectInfo {}
    }

    impl AsyncRead for Conn {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_read(cx, buf)
        }
    }

    impl AsyncWrite for Conn {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
            buf: &[u8],
        ) -> Poll<io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, buf)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut TaskContext<'_>) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut TaskContext<'_>,
        ) -> Poll<io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio_stream::StreamExt;

    #[tokio::test]
    async fn a_private_endpoint_carries_bytes_both_ways() {
        let dir = tempfile::tempdir().unwrap();
        crate::private::restrict_dir(dir.path()).unwrap();
        let path = dir.path().join("test.sock");
        let mut incoming = bind_private(&path).unwrap();
        let server = tokio::spawn(async move {
            let mut conn = incoming.next().await.unwrap().unwrap();
            let mut buf = [0u8; 5];
            conn.read_exact(&mut buf).await.unwrap();
            conn.write_all(b"world").await.unwrap();
            buf
        });
        let mut client = connect(&path).await.unwrap();
        client.write_all(b"hello").await.unwrap();
        let mut back = [0u8; 5];
        client.read_exact(&mut back).await.unwrap();
        assert_eq!(&back, b"world");
        assert_eq!(&server.await.unwrap(), b"hello");
        crate::private::check_private(&path).unwrap();
    }
}
