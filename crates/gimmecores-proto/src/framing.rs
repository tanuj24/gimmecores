//! Length-prefixed protobuf frames: a big-endian `u32` length followed by the message bytes.
//!
//! Frames larger than [`MAX_FRAME_LEN`] are rejected **before** allocating, so a peer cannot
//! make us reserve memory by sending a huge length header (threat model 5.1).

use prost::Message;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Maximum encoded size of one frame (4 MiB). Larger payloads (blobs) are chunked.
pub const MAX_FRAME_LEN: usize = 4 * 1024 * 1024;

#[derive(Debug, thiserror::Error)]
pub enum FrameError {
    #[error("frame of {0} bytes exceeds the {MAX_FRAME_LEN}-byte limit")]
    TooLarge(usize),
    #[error("stream ended in the middle of a frame")]
    Truncated,
    #[error("invalid message: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error(transparent)]
    Io(std::io::Error),
}

impl From<std::io::Error> for FrameError {
    fn from(e: std::io::Error) -> Self {
        if e.kind() == std::io::ErrorKind::UnexpectedEof {
            FrameError::Truncated
        } else {
            FrameError::Io(e)
        }
    }
}

/// Encodes `msg` and writes it as one frame.
pub async fn write_frame<W, M>(writer: &mut W, msg: &M) -> Result<(), FrameError>
where
    W: AsyncWrite + Unpin,
    M: Message,
{
    let len = msg.encoded_len();
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut buf = Vec::with_capacity(4 + len);
    // `len <= MAX_FRAME_LEN` (4 MiB) always fits in a u32.
    buf.extend_from_slice(&(len as u32).to_be_bytes());
    msg.encode(&mut buf)
        .expect("Vec<u8> grows as needed, encoding cannot run out of space");
    writer.write_all(&buf).await?;
    Ok(())
}

/// Reads one frame. Returns `Ok(None)` on a clean end of stream before a new frame starts.
pub async fn read_frame<R, M>(reader: &mut R) -> Result<Option<M>, FrameError>
where
    R: AsyncRead + Unpin,
    M: Message + Default,
{
    let mut header = [0u8; 4];
    match reader.read(&mut header[..1]).await? {
        0 => return Ok(None),
        _ => reader.read_exact(&mut header[1..]).await?,
    };
    let len = u32::from_be_bytes(header) as usize;
    if len > MAX_FRAME_LEN {
        return Err(FrameError::TooLarge(len));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body).await?;
    Ok(Some(M::decode(body.as_slice())?))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::peer::v1::{Hello, PeerMessage, peer_message::Body};

    fn hello() -> PeerMessage {
        PeerMessage {
            body: Some(Body::Hello(Hello {
                protocol_version: 1,
                software_version: "0.1.0".into(),
                device_name: "Maya's MacBook".into(),
                capabilities: None,
                wake_macs: vec![],
            })),
        }
    }

    #[tokio::test]
    async fn round_trip_two_frames_then_clean_eof() {
        let mut wire = Vec::new();
        write_frame(&mut wire, &hello()).await.unwrap();
        write_frame(&mut wire, &hello()).await.unwrap();
        let mut r = wire.as_slice();
        assert_eq!(
            read_frame::<_, PeerMessage>(&mut r).await.unwrap(),
            Some(hello())
        );
        assert_eq!(
            read_frame::<_, PeerMessage>(&mut r).await.unwrap(),
            Some(hello())
        );
        assert_eq!(read_frame::<_, PeerMessage>(&mut r).await.unwrap(), None);
    }

    #[tokio::test]
    async fn oversized_length_header_is_rejected_before_allocating() {
        let wire = u32::MAX.to_be_bytes();
        let err = read_frame::<_, PeerMessage>(&mut wire.as_slice())
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(n) if n == u32::MAX as usize));
    }

    #[tokio::test]
    async fn truncated_header_and_body_are_errors() {
        let err = read_frame::<_, PeerMessage>(&mut [0u8, 0].as_slice())
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Truncated));
        let mut wire = 10u32.to_be_bytes().to_vec();
        wire.extend_from_slice(b"abc");
        let err = read_frame::<_, PeerMessage>(&mut wire.as_slice())
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Truncated));
    }

    #[tokio::test]
    async fn garbage_body_is_a_decode_error() {
        let mut wire = 3u32.to_be_bytes().to_vec();
        wire.extend_from_slice(&[0xff, 0xff, 0xff]);
        let err = read_frame::<_, PeerMessage>(&mut wire.as_slice())
            .await
            .unwrap_err();
        assert!(matches!(err, FrameError::Decode(_)));
    }

    #[tokio::test]
    async fn oversized_message_is_refused_on_write() {
        let big = PeerMessage {
            body: Some(Body::Hello(Hello {
                device_name: "x".repeat(MAX_FRAME_LEN),
                ..Default::default()
            })),
        };
        let err = write_frame(&mut Vec::new(), &big).await.unwrap_err();
        assert!(matches!(err, FrameError::TooLarge(_)));
    }
}
