use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

use crate::error::{Error, Result};
use crate::frame::{Frame, HEADER_LEN, MAX_PAYLOAD_LEN};

pub async fn read_frame<R>(reader: &mut R, tag_len: usize) -> Result<Frame>
where
    R: AsyncRead + Unpin,
{
    let mut header = [0_u8; HEADER_LEN];
    reader.read_exact(&mut header).await?;
    let payload_len = u32::from_be_bytes(
        header[17..21]
            .try_into()
            .map_err(|_| Error::Protocol("invalid frame length".to_owned()))?,
    ) as usize;
    if payload_len > MAX_PAYLOAD_LEN {
        return Err(Error::Protocol(
            "frame payload exceeds the limit".to_owned(),
        ));
    }
    let body_len = payload_len
        .checked_add(tag_len)
        .ok_or_else(|| Error::Protocol("frame length overflow".to_owned()))?;
    let mut encoded = Vec::with_capacity(HEADER_LEN + body_len);
    encoded.extend_from_slice(&header);
    encoded.resize(HEADER_LEN + body_len, 0);
    reader.read_exact(&mut encoded[HEADER_LEN..]).await?;
    Frame::decode(&encoded, tag_len)
}

pub async fn write_frame<W>(writer: &mut W, frame: &Frame, tag_len: usize) -> Result<()>
where
    W: AsyncWrite + Unpin,
{
    let encoded = frame.encode(tag_len)?;
    writer.write_all(&encoded).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::frame::FrameType;

    #[tokio::test]
    async fn reads_back_to_back_frames_without_overreading() {
        let (mut writer, mut reader) = tokio::io::duplex(1024);
        let first = Frame {
            kind: FrameType::Data,
            flags: 0,
            sequence: 1,
            payload: b"one".to_vec(),
            tag: vec![1; 16],
        };
        let second = Frame {
            kind: FrameType::Close,
            flags: 0,
            sequence: 2,
            payload: Vec::new(),
            tag: vec![2; 16],
        };
        write_frame(&mut writer, &first, 16).await.unwrap();
        write_frame(&mut writer, &second, 16).await.unwrap();
        assert_eq!(read_frame(&mut reader, 16).await.unwrap(), first);
        assert_eq!(read_frame(&mut reader, 16).await.unwrap(), second);
    }
}
