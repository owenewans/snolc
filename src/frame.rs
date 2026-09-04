use crate::WIRE_VERSION;
use crate::error::{Error, Result};

pub const MAGIC: [u8; 4] = *b"SNLC";
pub const HEADER_LEN: usize = 21;
pub const MAX_PAYLOAD_LEN: usize = 16 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum FrameType {
    ClientHello = 1,
    ServerHello = 2,
    ClientFinish = 3,
    Data = 16,
    Heartbeat = 17,
    Close = 18,
    Open = 19,
    OpenOk = 20,
    Datagram = 21,
    Error = 255,
}

impl TryFrom<u8> for FrameType {
    type Error = Error;

    fn try_from(value: u8) -> Result<Self> {
        match value {
            1 => Ok(Self::ClientHello),
            2 => Ok(Self::ServerHello),
            3 => Ok(Self::ClientFinish),
            16 => Ok(Self::Data),
            17 => Ok(Self::Heartbeat),
            18 => Ok(Self::Close),
            19 => Ok(Self::Open),
            20 => Ok(Self::OpenOk),
            21 => Ok(Self::Datagram),
            255 => Ok(Self::Error),
            _ => Err(Error::Protocol("unknown frame type".to_owned())),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Frame {
    pub kind: FrameType,
    pub flags: u8,
    pub sequence: u64,
    pub payload: Vec<u8>,
    pub tag: Vec<u8>,
}

impl Frame {
    pub fn encode(&self, tag_len: usize) -> Result<Vec<u8>> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(Error::Protocol(
                "frame payload exceeds the limit".to_owned(),
            ));
        }
        if self.tag.len() != tag_len {
            return Err(Error::Protocol(
                "frame has an invalid tag length".to_owned(),
            ));
        }
        let mut output = Vec::with_capacity(HEADER_LEN + self.payload.len() + self.tag.len());
        output.extend_from_slice(&self.header()?);
        output.extend_from_slice(&self.payload);
        output.extend_from_slice(&self.tag);
        Ok(output)
    }

    pub fn decode(input: &[u8], tag_len: usize) -> Result<Self> {
        if input.len() < HEADER_LEN {
            return Err(Error::Protocol("truncated frame header".to_owned()));
        }
        if input[..4] != MAGIC {
            return Err(Error::Protocol("invalid frame magic".to_owned()));
        }
        let version = u32::from_be_bytes([0, input[4], input[5], input[6]]);
        if version != WIRE_VERSION {
            return Err(Error::Protocol("wire version mismatch".to_owned()));
        }
        let kind = FrameType::try_from(input[7])?;
        let flags = input[8];
        let sequence = u64::from_be_bytes(
            input[9..17]
                .try_into()
                .map_err(|_| Error::Protocol("invalid sequence".to_owned()))?,
        );
        let payload_len = u32::from_be_bytes(
            input[17..21]
                .try_into()
                .map_err(|_| Error::Protocol("invalid payload length".to_owned()))?,
        ) as usize;
        if payload_len > MAX_PAYLOAD_LEN {
            return Err(Error::Protocol(
                "frame payload exceeds the limit".to_owned(),
            ));
        }
        let expected = HEADER_LEN
            .checked_add(payload_len)
            .and_then(|length| length.checked_add(tag_len))
            .ok_or_else(|| Error::Protocol("frame length overflow".to_owned()))?;
        if input.len() != expected {
            return Err(Error::Protocol("frame length mismatch".to_owned()));
        }
        Ok(Self {
            kind,
            flags,
            sequence,
            payload: input[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
            tag: input[HEADER_LEN + payload_len..].to_vec(),
        })
    }

    pub fn header(&self) -> Result<[u8; HEADER_LEN]> {
        if WIRE_VERSION > 0x00ff_ffff {
            return Err(Error::Protocol(
                "wire version exceeds three bytes".to_owned(),
            ));
        }
        let payload_len = u32::try_from(self.payload.len())
            .map_err(|_| Error::Protocol("frame payload is too large".to_owned()))?;
        let version = WIRE_VERSION.to_be_bytes();
        let mut header = [0_u8; HEADER_LEN];
        header[..4].copy_from_slice(&MAGIC);
        header[4..7].copy_from_slice(&version[1..]);
        header[7] = self.kind as u8;
        header[8] = self.flags;
        header[9..17].copy_from_slice(&self.sequence.to_be_bytes());
        header[17..21].copy_from_slice(&payload_len.to_be_bytes());
        Ok(header)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frame_round_trip_preserves_binary_fields() {
        let frame = Frame {
            kind: FrameType::Data,
            flags: 3,
            sequence: 42,
            payload: vec![0, 1, 255, 9],
            tag: vec![7; 16],
        };
        let encoded = frame.encode(16).unwrap();
        assert_eq!(Frame::decode(&encoded, 16).unwrap(), frame);
    }

    #[test]
    fn rejects_version_and_length_mismatches() {
        let frame = Frame {
            kind: FrameType::Heartbeat,
            flags: 0,
            sequence: 0,
            payload: Vec::new(),
            tag: Vec::new(),
        };
        let mut encoded = frame.encode(0).unwrap();
        encoded[6] = 2;
        assert!(Frame::decode(&encoded, 0).is_err());

        let mut encoded = frame.encode(0).unwrap();
        encoded.push(0);
        assert!(Frame::decode(&encoded, 0).is_err());
    }
}
