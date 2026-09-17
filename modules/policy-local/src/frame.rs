use thiserror::Error;

pub struct FrameDecoder {
    buffer: Vec<u8>,
    expected: Option<usize>,
    limit: usize,
}

impl FrameDecoder {
    pub fn new(limit: usize) -> Result<Self, FrameError> {
        if limit == 0 {
            return Err(FrameError::Length);
        }
        Ok(Self {
            buffer: Vec::new(),
            expected: None,
            limit,
        })
    }

    pub fn push(&mut self, input: &[u8]) -> Result<Vec<String>, FrameError> {
        let mut frames = Vec::new();
        for byte in input {
            if self.buffer.len() >= self.limit.saturating_add(4) {
                return Err(FrameError::Length);
            }
            self.buffer.push(*byte);
            if self.expected.is_none() && self.buffer.len() >= 4 {
                let length =
                    u32::from_be_bytes(self.buffer[..4].try_into().expect("length checked"))
                        as usize;
                if length == 0 || length > self.limit {
                    return Err(FrameError::Length);
                }
                self.expected = Some(length);
            }
            let Some(length) = self.expected else {
                continue;
            };
            if self.buffer.len() < length + 4 {
                continue;
            }
            let payload = self.buffer[4..4 + length].to_vec();
            self.buffer.drain(..4 + length);
            self.expected = None;
            let frame = String::from_utf8(payload).map_err(|_| FrameError::Utf8)?;
            frames.push(frame);
        }
        Ok(frames)
    }
}

pub fn encode_frame(input: &str, limit: usize) -> Result<Vec<u8>, FrameError> {
    if input.is_empty() || input.len() > limit || input.len() > u32::MAX as usize {
        return Err(FrameError::Length);
    }
    let mut frame = Vec::with_capacity(input.len() + 4);
    frame.extend_from_slice(&(input.len() as u32).to_be_bytes());
    frame.extend_from_slice(input.as_bytes());
    Ok(frame)
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub enum FrameError {
    #[error("policy frame length is invalid")]
    Length,
    #[error("policy frame is not UTF-8")]
    Utf8,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_all_fragmentations_and_coalescing() {
        let first = encode_frame("one", 16).unwrap();
        let second = encode_frame("two", 16).unwrap();
        for split in 0..=first.len() {
            let mut decoder = FrameDecoder::new(16).unwrap();
            let mut frames = decoder.push(&first[..split]).unwrap();
            frames.extend(decoder.push(&first[split..]).unwrap());
            assert_eq!(frames, ["one"]);
        }
        let mut joined = first;
        joined.extend_from_slice(&second);
        assert_eq!(
            FrameDecoder::new(16).unwrap().push(&joined).unwrap(),
            ["one", "two"]
        );
    }

    #[test]
    fn rejects_zero_and_oversized_frames_before_payload() {
        assert_eq!(
            FrameDecoder::new(16).unwrap().push(&0_u32.to_be_bytes()),
            Err(FrameError::Length)
        );
        assert_eq!(
            FrameDecoder::new(16).unwrap().push(&17_u32.to_be_bytes()),
            Err(FrameError::Length)
        );
    }
}
