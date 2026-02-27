/// Double-AEAD framing for the `x25519-v0.2` skin (spec §9.4.1.3).
///
/// Wire layout per frame:
/// ```text
/// content  = frame_type(1) || frame_data
/// len      = uint16_be(len(content))
/// wire     = AEAD(k, nonce_n,   len_bytes)   → 2 + 16 = 18 bytes
///          || AEAD(k, nonce_n+1, content)    → len + 16 bytes
/// nonce_n += 2
/// ```
///
/// Nonce format (§9.4.1.4):
/// ```text
/// nonce(n) = uint64_le(n) || 4_zero_bytes   → 12 bytes total
/// ```
///
/// Frame types:
/// | Byte  | Name   | frame_data                                |
/// |-------|--------|-------------------------------------------|
/// | 0x00  | JSON   | UTF-8 JSON (envelope or error object)     |
/// | 0x01  | Binary | SHA-256 hash (32 bytes) || piece data     |
use anyhow::{anyhow, bail, Result};

use toloo_core::crypto::{chacha20_decrypt, chacha20_encrypt};

pub const FRAME_JSON: u8 = 0x00;
pub const FRAME_BINARY: u8 = 0x01;

const AEAD_TAG: usize = 16;
const LEN_WIRE: usize = 2 + AEAD_TAG; // 18 bytes: AEAD(uint16_be(len))

/// Encrypting side of a double-AEAD frame channel. One instance per direction.
pub struct FrameEncoder {
    key: [u8; 32],
    counter: u64,
}

/// Decrypting side of a double-AEAD frame channel. One instance per direction.
pub struct FrameDecoder {
    key: [u8; 32],
    counter: u64,
}

impl FrameEncoder {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    /// Encode a JSON frame (type byte `0x00`).
    pub fn encode_json(&mut self, json: &str) -> Result<Vec<u8>> {
        let mut content = Vec::with_capacity(1 + json.len());
        content.push(FRAME_JSON);
        content.extend_from_slice(json.as_bytes());
        self.encode_content(content)
    }

    /// Encode a binary blob-piece frame (type byte `0x01`).
    /// `hash` is the 32-byte SHA-256 hash of `data`.
    pub fn encode_binary(&mut self, hash: &[u8; 32], data: &[u8]) -> Result<Vec<u8>> {
        let mut content = Vec::with_capacity(1 + 32 + data.len());
        content.push(FRAME_BINARY);
        content.extend_from_slice(hash);
        content.extend_from_slice(data);
        self.encode_content(content)
    }

    fn encode_content(&mut self, content: Vec<u8>) -> Result<Vec<u8>> {
        let len = content.len();
        if len > u16::MAX as usize {
            bail!("frame content too large: {} bytes (max {})", len, u16::MAX);
        }
        let len_bytes = (len as u16).to_be_bytes();

        let nonce_n = make_nonce(self.counter);
        let nonce_n1 = make_nonce(self.counter + 1);
        self.counter += 2;

        let len_aead = chacha20_encrypt(&self.key, &nonce_n, &len_bytes);
        let content_aead = chacha20_encrypt(&self.key, &nonce_n1, &content);

        let mut wire = Vec::with_capacity(LEN_WIRE + len + AEAD_TAG);
        wire.extend_from_slice(&len_aead);
        wire.extend_from_slice(&content_aead);
        Ok(wire)
    }
}

impl FrameDecoder {
    pub fn new(key: [u8; 32]) -> Self {
        Self { key, counter: 0 }
    }

    /// Decode a complete wire frame.
    ///
    /// Returns `(frame_type_byte, frame_data)` where `frame_data` is everything
    /// after the type byte.
    ///
    /// `wire` must contain exactly one frame (18 + len + 16 bytes).
    /// Use [`decode_content_len`] first to know how many bytes to read.
    pub fn decode(&mut self, wire: &[u8]) -> Result<(u8, Vec<u8>)> {
        if wire.len() < LEN_WIRE {
            bail!("frame too short: {} bytes (need at least {})", wire.len(), LEN_WIRE);
        }

        let nonce_n = make_nonce(self.counter);
        let nonce_n1 = make_nonce(self.counter + 1);
        self.counter += 2;

        // Decrypt the 18-byte len AEAD.
        let len_bytes: [u8; 2] = chacha20_decrypt(&self.key, &nonce_n, &wire[..LEN_WIRE])?
            .try_into()
            .map_err(|_| anyhow!("len AEAD decrypted to unexpected size"))?;
        let content_len = u16::from_be_bytes(len_bytes) as usize;

        let expected_total = LEN_WIRE + content_len + AEAD_TAG;
        if wire.len() != expected_total {
            bail!(
                "frame size mismatch: got {} bytes, expected {}",
                wire.len(),
                expected_total
            );
        }

        // Decrypt the content AEAD.
        let content = chacha20_decrypt(&self.key, &nonce_n1, &wire[LEN_WIRE..])?;
        if content.len() != content_len {
            bail!("decrypted content length mismatch");
        }
        if content.is_empty() {
            bail!("frame content must not be empty (missing type byte)");
        }

        let frame_type = content[0];
        let frame_data = content[1..].to_vec();
        Ok((frame_type, frame_data))
    }

    /// Decrypt just the 18-byte len header to learn how many additional bytes to read.
    ///
    /// After calling this, read `content_len + 16` more bytes, then call
    /// [`decode`] with the full 18 + content_len + 16 byte slice.
    ///
    /// **Does not advance the counter** — call [`decode`] next to consume the full frame.
    pub fn decode_content_len(&self, len_aead: &[u8; 18]) -> Result<usize> {
        let nonce_n = make_nonce(self.counter);
        let len_bytes: [u8; 2] = chacha20_decrypt(&self.key, &nonce_n, len_aead)?
            .try_into()
            .map_err(|_| anyhow!("len AEAD decrypted to unexpected size"))?;
        Ok(u16::from_be_bytes(len_bytes) as usize)
    }
}

/// Build a 12-byte ChaCha20 nonce from a u64 counter (spec §9.4.1.4).
///
/// ```text
/// nonce(n) = uint64_le(n) || 4_zero_bytes
/// ```
pub fn make_nonce(counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::{FrameDecoder, FrameEncoder, FRAME_BINARY, FRAME_JSON};

    fn test_key() -> [u8; 32] {
        [0x42u8; 32]
    }

    #[test]
    fn json_frame_roundtrip() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);
        let mut dec = FrameDecoder::new(key);

        let json = r#"{"t":"room.message","n":"ARTA"}"#;
        let wire = enc.encode_json(json).expect("encode");
        let (frame_type, data) = dec.decode(&wire).expect("decode");

        assert_eq!(frame_type, FRAME_JSON);
        assert_eq!(std::str::from_utf8(&data).unwrap(), json);
    }

    #[test]
    fn binary_frame_roundtrip() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);
        let mut dec = FrameDecoder::new(key);

        let hash = [0xabu8; 32];
        let piece_data = b"piece content here";
        let wire = enc.encode_binary(&hash, piece_data).expect("encode");
        let (frame_type, data) = dec.decode(&wire).expect("decode");

        assert_eq!(frame_type, FRAME_BINARY);
        assert_eq!(&data[..32], &hash);
        assert_eq!(&data[32..], piece_data);
    }

    #[test]
    fn counter_advances_per_frame() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);
        let mut dec = FrameDecoder::new(key);

        for i in 0..5u64 {
            assert_eq!(enc.counter, i * 2);
            let wire = enc.encode_json("{}").expect("encode");
            assert_eq!(dec.counter, i * 2);
            dec.decode(&wire).expect("decode");
        }
    }

    #[test]
    fn wrong_key_fails_authentication() {
        let key_a = [0x11u8; 32];
        let key_b = [0x22u8; 32];
        let mut enc = FrameEncoder::new(key_a);
        let mut dec = FrameDecoder::new(key_b);

        let wire = enc.encode_json(r#"{"secret": true}"#).expect("encode");
        assert!(dec.decode(&wire).is_err());
    }

    #[test]
    fn tampered_wire_fails_authentication() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);
        let mut dec = FrameDecoder::new(key);

        let mut wire = enc.encode_json("{}").expect("encode");
        // Flip a bit in the content AEAD portion.
        let last = wire.last_mut().unwrap();
        *last ^= 0xff;
        assert!(dec.decode(&wire).is_err());
    }

    #[test]
    fn encode_empty_json_works() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);
        let mut dec = FrameDecoder::new(key);

        let wire = enc.encode_json("{}").expect("encode");
        let (t, data) = dec.decode(&wire).expect("decode");
        assert_eq!(t, FRAME_JSON);
        assert_eq!(&data, b"{}");
    }

    #[test]
    fn multiple_frames_sequential() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);
        let mut dec = FrameDecoder::new(key);

        let msgs = ["first", "second", "third"];
        let mut wires: Vec<Vec<u8>> = msgs.iter().map(|m| enc.encode_json(m).unwrap()).collect();
        // Decode must be in same order.
        for (wire, expected) in wires.iter_mut().zip(msgs.iter()) {
            let (_, data) = dec.decode(wire).expect("decode");
            assert_eq!(std::str::from_utf8(&data).unwrap(), *expected);
        }
    }

    #[test]
    fn decode_content_len_does_not_advance_counter() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);
        let dec = FrameDecoder::new(key);

        let wire = enc.encode_json(r#"{"msg":1}"#).expect("encode");
        let len_aead: [u8; 18] = wire[..18].try_into().unwrap();

        // peek at len without advancing
        let content_len = dec.decode_content_len(&len_aead).expect("peek len");
        assert_eq!(content_len, 1 + r#"{"msg":1}"#.len()); // type byte + json

        // counter still at 0, so full decode should work
        let mut dec2 = FrameDecoder::new(key);
        let (_, data) = dec2.decode(&wire).expect("decode");
        assert_eq!(std::str::from_utf8(&data).unwrap(), r#"{"msg":1}"#);
    }

    #[test]
    fn wire_size_is_exactly_18_plus_content_plus_16() {
        let key = test_key();
        let mut enc = FrameEncoder::new(key);

        let json = r#"{"a":1}"#;
        let wire = enc.encode_json(json).expect("encode");
        // 18 (len_aead) + 1 (type) + json.len() + 16 (content_aead tag)
        assert_eq!(wire.len(), 18 + 1 + json.len() + 16);
    }
}
