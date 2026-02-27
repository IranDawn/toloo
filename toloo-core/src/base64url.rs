use anyhow::Result;
use base64ct::{Base64UrlUnpadded, Encoding};

/// URL-safe base64 encoding without padding.
pub fn encode(bytes: &[u8]) -> String {
    Base64UrlUnpadded::encode_string(bytes)
}

/// URL-safe base64 decoding without padding.
pub fn decode(s: &str) -> Result<Vec<u8>> {
    Ok(Base64UrlUnpadded::decode_vec(s)?)
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};

    #[test]
    fn encodes_zero_32_bytes_to_expected_value() {
        let input = vec![0u8; 32];
        let got = encode(&input);
        assert_eq!(got, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");
    }

    #[test]
    fn roundtrips_bytes() {
        let input: Vec<u8> = (0..=63).collect();
        let encoded = encode(&input);
        let decoded = decode(&encoded).expect("decode should succeed");
        assert_eq!(decoded, input);
    }

    #[test]
    fn rejects_invalid_input() {
        assert!(decode("a+b/").is_err());
        assert!(decode("AA==").is_err());
    }
}
