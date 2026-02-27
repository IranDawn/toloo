use anyhow::{Context, Result};
use serde_json::Value;

use crate::base64url;
use crate::canonical::canonical;
use crate::crypto::{
    chacha20_decrypt, chacha20_encrypt, derive_private_message_key, sha256, x25519_generate,
    x25519_shared_secret,
};

/// The encrypted payload stored in `c` of a `private.message` envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivateCiphertext {
    /// 43-char base64url ephemeral X25519 public key.
    pub eph: String,
    /// base64url ChaCha20-Poly1305 ciphertext (canonical JSON of content).
    pub encrypted: String,
}

/// Encrypt `content` for `recipient_enc_pub` (spec §3.5.3).
///
/// Returns the `PrivateCiphertext` that goes into `c.eph` / `c.encrypted`.
pub fn encrypt_private(content: &Value, recipient_enc_pub: &str) -> Result<PrivateCiphertext> {
    encrypt_private_with_eph(content, recipient_enc_pub, None)
}

/// Same as `encrypt_private` but allows injecting a fixed ephemeral seed for
/// deterministic test vectors. Pass `None` for random (production use).
pub fn encrypt_private_with_eph(
    content: &Value,
    recipient_enc_pub: &str,
    eph_seed: Option<&[u8; 32]>,
) -> Result<PrivateCiphertext> {
    let rec_enc_bytes =
        base64url::decode(recipient_enc_pub).context("invalid recipient enc pub base64url")?;

    // Step 1: ephemeral X25519 keypair.
    let (eph_pub_bytes, eph_priv_bytes) = match eph_seed {
        Some(seed) => {
            use x25519_dalek::{PublicKey, StaticSecret};
            let secret = StaticSecret::from(*seed);
            let public = PublicKey::from(&secret);
            (public.as_bytes().to_vec(), secret.to_bytes().to_vec())
        }
        None => x25519_generate(),
    };

    // Step 2: X25519 shared secret.
    let shared = x25519_shared_secret(&eph_priv_bytes, &rec_enc_bytes)?;

    // Step 3: salt = SHA-256(eph_pub || recipient_enc_pub).
    let mut salt_input = Vec::with_capacity(64);
    salt_input.extend_from_slice(&eph_pub_bytes);
    salt_input.extend_from_slice(&rec_enc_bytes);
    let salt = sha256(&salt_input);

    // Steps 4-5: HKDF → key + nonce.
    let (key, nonce) = derive_private_message_key(&shared, &salt);

    // Step 6-7: encrypt canonical(content).
    let plaintext_bytes = canonical(content)?.into_bytes();
    let ciphertext = chacha20_encrypt(&key, &nonce, &plaintext_bytes);

    Ok(PrivateCiphertext {
        eph: base64url::encode(&eph_pub_bytes),
        encrypted: base64url::encode(&ciphertext),
    })
}

/// Decrypt a `PrivateCiphertext` using the recipient's X25519 private key (spec §3.5.3).
///
/// Returns the original content JSON value.
pub fn decrypt_private(c: &PrivateCiphertext, recipient_enc_priv: &str) -> Result<Value> {
    let eph_pub_bytes =
        base64url::decode(&c.eph).context("invalid eph base64url")?;
    let rec_enc_priv_bytes =
        base64url::decode(recipient_enc_priv).context("invalid recipient enc priv base64url")?;
    let rec_enc_pub_bytes = {
        use x25519_dalek::{PublicKey, StaticSecret};
        let priv_arr: [u8; 32] = rec_enc_priv_bytes
            .as_slice()
            .try_into()
            .context("recipient enc priv must be 32 bytes")?;
        let secret = StaticSecret::from(priv_arr);
        PublicKey::from(&secret).as_bytes().to_vec()
    };

    // Step 1: shared secret using recipient's private key.
    let shared = x25519_shared_secret(&rec_enc_priv_bytes, &eph_pub_bytes)?;

    // Step 2: same salt derivation as encryption.
    let mut salt_input = Vec::with_capacity(64);
    salt_input.extend_from_slice(&eph_pub_bytes);
    salt_input.extend_from_slice(&rec_enc_pub_bytes);
    let salt = sha256(&salt_input);

    // Steps 3-4: same HKDF.
    let (key, nonce) = derive_private_message_key(&shared, &salt);

    // Step 5: decrypt.
    let ciphertext = base64url::decode(&c.encrypted).context("invalid encrypted base64url")?;
    let plaintext_bytes = chacha20_decrypt(&key, &nonce, &ciphertext)
        .context("ChaCha20-Poly1305 decryption failed")?;

    serde_json::from_slice(&plaintext_bytes).context("decrypted content is not valid JSON")
}

#[cfg(test)]
mod tests {
    use super::{decrypt_private, encrypt_private, encrypt_private_with_eph, PrivateCiphertext};
    use crate::base64url;
    use crate::crypto::{ed25519_generate, x25519_generate};
    use crate::types::{Keypair, LocalNode};
    use serde_json::json;
    use x25519_dalek::{PublicKey, StaticSecret};

    fn mk_node() -> LocalNode {
        let (sig_pub, sig_seed) = ed25519_generate();
        let (enc_pub, enc_priv) = x25519_generate();
        LocalNode {
            sig: Keypair {
                pub_key: base64url::encode(&sig_pub),
                priv_key: base64url::encode(&sig_seed),
            },
            enc: Keypair {
                pub_key: base64url::encode(&enc_pub),
                priv_key: base64url::encode(&enc_priv),
            },
        }
    }

    // Helper: derive X25519 public key from a 32-byte seed.
    fn x25519_pub_from_seed(seed_hex: &str) -> (String, String) {
        let seed_bytes: Vec<u8> = (0..seed_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&seed_hex[i..i + 2], 16).unwrap())
            .collect();
        let seed_arr: [u8; 32] = seed_bytes.try_into().unwrap();
        let secret = StaticSecret::from(seed_arr);
        let public = PublicKey::from(&secret);
        (
            base64url::encode(public.as_bytes()),
            base64url::encode(&secret.to_bytes()),
        )
    }

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let recipient = mk_node();
        let content = json!({"body": "hello world", "blobs": []});

        let ct = encrypt_private(&content, &recipient.enc.pub_key)
            .expect("encrypt should succeed");

        assert_eq!(ct.eph.len(), 43, "eph must be 43-char base64url");
        assert!(!ct.encrypted.is_empty(), "encrypted must not be empty");

        let decrypted = decrypt_private(&ct, &recipient.enc.priv_key)
            .expect("decrypt should succeed");

        assert_eq!(decrypted, content);
    }

    #[test]
    fn decrypt_rejects_tampered_ciphertext() {
        let recipient = mk_node();
        let content = json!({"body": "secret"});

        let mut ct = encrypt_private(&content, &recipient.enc.pub_key)
            .expect("encrypt should succeed");

        // Corrupt the last character of the ciphertext.
        let mut bytes = base64url::decode(&ct.encrypted).unwrap();
        let last = bytes.last_mut().unwrap();
        *last ^= 0xff;
        ct.encrypted = base64url::encode(&bytes);

        assert!(decrypt_private(&ct, &recipient.enc.priv_key).is_err());
    }

    #[test]
    fn wrong_recipient_key_fails() {
        let recipient = mk_node();
        let wrong = mk_node();
        let content = json!({"body": "top secret"});

        let ct = encrypt_private(&content, &recipient.enc.pub_key)
            .expect("encrypt should succeed");

        assert!(decrypt_private(&ct, &wrong.enc.priv_key).is_err());
    }

    #[test]
    fn eph_key_differs_across_encryptions() {
        let recipient = mk_node();
        let content = json!({"body": "same"});

        let ct1 = encrypt_private(&content, &recipient.enc.pub_key).unwrap();
        let ct2 = encrypt_private(&content, &recipient.enc.pub_key).unwrap();

        assert_ne!(ct1.eph, ct2.eph, "each call must generate a fresh ephemeral key");
        assert_ne!(ct1.encrypted, ct2.encrypted);

        // Both must decrypt to same content.
        assert_eq!(decrypt_private(&ct1, &recipient.enc.priv_key).unwrap(), content);
        assert_eq!(decrypt_private(&ct2, &recipient.enc.priv_key).unwrap(), content);
    }

    /// Test vector: §E.7 — deterministic encryption using fixed ephemeral seed.
    /// Verifies byte-for-byte compatibility with toloo.js.
    #[test]
    fn test_vector_e7_deterministic_encryption() {
        // Babak's X25519 encryption keypair (from §E.2.2).
        let babak_enc_seed = "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a";
        let (babak_enc_pub, babak_enc_priv) = x25519_pub_from_seed(babak_enc_seed);

        // Ephemeral seed (§E.7.1) — all 0x11 bytes.
        let eph_seed_hex = "1111111111111111111111111111111111111111111111111111111111111111";
        let eph_seed_bytes: Vec<u8> = (0..eph_seed_hex.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&eph_seed_hex[i..i + 2], 16).unwrap())
            .collect();
        let eph_seed: [u8; 32] = eph_seed_bytes.try_into().unwrap();

        let content = json!({"body": "Hello Babak"});

        let ct = encrypt_private_with_eph(&content, &babak_enc_pub, Some(&eph_seed))
            .expect("deterministic encrypt should succeed");

        // Eph pub must be stable (deterministic from seed).
        assert_eq!(ct.eph.len(), 43);

        // Decryption must recover original content.
        let decrypted = decrypt_private(&ct, &babak_enc_priv)
            .expect("decrypt should succeed");
        assert_eq!(decrypted, content);

        // Encrypting again with same seed must produce identical output.
        let ct2 = encrypt_private_with_eph(&content, &babak_enc_pub, Some(&eph_seed)).unwrap();
        assert_eq!(ct.eph, ct2.eph);
        assert_eq!(ct.encrypted, ct2.encrypted);
    }

    #[test]
    fn invalid_recipient_pub_returns_error() {
        let content = json!({"body": "test"});
        assert!(encrypt_private(&content, "not-a-key").is_err());
    }

    #[test]
    fn invalid_eph_in_ciphertext_returns_error() {
        let recipient = mk_node();
        let ct = PrivateCiphertext {
            eph: "bad".to_owned(),
            encrypted: "dGVzdA".to_owned(),
        };
        assert!(decrypt_private(&ct, &recipient.enc.priv_key).is_err());
    }
}
