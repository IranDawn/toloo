//! Encrypted-at-rest key storage (§D.15.2).
//!
//! Uses Argon2id to derive an encryption key from a passphrase,
//! then wraps private keys with ChaCha20-Poly1305.

use anyhow::{anyhow, bail, Context, Result};

use crate::base64url;
use crate::crypto::{chacha20_decrypt, chacha20_encrypt};

const SALT_LEN: usize = 16;
const NONCE_LEN: usize = 12;

/// An encrypted key blob: salt + nonce + ciphertext, base64url-encoded.
#[derive(Debug, Clone)]
pub struct EncryptedKey {
    pub blob: String,
}

/// Encrypt a private key (raw bytes) under a passphrase.
pub fn encrypt_key(private_key: &[u8], passphrase: &str) -> Result<EncryptedKey> {
    if passphrase.is_empty() {
        bail!("passphrase must not be empty");
    }

    let salt = generate_salt();
    let derived = derive_key(passphrase, &salt)?;
    let nonce = generate_nonce();
    let ciphertext = chacha20_encrypt(&derived, &nonce, private_key);

    // blob = salt (16) || nonce (12) || ciphertext
    let mut blob = Vec::with_capacity(SALT_LEN + NONCE_LEN + ciphertext.len());
    blob.extend_from_slice(&salt);
    blob.extend_from_slice(&nonce);
    blob.extend_from_slice(&ciphertext);

    Ok(EncryptedKey {
        blob: base64url::encode(&blob),
    })
}

/// Decrypt a private key from an encrypted blob using a passphrase.
pub fn decrypt_key(encrypted: &EncryptedKey, passphrase: &str) -> Result<Vec<u8>> {
    let raw = base64url::decode(&encrypted.blob)
        .context("invalid encrypted key blob encoding")?;

    if raw.len() < SALT_LEN + NONCE_LEN + 16 {
        bail!("encrypted key blob too short");
    }

    let salt = &raw[..SALT_LEN];
    let nonce: [u8; NONCE_LEN] = raw[SALT_LEN..SALT_LEN + NONCE_LEN]
        .try_into()
        .map_err(|_| anyhow!("invalid nonce length"))?;
    let ciphertext = &raw[SALT_LEN + NONCE_LEN..];

    let derived = derive_key(passphrase, salt)?;
    chacha20_decrypt(&derived, &nonce, ciphertext)
        .context("decryption failed — wrong passphrase or corrupted data")
}

/// Derive a 32-byte key from a passphrase and salt using Argon2id.
fn derive_key(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    use argon2::{Argon2, Algorithm, Version, Params};

    let params = Params::new(
        19_456,  // 19 MiB memory
        2,       // 2 iterations
        1,       // 1 lane
        Some(32),
    ).map_err(|e| anyhow!("argon2 params error: {e}"))?;

    let argon2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut output = [0u8; 32];
    argon2
        .hash_password_into(passphrase.as_bytes(), salt, &mut output)
        .map_err(|e| anyhow!("argon2 key derivation failed: {e}"))?;

    Ok(output)
}

fn generate_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(&mut salt);
    salt
}

fn generate_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    use rand_core::{OsRng, RngCore};
    OsRng.fill_bytes(&mut nonce);
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_decrypt_roundtrip() {
        let key = b"my_secret_private_key_32_bytes!!";
        let passphrase = "correct horse battery staple";

        let encrypted = encrypt_key(key, passphrase).expect("encrypt should succeed");
        let decrypted = decrypt_key(&encrypted, passphrase).expect("decrypt should succeed");
        assert_eq!(decrypted, key);
    }

    #[test]
    fn wrong_passphrase_fails() {
        let key = b"my_secret_private_key_32_bytes!!";
        let encrypted = encrypt_key(key, "right").expect("encrypt should succeed");
        assert!(decrypt_key(&encrypted, "wrong").is_err());
    }

    #[test]
    fn empty_passphrase_rejected() {
        assert!(encrypt_key(b"key", "").is_err());
    }

    #[test]
    fn different_encryptions_produce_different_blobs() {
        let key = b"same_key_different_salt";
        let enc1 = encrypt_key(key, "pass").unwrap();
        let enc2 = encrypt_key(key, "pass").unwrap();
        assert_ne!(enc1.blob, enc2.blob, "random salt should produce different blobs");
    }
}
