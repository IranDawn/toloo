use anyhow::{anyhow, Context, Result};
use chacha20poly1305::aead::Aead;
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use hkdf::Hkdf;
use rand_core::OsRng;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};
use zeroize::Zeroizing;

const ED25519_KEY_LEN: usize = 32;
const ED25519_SIG_LEN: usize = 64;
const ENDPOINT_INFO: &[u8] = b"toloo-endpoint-enc-v0.2";
const PRIVATE_INFO: &[u8] = b"toloo-private-v0.2";

/// Generate an Ed25519 keypair (public key, seed).
pub fn ed25519_generate() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let signing = SigningKey::generate(&mut rng);
    let verifying = signing.verifying_key();
    (verifying.to_bytes().to_vec(), signing.to_bytes().to_vec())
}

/// Derive Ed25519 public key from a 32-byte seed.
pub fn ed25519_pub_from_seed(seed: &[u8]) -> Result<Vec<u8>> {
    let seed_bytes = seed32(seed, "Ed25519 seed")?;
    let signing = SigningKey::from_bytes(&seed_bytes);
    Ok(signing.verifying_key().to_bytes().to_vec())
}

/// Sign a message with a 32-byte Ed25519 seed.
pub fn ed25519_sign(message: &[u8], seed: &[u8]) -> Result<Vec<u8>> {
    let seed_bytes = seed32(seed, "Ed25519 seed")?;
    let signing = SigningKey::from_bytes(&seed_bytes);
    let signature: Signature = signing.sign(message);
    Ok(signature.to_bytes().to_vec())
}

/// Verify Ed25519 signature.
pub fn ed25519_verify(message: &[u8], sig: &[u8], pub_key: &[u8]) -> Result<()> {
    let sig_bytes = seed64(sig, "Ed25519 signature")?;
    let pub_bytes = seed32(pub_key, "Ed25519 public key")?;
    let verifying =
        VerifyingKey::from_bytes(&pub_bytes).context("invalid Ed25519 public key bytes")?;
    let signature = Signature::from_bytes(&sig_bytes);

    // Verification in dalek uses constant-time internals for signature checks.
    verifying
        .verify(message, &signature)
        .context("Ed25519 signature verification failed")
}

/// Generate an X25519 keypair (public key, private key).
pub fn x25519_generate() -> (Vec<u8>, Vec<u8>) {
    let mut rng = OsRng;
    let secret = StaticSecret::random_from_rng(&mut rng);
    let public = PublicKey::from(&secret);
    (public.as_bytes().to_vec(), secret.to_bytes().to_vec())
}

/// Compute X25519 shared secret.
pub fn x25519_shared_secret(my_priv: &[u8], their_pub: &[u8]) -> Result<Vec<u8>> {
    let my_priv_bytes = exact_bytes(my_priv, "X25519 private key")?;
    let their_pub_bytes = exact_bytes(their_pub, "X25519 public key")?;
    let my_secret = StaticSecret::from(*my_priv_bytes);
    let their_public = PublicKey::from(*their_pub_bytes);
    let shared = my_secret.diffie_hellman(&their_public);
    Ok(shared.as_bytes().to_vec())
}

/// SHA-256 digest.
pub fn sha256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

/// Generic HKDF-SHA256.
pub fn hkdf_sha256(ikm: &[u8], salt: &[u8], info: &[u8], length: usize) -> Vec<u8> {
    if length == 0 {
        return Vec::new();
    }
    let hk = Hkdf::<Sha256>::new(Some(salt), ikm);
    let mut okm = vec![0u8; length];
    hk.expand(info, &mut okm)
        .expect("HKDF output length exceeds SHA-256 HKDF limits");
    okm
}

/// Derive endpoint transport keys for the skin handshake.
pub fn derive_endpoint_keys(shared: &[u8]) -> ([u8; 32], [u8; 32]) {
    let salt = [0u8; 32];
    let okm = hkdf_sha256(shared, &salt, ENDPOINT_INFO, 64);
    let mut k_i2r = [0u8; 32];
    let mut k_r2i = [0u8; 32];
    k_i2r.copy_from_slice(&okm[0..32]);
    k_r2i.copy_from_slice(&okm[32..64]);
    (k_i2r, k_r2i)
}

/// Derive private message content key + nonce.
pub fn derive_private_message_key(shared: &[u8], salt: &[u8]) -> ([u8; 32], [u8; 12]) {
    let okm = hkdf_sha256(shared, salt, PRIVATE_INFO, 44);
    let mut key = [0u8; 32];
    let mut nonce = [0u8; 12];
    key.copy_from_slice(&okm[0..32]);
    nonce.copy_from_slice(&okm[32..44]);
    (key, nonce)
}

/// ChaCha20-Poly1305 encryption.
pub fn chacha20_encrypt(key: &[u8; 32], nonce: &[u8; 12], plaintext: &[u8]) -> Vec<u8> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .expect("encryption failed for input length")
}

/// ChaCha20-Poly1305 decryption.
pub fn chacha20_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = ChaCha20Poly1305::new(key.into());
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| anyhow!("ChaCha20-Poly1305 authentication failed"))
}

fn seed32(input: &[u8], name: &str) -> Result<Zeroizing<[u8; ED25519_KEY_LEN]>> {
    exact_bytes(input, name)
}

fn seed64(input: &[u8], name: &str) -> Result<Zeroizing<[u8; ED25519_SIG_LEN]>> {
    exact_bytes(input, name)
}

fn exact_bytes<const N: usize>(input: &[u8], name: &str) -> Result<Zeroizing<[u8; N]>> {
    let bytes: [u8; N] = input
        .try_into()
        .map_err(|_| anyhow!("{name} must be {N} bytes"))?;
    Ok(Zeroizing::new(bytes))
}

#[cfg(test)]
mod tests {
    use hex::encode as hex_encode;

    use super::{
        chacha20_decrypt, chacha20_encrypt, derive_endpoint_keys, derive_private_message_key,
        ed25519_generate, ed25519_pub_from_seed, ed25519_sign, ed25519_verify, hkdf_sha256,
        sha256, x25519_generate, x25519_shared_secret,
    };

    #[test]
    fn ed25519_sign_and_verify_roundtrip() {
        let (pub_key, seed) = ed25519_generate();
        let msg = b"toloo-signature-surface";
        let sig = ed25519_sign(msg, &seed).expect("sign should succeed");
        ed25519_verify(msg, &sig, &pub_key).expect("verify should succeed");
        assert!(ed25519_verify(b"tampered", &sig, &pub_key).is_err());
    }

    #[test]
    fn ed25519_pub_derivation_matches_generated_pub() {
        let (pub_key, seed) = ed25519_generate();
        let derived = ed25519_pub_from_seed(&seed).expect("pub derivation should succeed");
        assert_eq!(derived, pub_key);
    }

    #[test]
    fn x25519_shared_secret_matches_both_directions() {
        let (a_pub, a_priv) = x25519_generate();
        let (b_pub, b_priv) = x25519_generate();
        let ab = x25519_shared_secret(&a_priv, &b_pub).expect("shared secret should succeed");
        let ba = x25519_shared_secret(&b_priv, &a_pub).expect("shared secret should succeed");
        assert_eq!(ab, ba);
        assert_eq!(ab.len(), 32);
    }

    #[test]
    fn sha256_matches_known_vector() {
        let digest = sha256(b"abc");
        assert_eq!(
            hex_encode(digest),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn endpoint_key_derivation_matches_generic_hkdf_split() {
        let shared = [7u8; 32];
        let salt = [0u8; 32];
        let okm = hkdf_sha256(&shared, &salt, b"toloo-endpoint-enc-v0.2", 64);
        let (k_i2r, k_r2i) = derive_endpoint_keys(&shared);
        assert_eq!(&k_i2r[..], &okm[0..32]);
        assert_eq!(&k_r2i[..], &okm[32..64]);
    }

    #[test]
    fn private_message_derivation_has_expected_sizes() {
        let shared = [1u8; 32];
        let salt = [2u8; 32];
        let (key, nonce) = derive_private_message_key(&shared, &salt);
        assert_eq!(key.len(), 32);
        assert_eq!(nonce.len(), 12);
    }

    #[test]
    fn chacha20_encrypt_decrypt_roundtrip_and_detects_tamper() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];
        let plaintext = b"toloo-private-payload";
        let ciphertext = chacha20_encrypt(&key, &nonce, plaintext);
        assert_eq!(ciphertext.len(), plaintext.len() + 16);

        let decrypted = chacha20_decrypt(&key, &nonce, &ciphertext).expect("decrypt should pass");
        assert_eq!(decrypted, plaintext);

        let mut tampered = ciphertext.clone();
        tampered[0] ^= 0x01;
        assert!(chacha20_decrypt(&key, &nonce, &tampered).is_err());
    }
}
