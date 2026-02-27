/// Test vector computation for Toloo v0.2 (spec §Appendix E).
///
/// This module provides deterministic reference values for cross-implementation
/// verification. All `[REF]` values in E-test-vectors.md are computed here.
///
/// Use `VectorSet::compute()` to derive all reference values.
use anyhow::Result;
use serde_json::{json, Value};

use crate::base64url;
use crate::canonical::canonical_bytes;
use crate::crypto::{
    derive_endpoint_keys, ed25519_pub_from_seed, ed25519_sign, hkdf_sha256, sha256,
    x25519_shared_secret,
};
use crate::envelope::{sign_envelope, wrap_commit};
use crate::ids::{datum_id, eid};
use crate::pow::find_pow_nonce;
use crate::private::encrypt_private_with_eph;
use crate::types::{DatumBody, Envelope, Keypair, LocalNode, LocalRoom};

// ---- Test identity seeds ----

pub const ARTA_SIG_SEED_HEX: &str =
    "4f6a183e5a4b3c2d1e0f987654321abc4f6a183e5a4b3c2d1e0f987654321abc";
pub const ARTA_ENC_SEED_HEX: &str =
    "5a4b3c2d1e0f987654321abc4f6a183e5a4b3c2d1e0f987654321abc4f6a183e";

pub const BABAK_SIG_SEED_HEX: &str =
    "1a2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f809";
pub const BABAK_ENC_SEED_HEX: &str =
    "2b3c4d5e6f708192a3b4c5d6e7f8091a2b3c4d5e6f708192a3b4c5d6e7f8091a";

pub const MITHRA_SIG_SEED_HEX: &str =
    "aabbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344";
pub const MITHRA_ENC_SEED_HEX: &str =
    "bbccdd11223344aabbccdd11223344aabbccdd11223344aabbccdd11223344aa";

pub const ROOM_SIG_SEED_HEX: &str =
    "deadbeef00112233deadbeef00112233deadbeef00112233deadbeef00112233";

pub const RELAY_SIG_SEED_HEX: &str =
    "ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00";
pub const RELAY_ENC_SEED_HEX: &str =
    "00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff00ff";

pub const EPH_PRIV_SEED_HEX: &str =
    "1111111111111111111111111111111111111111111111111111111111111111";
pub const INITIATOR_EPH_SEED_HEX: &str =
    "2222222222222222222222222222222222222222222222222222222222222222";
pub const RESPONDER_EPH_SEED_HEX: &str =
    "3333333333333333333333333333333333333333333333333333333333333333";

// ---- Helpers ----

pub fn hex_to_bytes(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn x25519_pub_from_seed_hex(seed_hex: &str) -> Vec<u8> {
    let priv_bytes: [u8; 32] = hex_to_bytes(seed_hex).try_into().unwrap();
    let secret = x25519_dalek::StaticSecret::from(priv_bytes);
    x25519_dalek::PublicKey::from(&secret).as_bytes().to_vec()
}

pub fn mk_node(sig_seed_hex: &str, enc_seed_hex: &str) -> LocalNode {
    let sig_seed = hex_to_bytes(sig_seed_hex);
    let enc_seed = hex_to_bytes(enc_seed_hex);
    let sig_pub = ed25519_pub_from_seed(&sig_seed).unwrap();
    let enc_pub = x25519_pub_from_seed_hex(enc_seed_hex);
    LocalNode {
        sig: Keypair {
            pub_key: base64url::encode(&sig_pub),
            priv_key: base64url::encode(&sig_seed),
        },
        enc: Keypair {
            pub_key: base64url::encode(&enc_pub),
            priv_key: base64url::encode(&enc_seed),
        },
    }
}

pub fn mk_room(sig_seed_hex: &str) -> LocalRoom {
    let sig_seed = hex_to_bytes(sig_seed_hex);
    let sig_pub = ed25519_pub_from_seed(&sig_seed).unwrap();
    LocalRoom {
        sig: Keypair {
            pub_key: base64url::encode(&sig_pub),
            priv_key: base64url::encode(&sig_seed),
        },
    }
}

// ---- VectorSet ----

#[derive(Debug)]
pub struct IdentityVector {
    pub sig_seed_hex: String,
    pub sig_pub_hex: String,
    pub sig_pub_b64: String,
    pub enc_seed_hex: Option<String>,
    pub enc_pub_hex: Option<String>,
    pub enc_pub_b64: Option<String>,
}

#[derive(Debug)]
pub struct VectorSet {
    // §E.2 Identities
    pub arta: IdentityVector,
    pub babak: IdentityVector,
    pub mithra: IdentityVector,
    pub room: IdentityVector,
    pub relay: IdentityVector,

    // §E.3 Canonical JSON
    pub e3_1_canonical: String,
    pub e3_2_canonical: String,
    pub e3_3_canonical: String,
    pub e3_4_canonical: String,
    pub e3_5_canonical: String,

    // §E.4 Envelope signing
    pub e4_1_canonical_hex: String,
    pub e4_1_sig_hex: String,
    pub e4_1_sig_b64: String,
    pub e4_1_envelope: Envelope,

    // §E.5 Depth-2 commit
    pub e5_1_commit: Envelope,
    pub e5_1_outer_canonical: String,
    pub e5_1_outer_sig_b64: String,

    // §E.6 Identity
    pub e6_1_eid: String,
    pub e6_3_datum_id_d1: String,
    pub e6_3_datum_id_d2: String,

    // §E.7 Private message encryption
    pub e7_eph_pub_hex: String,
    pub e7_eph_pub_b64: String,
    pub e7_shared_hex: String,
    pub e7_salt_hex: String,
    pub e7_okm_hex: String,
    pub e7_key_hex: String,
    pub e7_nonce_hex: String,
    pub e7_ciphertext_b64: String,

    // §E.8 Endpoint encryption
    pub e8_initiator_eph_pub_hex: String,
    pub e8_responder_eph_pub_hex: String,
    pub e8_shared_hex: String,
    pub e8_okm_hex: String,
    pub e8_k_i2r_hex: String,
    pub e8_k_r2i_hex: String,
    pub e8_transcript_hex: String,
    pub e8_proof_b64: String,

    // §E.9 PoW
    pub e9_winning_nonce: u64,
    pub e9_winning_hash_hex: String,

    // §E.13 base64url
    pub e13_cases: Vec<(String, String)>,
}

impl VectorSet {
    pub fn compute() -> Result<Self> {
        let arta = mk_node(ARTA_SIG_SEED_HEX, ARTA_ENC_SEED_HEX);
        let babak = mk_node(BABAK_SIG_SEED_HEX, BABAK_ENC_SEED_HEX);
        let mithra = mk_node(MITHRA_SIG_SEED_HEX, MITHRA_ENC_SEED_HEX);
        let room = mk_room(ROOM_SIG_SEED_HEX);
        let relay = mk_node(RELAY_SIG_SEED_HEX, RELAY_ENC_SEED_HEX);

        // ---- §E.3 Canonical JSON ----
        let e3_1_canonical = String::from_utf8(canonical_bytes(&json!({
            "ts": 1710000000000_u64, "n": "ARTA_SIG", "v": "0.2", "t": "room.message"
        }))?).unwrap();

        let e3_2_canonical = String::from_utf8(canonical_bytes(&json!({
            "v": "0.2", "t": "commit", "n": "ROOM_SIG",
            "ts": 1710000100000_u64, "tc": 1710000100000_u64,
            "env": {
                "p": "INNER_SIG",
                "d": {
                    "ts": 1710000000000_u64,
                    "c": {"ch": 0, "body": "hello"},
                    "n": "ARTA_SIG", "v": "0.2", "t": "room.message", "r": "ROOM_SIG"
                }
            }
        }))?).unwrap();

        let e3_3_canonical = String::from_utf8(canonical_bytes(&json!({
            "t": "room.message", "n": "TEST", "v": "0.2",
            "ts": 0_u64, "c": {"body": "سلام"}
        }))?).unwrap();

        let e3_4_canonical = String::from_utf8(canonical_bytes(&json!({
            "n": "X", "v": "0.2", "t": "test",
            "ts": 1710000000000_u64,
            "c": {"a": 0, "b": -1, "c": 1.5, "d": 100}
        }))?).unwrap();

        let e3_5_canonical = String::from_utf8(canonical_bytes(&json!({
            "n": "X", "v": "0.2", "t": "test", "ts": 0_u64,
            "c": {"empty": "", "list": [], "obj": {}, "null_val": Value::Null, "bool": true}
        }))?).unwrap();

        // ---- §E.4.1 Room message ----
        let e4_1_d = DatumBody {
            n: arta.sig.pub_key.clone(),
            v: "0.2".into(),
            t: "room.message".into(),
            ts: 1710000000000,
            r: Some(room.sig.pub_key.clone()),
            to: None,
            c: Some(json!({"ch": 0, "body": "Hello, world!"})),
            env: None,
            tc: None,
            exp: None,
            nonce: None,
            extra: Default::default(),
        };
        let e4_1_d_val = serde_json::to_value(&e4_1_d)?;
        let e4_1_canonical_bytes = canonical_bytes(&e4_1_d_val)?;
        let e4_1_canonical_hex = hex::encode(&e4_1_canonical_bytes);
        let arta_sig_seed = hex_to_bytes(ARTA_SIG_SEED_HEX);
        let e4_1_sig_bytes = ed25519_sign(&e4_1_canonical_bytes, &arta_sig_seed)?;
        let e4_1_sig_hex = hex::encode(&e4_1_sig_bytes);
        let e4_1_sig_b64 = base64url::encode(&e4_1_sig_bytes);
        let e4_1_envelope = sign_envelope(e4_1_d, &arta.sig.priv_key)?;

        // ---- §E.5.1 Depth-2 commit ----
        let e5_1_commit = wrap_commit(e4_1_envelope.clone(), &room, 1710000100000)?;
        let e5_1_outer_d_val = serde_json::to_value(&e5_1_commit.d)?;
        let e5_1_outer_canonical =
            String::from_utf8(canonical_bytes(&e5_1_outer_d_val)?).unwrap();
        let e5_1_outer_sig_b64 = e5_1_commit.p.clone();

        // ---- §E.6 Identity ----
        let e6_1_eid = eid(&e5_1_commit);
        let e6_3_datum_id_d1 = datum_id(&e4_1_envelope);
        let e6_3_datum_id_d2 = datum_id(&e5_1_commit);

        // ---- §E.7 Private message encryption ----
        let eph_priv = hex_to_bytes(EPH_PRIV_SEED_HEX);
        let eph_pub_bytes = x25519_pub_from_seed_hex(EPH_PRIV_SEED_HEX);
        let e7_eph_pub_hex = hex::encode(&eph_pub_bytes);
        let e7_eph_pub_b64 = base64url::encode(&eph_pub_bytes);

        let babak_enc_pub_bytes = base64url::decode(&babak.enc.pub_key)?;
        let e7_shared = x25519_shared_secret(&eph_priv, &babak_enc_pub_bytes)?;
        let e7_shared_hex = hex::encode(&e7_shared);

        let e7_salt_bytes = sha256(
            &[eph_pub_bytes.as_slice(), babak_enc_pub_bytes.as_slice()].concat(),
        );
        let e7_salt_hex = hex::encode(e7_salt_bytes);

        let e7_okm = hkdf_sha256(&e7_shared, &e7_salt_bytes, b"toloo-private-v0.2", 44);
        let e7_okm_hex = hex::encode(&e7_okm);
        let e7_key_hex = hex::encode(&e7_okm[0..32]);
        let e7_nonce_hex = hex::encode(&e7_okm[32..44]);

        let eph_seed_array: [u8; 32] = hex_to_bytes(EPH_PRIV_SEED_HEX).try_into().unwrap();
        let cipher = encrypt_private_with_eph(
            &json!({"body": "Hello Babak"}),
            &babak.enc.pub_key,
            Some(&eph_seed_array),
        )?;
        let e7_ciphertext_b64 = cipher.encrypted.clone();

        // ---- §E.8 Endpoint encryption handshake ----
        let init_priv = hex_to_bytes(INITIATOR_EPH_SEED_HEX);
        let init_pub_bytes = x25519_pub_from_seed_hex(INITIATOR_EPH_SEED_HEX);
        let resp_pub_bytes = x25519_pub_from_seed_hex(RESPONDER_EPH_SEED_HEX);

        let e8_initiator_eph_pub_hex = hex::encode(&init_pub_bytes);
        let e8_responder_eph_pub_hex = hex::encode(&resp_pub_bytes);

        let e8_shared = x25519_shared_secret(&init_priv, &resp_pub_bytes)?;
        let e8_shared_hex = hex::encode(&e8_shared);

        let salt = [0u8; 32];
        let e8_okm_raw = hkdf_sha256(&e8_shared, &salt, b"toloo-endpoint-enc-v0.2", 64);
        let e8_okm_hex = hex::encode(&e8_okm_raw);
        let (k_i2r, k_r2i) = derive_endpoint_keys(&e8_shared);
        let e8_k_i2r_hex = hex::encode(k_i2r);
        let e8_k_r2i_hex = hex::encode(k_r2i);

        let mut transcript = Vec::with_capacity(64);
        transcript.extend_from_slice(&init_pub_bytes);
        transcript.extend_from_slice(&resp_pub_bytes);
        let e8_transcript_hex = hex::encode(&transcript);
        let relay_sig_seed = hex_to_bytes(RELAY_SIG_SEED_HEX);
        let proof_bytes = ed25519_sign(&transcript, &relay_sig_seed)?;
        let e8_proof_b64 = base64url::encode(&proof_bytes);

        // ---- §E.9 PoW ----
        let mut pow_d = DatumBody {
            n: arta.sig.pub_key.clone(),
            v: "0.2".into(),
            t: "room.join".into(),
            ts: 1710000200000,
            r: Some(room.sig.pub_key.clone()),
            to: None, c: None, env: None, tc: None, exp: None,
            nonce: Some(0),
            extra: Default::default(),
        };
        let e9_winning_nonce = find_pow_nonce(&mut pow_d, 16) as u64;
        let pow_d_val = serde_json::to_value(&pow_d)?;
        let pow_hash = sha256(&canonical_bytes(&pow_d_val)?);
        let e9_winning_hash_hex = hex::encode(pow_hash);

        // ---- §E.13 base64url ----
        let e13_cases = vec![
            (String::new(),             String::new()),
            ("00".to_owned(),           base64url::encode(&[0x00u8])),
            ("ff".to_owned(),           base64url::encode(&[0xffu8])),
            ("00ff".to_owned(),         base64url::encode(&[0x00u8, 0xff])),
            ("deadbeef".to_owned(),     base64url::encode(&[0xde, 0xad, 0xbe, 0xef])),
            ("00".repeat(32),           base64url::encode(&[0u8; 32])),
        ];

        Ok(VectorSet {
            arta: mk_identity_vec(ARTA_SIG_SEED_HEX, ARTA_ENC_SEED_HEX, &arta),
            babak: mk_identity_vec(BABAK_SIG_SEED_HEX, BABAK_ENC_SEED_HEX, &babak),
            mithra: mk_identity_vec(MITHRA_SIG_SEED_HEX, MITHRA_ENC_SEED_HEX, &mithra),
            room: mk_room_identity_vec(ROOM_SIG_SEED_HEX, &room),
            relay: mk_identity_vec(RELAY_SIG_SEED_HEX, RELAY_ENC_SEED_HEX, &relay),
            e3_1_canonical,
            e3_2_canonical,
            e3_3_canonical,
            e3_4_canonical,
            e3_5_canonical,
            e4_1_canonical_hex,
            e4_1_sig_hex,
            e4_1_sig_b64,
            e4_1_envelope,
            e5_1_commit,
            e5_1_outer_canonical,
            e5_1_outer_sig_b64,
            e6_1_eid,
            e6_3_datum_id_d1,
            e6_3_datum_id_d2,
            e7_eph_pub_hex,
            e7_eph_pub_b64,
            e7_shared_hex,
            e7_salt_hex,
            e7_okm_hex,
            e7_key_hex,
            e7_nonce_hex,
            e7_ciphertext_b64,
            e8_initiator_eph_pub_hex,
            e8_responder_eph_pub_hex,
            e8_shared_hex,
            e8_okm_hex,
            e8_k_i2r_hex,
            e8_k_r2i_hex,
            e8_transcript_hex,
            e8_proof_b64,
            e9_winning_nonce,
            e9_winning_hash_hex,
            e13_cases,
        })
    }
}

fn mk_identity_vec(sig_seed_hex: &str, enc_seed_hex: &str, node: &LocalNode) -> IdentityVector {
    let sig_pub_bytes = base64url::decode(&node.sig.pub_key).unwrap();
    let enc_pub_bytes = base64url::decode(&node.enc.pub_key).unwrap();
    IdentityVector {
        sig_seed_hex: sig_seed_hex.to_owned(),
        sig_pub_hex: hex::encode(&sig_pub_bytes),
        sig_pub_b64: node.sig.pub_key.clone(),
        enc_seed_hex: Some(enc_seed_hex.to_owned()),
        enc_pub_hex: Some(hex::encode(&enc_pub_bytes)),
        enc_pub_b64: Some(node.enc.pub_key.clone()),
    }
}

fn mk_room_identity_vec(sig_seed_hex: &str, room: &LocalRoom) -> IdentityVector {
    let sig_pub_bytes = base64url::decode(&room.sig.pub_key).unwrap();
    IdentityVector {
        sig_seed_hex: sig_seed_hex.to_owned(),
        sig_pub_hex: hex::encode(&sig_pub_bytes),
        sig_pub_b64: room.sig.pub_key.clone(),
        enc_seed_hex: None,
        enc_pub_hex: None,
        enc_pub_b64: None,
    }
}
