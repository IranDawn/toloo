// Toloo Protocol v0.2 — uniffi FFI bindings
//
// All envelope values cross the boundary as canonical JSON strings.
// Helper functions parse JSON strings into Rust types, call toloo-core/lib,
// and serialize results back to JSON strings.

use toloo_core::base64url;
use toloo_core::canonical::canonical;
use toloo_core::crypto::{ed25519_generate, x25519_generate};
use toloo_core::envelope::{depth, innermost, parse_envelope, verify_chain};
use toloo_core::events::{
    make_node_meta as core_make_node_meta, make_private_message as core_make_private_message,
    make_private_read as core_make_private_read, make_room_ban as core_make_room_ban,
    make_room_create as core_make_room_create, make_room_delete as core_make_room_delete,
    make_room_edit as core_make_room_edit, make_room_invite as core_make_room_invite,
    make_room_join as core_make_room_join, make_room_leave as core_make_room_leave,
    make_room_message as core_make_room_message, make_room_react as core_make_room_react,
    make_room_unban as core_make_room_unban, make_room_update as core_make_room_update,
};
use toloo_core::ids::{datum_id, eid};
use toloo_core::pow::find_pow_nonce;
use toloo_core::private::{
    decrypt_private as core_decrypt_private, encrypt_private as core_encrypt_private,
    PrivateCiphertext as CorePrivateCiphertext,
};
use toloo_core::types::{Envelope, Keypair as CoreKeypair, LocalNode, LocalRoom};
use toloo_lib::discovery::{decode as core_decode, encode_file as core_encode_file, encode_uri as core_encode_uri};

uniffi::include_scaffolding!("toloo");

// ---- Error type ----
// Not annotated with uniffi derives — the UDL scaffolding handles the FFI glue.

#[derive(Debug, thiserror::Error)]
pub enum TolooError {
    #[error("Invalid input: {message}")]
    InvalidInput { message: String },
    #[error("Crypto error: {message}")]
    CryptoError { message: String },
    #[error("Verification failed: {message}")]
    VerificationFailed { message: String },
    #[error("Decryption failed: {message}")]
    DecryptionFailed { message: String },
    #[error("Parse error: {message}")]
    ParseError { message: String },
}

impl From<anyhow::Error> for TolooError {
    fn from(e: anyhow::Error) -> Self {
        TolooError::InvalidInput { message: e.to_string() }
    }
}

// ---- FFI data types ----
// Plain Rust structs — UDL scaffolding generates all FFI trait implementations.

pub struct Keypair {
    pub pub_key: String,
    pub priv_key: String,
}

pub struct NodeIdentity {
    pub sig: Keypair,
    pub enc: Keypair,
}

pub struct RoomIdentity {
    pub sig: Keypair,
}

pub struct PrivateCiphertext {
    pub eph: String,
    pub encrypted: String,
}

// ---- Helpers ----

fn parse_node(node_json: &str) -> Result<LocalNode, TolooError> {
    serde_json::from_str(node_json).map_err(|e| TolooError::ParseError { message: e.to_string() })
}

fn parse_room(room_json: &str) -> Result<LocalRoom, TolooError> {
    serde_json::from_str(room_json).map_err(|e| TolooError::ParseError { message: e.to_string() })
}

fn parse_env(envelope_json: &str) -> Result<Envelope, TolooError> {
    let value: serde_json::Value = serde_json::from_str(envelope_json)
        .map_err(|e| TolooError::ParseError { message: e.to_string() })?;
    parse_envelope(value).map_err(|e| TolooError::ParseError { message: e.to_string() })
}

fn serialize_env(env: &Envelope) -> Result<String, TolooError> {
    serde_json::to_string(env).map_err(|e| TolooError::InvalidInput { message: e.to_string() })
}

fn parse_envs(jsons: Vec<String>) -> Result<Vec<Envelope>, TolooError> {
    jsons.iter().map(|j| parse_env(j)).collect()
}

// ---- Key generation ----

pub fn keygen() -> Result<NodeIdentity, TolooError> {
    let (sig_pub, sig_seed) = ed25519_generate();
    let (enc_pub, enc_priv) = x25519_generate();
    Ok(NodeIdentity {
        sig: Keypair {
            pub_key:  base64url::encode(&sig_pub),
            priv_key: base64url::encode(&sig_seed),
        },
        enc: Keypair {
            pub_key:  base64url::encode(&enc_pub),
            priv_key: base64url::encode(&enc_priv),
        },
    })
}

pub fn room_keygen() -> Result<RoomIdentity, TolooError> {
    let (pub_bytes, seed_bytes) = ed25519_generate();
    Ok(RoomIdentity {
        sig: Keypair {
            pub_key:  base64url::encode(&pub_bytes),
            priv_key: base64url::encode(&seed_bytes),
        },
    })
}

// ---- Node events ----

pub fn make_node_meta(node_json: String) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_node_meta(&node, vec![]).map_err(TolooError::from)?;
    serialize_env(&env)
}

// ---- Room lifecycle ----

pub fn make_room_create(
    node_json: String,
    room_json: String,
    name: Option<String>,
    rules_json: Option<String>,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let room = parse_room(&room_json)?;
    let rules = rules_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e: serde_json::Error| TolooError::ParseError { message: e.to_string() })?;
    let (_authored, committed) = core_make_room_create(&node, &room, name.as_deref(), rules)
        .map_err(TolooError::from)?;
    serialize_env(&committed)
}

pub fn make_room_update(
    node_json: String,
    room_json: String,
    name: Option<String>,
    rules_json: Option<String>,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let room = parse_room(&room_json)?;
    let rules = rules_json
        .as_deref()
        .map(serde_json::from_str)
        .transpose()
        .map_err(|e: serde_json::Error| TolooError::ParseError { message: e.to_string() })?;
    let env = core_make_room_update(&node, &room, name.as_deref(), rules)
        .map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_join(node_json: String, room_pub: String) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_join(&node, &room_pub, None).map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_join_pow(
    node_json: String,
    room_pub: String,
    required_bits: u32,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let mut env = core_make_room_join(&node, &room_pub, None).map_err(TolooError::from)?;
    // Mine PoW nonce on the innermost DatumBody, then re-sign.
    find_pow_nonce(&mut env.d, required_bits);
    let re_signed = toloo_core::envelope::sign_envelope(env.d, &node.sig.priv_key)
        .map_err(TolooError::from)?;
    serialize_env(&re_signed)
}

pub fn make_room_leave(node_json: String, room_pub: String) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_leave(&node, &room_pub).map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_invite(
    node_json: String,
    room_pub: String,
    invitee_pub: String,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_invite(&node, &room_pub, &invitee_pub).map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_ban(
    node_json: String,
    room_pub: String,
    target_pub: String,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_ban(&node, &room_pub, &target_pub, None).map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_unban(
    node_json: String,
    room_pub: String,
    target_pub: String,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_unban(&node, &room_pub, &target_pub).map_err(TolooError::from)?;
    serialize_env(&env)
}

// ---- Room content ----

pub fn make_room_message(
    node_json: String,
    room_pub: String,
    channel: i32,
    body: String,
    blobs: Vec<String>,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_message(&node, &room_pub, channel, &body, blobs)
        .map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_react(
    node_json: String,
    room_pub: String,
    channel: i32,
    target_eid: String,
    emoji: String,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_react(&node, &room_pub, channel, &target_eid, &emoji)
        .map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_edit(
    node_json: String,
    room_pub: String,
    channel: i32,
    target_eid: String,
    body: String,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_edit(&node, &room_pub, channel, &target_eid, &body)
        .map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_room_delete(
    node_json: String,
    room_pub: String,
    channel: i32,
    target_eid: String,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_room_delete(&node, &room_pub, channel, &target_eid)
        .map_err(TolooError::from)?;
    serialize_env(&env)
}

// ---- Private messages ----

pub fn make_private_message(
    node_json: String,
    to_pub: String,
    to_enc_pub: String,
    body: String,
    blobs: Vec<String>,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_private_message(&node, &to_pub, &to_enc_pub, &body, blobs)
        .map_err(TolooError::from)?;
    serialize_env(&env)
}

pub fn make_private_read(
    node_json: String,
    to_pub: String,
    ids: Vec<String>,
) -> Result<String, TolooError> {
    let node = parse_node(&node_json)?;
    let env = core_make_private_read(&node, &to_pub, ids).map_err(TolooError::from)?;
    serialize_env(&env)
}

// ---- Envelope verification ----

pub fn verify_envelope(envelope_json: String) -> Result<(), TolooError> {
    let env = parse_env(&envelope_json)?;
    verify_chain(&env).map_err(|e| TolooError::VerificationFailed { message: e.to_string() })
}

pub fn envelope_eid(envelope_json: String) -> Result<String, TolooError> {
    let env = parse_env(&envelope_json)?;
    Ok(eid(&env))
}

pub fn envelope_datum_id(envelope_json: String) -> Result<String, TolooError> {
    let env = parse_env(&envelope_json)?;
    Ok(datum_id(&env))
}

pub fn envelope_depth(envelope_json: String) -> Result<u8, TolooError> {
    let env = parse_env(&envelope_json)?;
    Ok(depth(&env))
}

// ---- Private message crypto ----

pub fn encrypt_private(
    content_json: String,
    recipient_enc_pub: String,
) -> Result<PrivateCiphertext, TolooError> {
    let content: serde_json::Value = serde_json::from_str(&content_json)
        .map_err(|e| TolooError::ParseError { message: e.to_string() })?;
    let c = core_encrypt_private(&content, &recipient_enc_pub)
        .map_err(|e| TolooError::CryptoError { message: e.to_string() })?;
    Ok(PrivateCiphertext { eph: c.eph, encrypted: c.encrypted })
}

pub fn decrypt_private(
    ciphertext: PrivateCiphertext,
    enc_priv: String,
) -> Result<String, TolooError> {
    let c = CorePrivateCiphertext { eph: ciphertext.eph, encrypted: ciphertext.encrypted };
    let content = core_decrypt_private(&c, &enc_priv)
        .map_err(|e| TolooError::DecryptionFailed { message: e.to_string() })?;
    serde_json::to_string(&content)
        .map_err(|e| TolooError::InvalidInput { message: e.to_string() })
}

// ---- Discovery ----

pub fn encode_uri(envelope_jsons: Vec<String>) -> Result<String, TolooError> {
    let envs = parse_envs(envelope_jsons)?;
    core_encode_uri(&envs).map_err(TolooError::from)
}

pub fn encode_file(envelope_jsons: Vec<String>) -> Result<String, TolooError> {
    let envs = parse_envs(envelope_jsons)?;
    core_encode_file(&envs).map_err(TolooError::from)
}

pub fn decode(input: String) -> Result<Vec<String>, TolooError> {
    let envs = core_decode(&input).map_err(TolooError::from)?;
    envs.iter().map(serialize_env).collect()
}

// ---- Utilities ----

pub fn canonical_json(json: String) -> Result<String, TolooError> {
    let value: serde_json::Value = serde_json::from_str(&json)
        .map_err(|e| TolooError::ParseError { message: e.to_string() })?;
    canonical(&value).map_err(|e| TolooError::InvalidInput { message: e.to_string() })
}

pub fn base64url_encode(data: Vec<u8>) -> Result<String, TolooError> {
    Ok(base64url::encode(&data))
}

pub fn base64url_decode(encoded: String) -> Result<Vec<u8>, TolooError> {
    base64url::decode(&encoded)
        .map_err(|e| TolooError::InvalidInput { message: e.to_string() })
}
