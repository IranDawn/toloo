use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, bail, Context, Result};
use serde::{Deserialize, Serialize};
use serde_json::{json, Map, Value};

use crate::base64url;
use crate::canonical::canonical;
use crate::crypto::{chacha20_encrypt, derive_private_message_key, sha256, x25519_generate, x25519_shared_secret};
use crate::envelope::{innermost, make_envelope, wrap_commit, DatumBodyExtra};
use crate::types::{DatumBody, EndpointDescriptor, Envelope, LocalNode, LocalRoom};

const MAX_MESSAGE_BODY: usize = 4096;
const MAX_ROOM_NAME: usize = 256;
const MAX_ROOM_DESCRIPTION: usize = 1024;
const MAX_EMOJI: usize = 16;
const MAX_REASON: usize = 250;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct BlobManifest {
    pub hash: String,
    pub size: u64,
    pub piece_size: u64,
    pub pieces: Vec<String>,
}

pub fn make_node_meta(node: &LocalNode, endpoints: Vec<EndpointDescriptor>) -> Result<Envelope> {
    let mut content = Map::new();
    content.insert("enc".to_owned(), json!(node.enc.pub_key));
    if !endpoints.is_empty() {
        content.insert(
            "endpoints".to_owned(),
            serde_json::to_value(&endpoints).context("failed to serialize endpoints")?,
        );
    }
    let env = make_envelope("node.meta", Some(Value::Object(content)), node, None)?;
    validate_event_content(&env)?;
    Ok(env)
}

pub fn make_room_create(
    node: &LocalNode,
    room: &LocalRoom,
    name: Option<&str>,
    rules: Option<Value>,
) -> Result<(Envelope, Envelope)> {
    let mut content = Map::new();
    content.insert(
        "name".to_owned(),
        Value::String(name.unwrap_or("Room").to_owned()),
    );
    if let Some(rules) = rules {
        content.insert("rules".to_owned(), rules);
    }

    let depth1 = make_room_scoped("room.create", node, &room.sig.pub_key, Some(Value::Object(content)))?;
    validate_event_content(&depth1)?;
    let tc = now_ms()?.max(depth1.d.ts);
    let depth2 = wrap_commit(depth1.clone(), room, tc)?;
    validate_event_content(&depth2)?;
    Ok((depth1, depth2))
}

/// Pass `nonce` when the room requires Proof-of-Work for joining (spec §2.3.3, §3.6).
/// The nonce is a `d`-level field, not a content field.
pub fn make_room_join(node: &LocalNode, room_pub: &str, nonce: Option<u64>) -> Result<Envelope> {
    let extra = DatumBodyExtra {
        r: Some(room_pub.to_owned()),
        nonce,
        ..Default::default()
    };
    let env = make_envelope("room.join", Some(json!({})), node, Some(extra))?;
    validate_event_content(&env)?;
    Ok(env)
}

pub fn make_room_leave(node: &LocalNode, room_pub: &str) -> Result<Envelope> {
    make_room_scoped("room.leave", node, room_pub, Some(json!({})))
}

pub fn make_room_invite(node: &LocalNode, room_pub: &str, invitee: &str) -> Result<Envelope> {
    make_room_scoped("room.invite", node, room_pub, Some(json!({ "invitee": invitee })))
}

/// Pass `reason` for an optional human-readable ban reason (spec §A.6.6, max 250 chars).
pub fn make_room_ban(
    node: &LocalNode,
    room_pub: &str,
    target: &str,
    reason: Option<&str>,
) -> Result<Envelope> {
    let mut content = Map::new();
    content.insert("banned".to_owned(), json!(target));
    if let Some(r) = reason {
        content.insert("reason".to_owned(), json!(r));
    }
    make_room_scoped("room.ban", node, room_pub, Some(Value::Object(content)))
}

pub fn make_room_unban(node: &LocalNode, room_pub: &str, target: &str) -> Result<Envelope> {
    make_room_scoped(
        "room.unban",
        node,
        room_pub,
        Some(json!({ "unbanned": target })),
    )
}

pub fn make_room_update(
    node: &LocalNode,
    room: &LocalRoom,
    name: Option<&str>,
    rules: Option<Value>,
) -> Result<Envelope> {
    let mut content = Map::new();
    if let Some(name) = name {
        content.insert("name".to_owned(), Value::String(name.to_owned()));
    }
    if let Some(rules) = rules {
        content.insert("rules".to_owned(), rules);
    }
    if content.is_empty() {
        bail!("room.update requires at least one content field");
    }
    make_room_scoped(
        "room.update",
        node,
        &room.sig.pub_key,
        Some(Value::Object(content)),
    )
}

pub fn make_room_message(
    node: &LocalNode,
    room_pub: &str,
    channel: i32,
    body: &str,
    blobs: Vec<String>,
) -> Result<Envelope> {
    if channel < 0 {
        bail!("room.message channel must be >= 0");
    }
    let mut content = Map::new();
    content.insert("ch".to_owned(), json!(channel));
    content.insert("body".to_owned(), Value::String(body.to_owned()));
    if !blobs.is_empty() {
        content.insert("blobs".to_owned(), json!(blobs));
    }
    make_room_scoped(
        "room.message",
        node,
        room_pub,
        Some(Value::Object(content)),
    )
}

pub fn make_room_react(
    node: &LocalNode,
    room_pub: &str,
    channel: i32,
    target_eid: &str,
    emoji: &str,
) -> Result<Envelope> {
    if channel < 0 {
        bail!("room.react channel must be >= 0");
    }
    make_room_scoped(
        "room.react",
        node,
        room_pub,
        Some(json!({
            "ch": channel,
            "target": target_eid,
            "emoji": emoji
        })),
    )
}

pub fn make_room_edit(
    node: &LocalNode,
    room_pub: &str,
    channel: i32,
    target_eid: &str,
    body: &str,
) -> Result<Envelope> {
    if channel < 0 {
        bail!("room.edit channel must be >= 0");
    }
    make_room_scoped(
        "room.edit",
        node,
        room_pub,
        Some(json!({
            "ch": channel,
            "target": target_eid,
            "body": body
        })),
    )
}

pub fn make_room_delete(
    node: &LocalNode,
    room_pub: &str,
    channel: i32,
    target_eid: &str,
) -> Result<Envelope> {
    if channel < 0 {
        bail!("room.delete channel must be >= 0");
    }
    make_room_scoped(
        "room.delete",
        node,
        room_pub,
        Some(json!({
            "ch": channel,
            "target": target_eid
        })),
    )
}

pub fn make_room_blob(
    node: &LocalNode,
    room_pub: &str,
    channel: i32,
    manifest: &BlobManifest,
    mime: Option<&str>,
    name: Option<&str>,
) -> Result<Envelope> {
    if channel < 0 {
        bail!("room.blob channel must be >= 0");
    }
    let mut content = Map::new();
    content.insert("ch".to_owned(), json!(channel));
    content.insert("hash".to_owned(), Value::String(manifest.hash.clone()));
    content.insert("size".to_owned(), json!(manifest.size));
    content.insert("piece_size".to_owned(), json!(manifest.piece_size));
    content.insert("pieces".to_owned(), json!(manifest.pieces.clone()));
    if let Some(mime) = mime {
        content.insert("mime".to_owned(), Value::String(mime.to_owned()));
    }
    if let Some(name) = name {
        content.insert("name".to_owned(), Value::String(name.to_owned()));
    }
    make_room_scoped("room.blob", node, room_pub, Some(Value::Object(content)))
}

pub fn make_private_message(
    sender: &LocalNode,
    to: &str,
    to_enc_pub: &str,
    body: &str,
    blobs: Vec<String>,
) -> Result<Envelope> {
    // Decode recipient's long-lived encryption public key.
    let rec_enc_bytes =
        base64url::decode(to_enc_pub).context("invalid recipient enc pub base64url")?;

    // Step 1: fresh ephemeral X25519 keypair (§3.5.3).
    let (eph_pub_bytes, eph_priv_bytes) = x25519_generate();

    // Step 2: X25519 shared secret.
    let shared = x25519_shared_secret(&eph_priv_bytes, &rec_enc_bytes)?;

    // Step 3: salt = SHA-256(eph_pub || recipient_enc_pub).
    let mut salt_input = Vec::with_capacity(64);
    salt_input.extend_from_slice(&eph_pub_bytes);
    salt_input.extend_from_slice(&rec_enc_bytes);
    let salt = sha256(&salt_input);

    // Step 4: derive key + nonce via HKDF-SHA256.
    let (key, nonce) = derive_private_message_key(&shared, &salt);

    // Steps 5–6: encrypt canonical(content_json) with ChaCha20-Poly1305.
    let plaintext_obj = json!({ "body": body, "blobs": blobs });
    let plaintext_bytes = canonical(&plaintext_obj)?.into_bytes();
    let ciphertext = chacha20_encrypt(&key, &nonce, &plaintext_bytes);

    let content = json!({
        "eph": base64url::encode(&eph_pub_bytes),
        "encrypted": base64url::encode(&ciphertext)
    });

    let extra = DatumBodyExtra {
        to: Some(to.to_owned()),
        ..Default::default()
    };
    let env = make_envelope("private.message", Some(content), sender, Some(extra))?;
    validate_event_content(&env)?;
    Ok(env)
}

pub fn make_private_read(sender: &LocalNode, to: &str, ids: Vec<String>) -> Result<Envelope> {
    let extra = DatumBodyExtra {
        to: Some(to.to_owned()),
        ..Default::default()
    };
    let env = make_envelope(
        "private.read",
        Some(json!({
            "ids": ids
        })),
        sender,
        Some(extra),
    )?;
    validate_event_content(&env)?;
    Ok(env)
}

pub fn make_side_fork(
    node: &LocalNode,
    room_pub: &str,
    forked_from: &str,
    reason: Option<&str>,
) -> Result<Envelope> {
    let mut content = Map::new();
    content.insert("forked_from".to_owned(), Value::String(forked_from.to_owned()));
    if let Some(r) = reason {
        if r.len() > MAX_REASON {
            bail!("side.fork reason exceeds {} chars", MAX_REASON);
        }
        content.insert("reason".to_owned(), Value::String(r.to_owned()));
    }
    make_room_scoped("side.fork", node, room_pub, Some(Value::Object(content)))
}

pub fn make_side_attestation(
    node: &LocalNode,
    target_node: &str,
    level: &str,
    reason: Option<&str>,
) -> Result<Envelope> {
    match level {
        "positive" | "negative" | "neutral" => {}
        _ => bail!("side.attestation level must be positive, negative, or neutral"),
    }
    let mut content = Map::new();
    content.insert("target".to_owned(), Value::String(target_node.to_owned()));
    content.insert("level".to_owned(), Value::String(level.to_owned()));
    if let Some(r) = reason {
        if r.len() > MAX_REASON {
            bail!("side.attestation reason exceeds {} chars", MAX_REASON);
        }
        content.insert("reason".to_owned(), Value::String(r.to_owned()));
    }
    let env = make_envelope("side.attestation", Some(Value::Object(content)), node, None)?;
    validate_event_content(&env)?;
    Ok(env)
}

pub fn make_room_flag(
    node: &LocalNode,
    room_pub: &str,
    target_eid: &str,
    category: &str,
    reason: Option<&str>,
) -> Result<Envelope> {
    let mut content = Map::new();
    content.insert("target".to_owned(), Value::String(target_eid.to_owned()));
    content.insert("category".to_owned(), Value::String(category.to_owned()));
    if let Some(r) = reason {
        if r.len() > MAX_REASON {
            bail!("room.flag reason exceeds {} chars", MAX_REASON);
        }
        content.insert("reason".to_owned(), Value::String(r.to_owned()));
    }
    make_room_scoped("room.flag", node, room_pub, Some(Value::Object(content)))
}

pub fn make_room_migrate(
    node: &LocalNode,
    room: &LocalRoom,
    new_room_pub: &str,
    reason: Option<&str>,
) -> Result<Envelope> {
    let mut content = Map::new();
    content.insert("new_room".to_owned(), Value::String(new_room_pub.to_owned()));
    if let Some(r) = reason {
        if r.len() > MAX_REASON {
            bail!("room.migrate reason exceeds {} chars", MAX_REASON);
        }
        content.insert("reason".to_owned(), Value::String(r.to_owned()));
    }
    make_room_scoped("room.migrate", node, &room.sig.pub_key, Some(Value::Object(content)))
}

pub fn validate_event_content(env: &Envelope) -> Result<()> {
    if env.d.t == "commit" {
        let tc = env
            .d
            .tc
            .ok_or_else(|| anyhow!("commit envelope must include d.tc"))?;
        let inner = env
            .d
            .env
            .as_deref()
            .ok_or_else(|| anyhow!("commit envelope must include d.env"))?;
        if tc < inner.d.ts {
            bail!("commit timestamp must be >= inner timestamp");
        }
    }

    let d = &innermost(env).d;
    match d.t.as_str() {
        "node.meta" => validate_node_meta(d),
        "room.create" => validate_room_create(d),
        "room.update" => validate_room_update(d),
        "room.message" => validate_room_message(d),
        "room.join" | "room.leave" => validate_object_or_empty(d),
        "room.invite" => validate_required_string_field(d, "invitee"),
        "room.ban" => validate_room_ban(d),
        "room.unban" => validate_required_string_field(d, "unbanned"),
        "room.react" => validate_room_react(d),
        "room.edit" => validate_room_edit(d),
        "room.delete" => validate_required_string_field(d, "target"),
        "room.blob" => validate_room_blob(d),
        "private.message" | "private.blob" => validate_private_payload(d),
        "private.read" => validate_private_read(d),
        "side.fork" => validate_required_string_field(d, "forked_from"),
        "side.attestation" => {
            validate_required_string_field(d, "target")?;
            validate_required_string_field(d, "level")
        }
        "room.flag" => {
            validate_required_string_field(d, "target")?;
            validate_required_string_field(d, "category")
        }
        "room.migrate" => validate_required_string_field(d, "new_room"),
        _ => Ok(()),
    }
}

fn make_room_scoped(
    t: &str,
    node: &LocalNode,
    room_pub: &str,
    content: Option<Value>,
) -> Result<Envelope> {
    let extra = DatumBodyExtra {
        r: Some(room_pub.to_owned()),
        ..Default::default()
    };
    let env = make_envelope(t, content, node, Some(extra))?;
    validate_event_content(&env)?;
    Ok(env)
}

fn validate_node_meta(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    let enc = c
        .get("enc")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("node.meta requires c.enc"))?;
    ensure_base64url_key(enc, "node.meta c.enc")
}

fn validate_room_create(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    let name = c
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.create requires c.name"))?;
    if name.is_empty() || name.chars().count() > MAX_ROOM_NAME {
        bail!("room.create name must be 1..={MAX_ROOM_NAME} chars");
    }
    if let Some(description) = c.get("description").and_then(Value::as_str) {
        if description.chars().count() > MAX_ROOM_DESCRIPTION {
            bail!("room.create description too long");
        }
    }
    if let Some(rules) = c.get("rules") {
        if !rules.is_array() {
            bail!("room.create rules must be an array");
        }
    }
    Ok(())
}

fn validate_room_update(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    if c.is_empty() {
        bail!("room.update requires at least one field");
    }
    if let Some(name) = c.get("name").and_then(Value::as_str) {
        if name.is_empty() || name.chars().count() > MAX_ROOM_NAME {
            bail!("room.update name must be 1..={MAX_ROOM_NAME} chars");
        }
    }
    if let Some(description) = c.get("description").and_then(Value::as_str) {
        if description.chars().count() > MAX_ROOM_DESCRIPTION {
            bail!("room.update description too long");
        }
    }
    if let Some(rules) = c.get("rules") {
        if !rules.is_array() {
            bail!("room.update rules must be an array");
        }
    }
    Ok(())
}

fn validate_room_message(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    let body = c
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.message requires c.body"))?;
    if body.chars().count() > MAX_MESSAGE_BODY {
        bail!("room.message body too long");
    }
    validate_channel_non_negative(c, "room.message")?;
    if let Some(blobs) = c.get("blobs") {
        let arr = blobs
            .as_array()
            .ok_or_else(|| anyhow!("room.message blobs must be an array"))?;
        if arr.len() > 10 {
            bail!("room.message blobs supports up to 10 entries");
        }
        for item in arr {
            if item.as_str().is_none() {
                bail!("room.message blobs entries must be strings");
            }
        }
    }
    Ok(())
}

fn validate_room_ban(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    let banned = c
        .get("banned")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.ban requires c.banned"))?;
    if banned.is_empty() {
        bail!("room.ban c.banned must be non-empty");
    }
    if let Some(reason) = c.get("reason").and_then(Value::as_str) {
        if reason.chars().count() > MAX_REASON {
            bail!("room.ban reason exceeds {MAX_REASON} characters");
        }
    }
    Ok(())
}

fn validate_room_react(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    validate_channel_non_negative(c, "room.react")?;
    let target = c
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.react requires c.target"))?;
    if target.is_empty() {
        bail!("room.react target must be non-empty");
    }
    let emoji = c
        .get("emoji")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.react requires c.emoji"))?;
    if emoji.is_empty() || emoji.chars().count() > MAX_EMOJI {
        bail!("room.react emoji must be 1..={MAX_EMOJI} chars");
    }
    Ok(())
}

fn validate_room_edit(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    validate_channel_non_negative(c, "room.edit")?;
    let target = c
        .get("target")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.edit requires c.target"))?;
    if target.is_empty() {
        bail!("room.edit target must be non-empty");
    }
    let body = c
        .get("body")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.edit requires c.body"))?;
    if body.chars().count() > MAX_MESSAGE_BODY {
        bail!("room.edit body too long");
    }
    Ok(())
}

fn validate_room_blob(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    validate_channel_non_negative(c, "room.blob")?;

    let hash = c
        .get("hash")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("room.blob requires c.hash"))?;
    ensure_hex64(hash, "room.blob hash")?;

    let size = c
        .get("size")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("room.blob requires c.size"))?;
    if size == 0 {
        bail!("room.blob size must be > 0");
    }

    let piece_size = c
        .get("piece_size")
        .and_then(Value::as_u64)
        .ok_or_else(|| anyhow!("room.blob requires c.piece_size"))?;
    if piece_size == 0 {
        bail!("room.blob piece_size must be > 0");
    }

    let pieces = c
        .get("pieces")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("room.blob requires c.pieces array"))?;
    if pieces.is_empty() {
        bail!("room.blob pieces must be non-empty");
    }
    for piece in pieces {
        let piece_hash = piece
            .as_str()
            .ok_or_else(|| anyhow!("room.blob pieces entries must be strings"))?;
        ensure_hex64(piece_hash, "room.blob piece hash")?;
    }
    let expected_pieces = size.div_ceil(piece_size);
    if pieces.len() as u64 != expected_pieces {
        bail!("room.blob pieces count must equal ceil(size/piece_size) = {expected_pieces}");
    }
    Ok(())
}

fn validate_private_payload(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    let eph = c
        .get("eph")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("private payload requires c.eph"))?;
    ensure_base64url_key(eph, "private payload eph")?;

    let encrypted = c
        .get("encrypted")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("private payload requires c.encrypted"))?;
    base64url::decode(encrypted).map_err(|_| anyhow!("private payload encrypted must be base64url"))?;
    Ok(())
}

fn validate_private_read(d: &DatumBody) -> Result<()> {
    let c = content_object(d)?;
    let ids = c
        .get("ids")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("private.read requires c.ids array"))?;
    for id in ids {
        let id = id
            .as_str()
            .ok_or_else(|| anyhow!("private.read ids must be strings"))?;
        if id.is_empty() {
            bail!("private.read ids entries must be non-empty");
        }
    }
    Ok(())
}

fn validate_required_string_field(d: &DatumBody, field: &str) -> Result<()> {
    let c = content_object(d)?;
    let value = c
        .get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("{} requires c.{field}", d.t))?;
    if value.is_empty() {
        bail!("{} c.{field} must be non-empty", d.t);
    }
    Ok(())
}


fn validate_object_or_empty(d: &DatumBody) -> Result<()> {
    if let Some(c) = d.c.as_ref() {
        if !c.is_object() {
            bail!("{} content must be an object", d.t);
        }
    }
    Ok(())
}

fn validate_channel_non_negative(c: &Map<String, Value>, event: &str) -> Result<()> {
    if let Some(ch) = c.get("ch").and_then(Value::as_i64) {
        if ch < 0 {
            bail!("{event} c.ch must be >= 0");
        }
    }
    Ok(())
}

fn content_object(d: &DatumBody) -> Result<&Map<String, Value>> {
    d.c.as_ref()
        .ok_or_else(|| anyhow!("{} requires content object", d.t))?
        .as_object()
        .ok_or_else(|| anyhow!("{} content must be an object", d.t))
}

fn ensure_hex64(v: &str, label: &str) -> Result<()> {
    if v.len() != 64 || !v.chars().all(|c| c.is_ascii_hexdigit()) {
        bail!("{label} must be 64 hex chars");
    }
    Ok(())
}

fn ensure_base64url_key(v: &str, label: &str) -> Result<()> {
    if v.len() != 43 {
        bail!("{label} must be 43-char base64url");
    }
    let decoded = base64url::decode(v).map_err(|_| anyhow!("{label} must be valid base64url"))?;
    if decoded.len() != 32 {
        bail!("{label} must decode to 32 bytes");
    }
    Ok(())
}

fn now_ms() -> Result<u64> {
    let dur = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| anyhow!("system clock is before Unix epoch"))?;
    Ok(dur.as_millis() as u64)
}

#[cfg(test)]
mod tests {
    use super::{
        make_node_meta, make_private_message, make_room_blob, make_room_create, make_room_message,
        validate_event_content, BlobManifest,
    };
    use crate::base64url;
    use crate::crypto::{ed25519_generate, x25519_generate};
    use crate::envelope::sign_envelope;
    use crate::types::{DatumBody, Keypair, LocalNode, LocalRoom};
    use serde_json::json;
    use std::collections::HashMap;

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

    fn mk_room() -> LocalRoom {
        let (room_pub, room_seed) = ed25519_generate();
        LocalRoom {
            sig: Keypair {
                pub_key: base64url::encode(&room_pub),
                priv_key: base64url::encode(&room_seed),
            },
        }
    }

    #[test]
    fn make_node_meta_puts_enc_in_content() {
        let node = mk_node();
        let env = make_node_meta(&node, vec![]).expect("node.meta builder should work");
        assert_eq!(env.d.t, "node.meta");
        let c = env.d.c.as_ref().unwrap();
        assert_eq!(c.get("enc").and_then(|v| v.as_str()), Some(node.enc.pub_key.as_str()));
        validate_event_content(&env).expect("node.meta should validate");
    }

    #[test]
    fn make_room_create_returns_depth1_and_depth2_commit() {
        let node = mk_node();
        let room = mk_room();
        let (depth1, depth2) =
            make_room_create(&node, &room, Some("my room"), Some(json!([]))).expect("room.create");

        assert_eq!(depth1.d.t, "room.create");
        assert!(depth1.d.env.is_none());
        assert_eq!(depth2.d.t, "commit");
        assert!(depth2.d.env.is_some());
        validate_event_content(&depth1).expect("depth1 valid");
        validate_event_content(&depth2).expect("depth2 valid");
    }

    #[test]
    fn room_message_validation_rejects_long_body() {
        let node = mk_node();
        let room = mk_room();
        let too_long = "x".repeat(4097);
        assert!(make_room_message(&node, &room.sig.pub_key, 0, &too_long, vec![]).is_err());
    }

    fn valid_hex64() -> String {
        "a".repeat(64)
    }

    #[test]
    fn room_blob_validation_rejects_invalid_hash() {
        let node = mk_node();
        let room = mk_room();
        let manifest = BlobManifest {
            hash: "not_hex".to_owned(),
            size: 1,
            piece_size: 1,
            pieces: vec![valid_hex64()],
        };
        assert!(make_room_blob(&node, &room.sig.pub_key, 0, &manifest, None, None).is_err());
    }

    #[test]
    fn room_blob_validation_rejects_wrong_piece_count() {
        let node = mk_node();
        let room = mk_room();
        // size=200, piece_size=100 → expect 2 pieces, but only 1 supplied.
        let manifest = BlobManifest {
            hash: valid_hex64(),
            size: 200,
            piece_size: 100,
            pieces: vec![valid_hex64()],
        };
        assert!(make_room_blob(&node, &room.sig.pub_key, 0, &manifest, None, None).is_err());
    }

    #[test]
    fn room_blob_validation_accepts_correct_piece_count() {
        let node = mk_node();
        let room = mk_room();
        // size=150, piece_size=100 → ceil(150/100) = 2 pieces.
        let manifest = BlobManifest {
            hash: valid_hex64(),
            size: 150,
            piece_size: 100,
            pieces: vec![valid_hex64(), valid_hex64()],
        };
        assert!(make_room_blob(&node, &room.sig.pub_key, 0, &manifest, None, None).is_ok());
    }

    #[test]
    fn private_message_builder_emits_valid_shape() {
        let sender = mk_node();
        let recipient = mk_node();
        let env = make_private_message(
            &sender,
            &recipient.sig.pub_key,
            &recipient.enc.pub_key,
            "hello",
            vec![],
        )
        .expect("private.message builder should work");

        assert_eq!(env.d.t, "private.message");
        assert_eq!(env.d.to.as_deref(), Some(recipient.sig.pub_key.as_str()));
        validate_event_content(&env).expect("private.message should validate");

        // c.eph must be a fresh ephemeral key — not the recipient's permanent enc pub.
        let c = env.d.c.as_ref().unwrap();
        let eph = c.get("eph").and_then(|v| v.as_str()).unwrap();
        assert_ne!(eph, recipient.enc.pub_key, "c.eph must be ephemeral, not recipient's permanent enc pub");
        // c.encrypted must be non-empty base64url (real ciphertext, not plaintext).
        let encrypted = c.get("encrypted").and_then(|v| v.as_str()).unwrap();
        let decoded = crate::base64url::decode(encrypted).expect("must be valid base64url");
        assert!(decoded.len() > 16, "ciphertext must be longer than AEAD tag alone");
    }

    #[test]
    fn commit_validation_rejects_bad_tc() {
        let node = mk_node();
        let room = mk_room();
        let inner = make_room_message(&node, &room.sig.pub_key, 0, "ok", vec![])
            .expect("builder should work");

        let bad_commit_d = DatumBody {
            n: room.sig.pub_key.clone(),
            v: "0.2".to_owned(),
            t: "commit".to_owned(),
            ts: inner.d.ts.saturating_sub(1),
            r: None,
            to: None,
            c: None,
            env: Some(Box::new(inner)),
            tc: Some(1),
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        let bad_commit = sign_envelope(bad_commit_d, &room.sig.priv_key).expect("sign commit");
        assert!(validate_event_content(&bad_commit).is_err());
    }

    #[test]
    fn side_fork_builder_emits_valid_shape() {
        let node = mk_node();
        let room = mk_room();
        let env = super::make_side_fork(&node, &room.sig.pub_key, "some_eid", Some("test fork"))
            .expect("side.fork builder should work");
        assert_eq!(env.d.t, "side.fork");
        let c = env.d.c.as_ref().unwrap();
        assert_eq!(c.get("forked_from").and_then(|v| v.as_str()), Some("some_eid"));
        validate_event_content(&env).expect("side.fork should validate");
    }

    #[test]
    fn side_attestation_builder_emits_valid_shape() {
        let node = mk_node();
        let target = mk_node();
        let env = super::make_side_attestation(&node, &target.sig.pub_key, "positive", Some("trusted"))
            .expect("side.attestation builder should work");
        assert_eq!(env.d.t, "side.attestation");
        let c = env.d.c.as_ref().unwrap();
        assert_eq!(c.get("level").and_then(|v| v.as_str()), Some("positive"));
        validate_event_content(&env).expect("side.attestation should validate");
    }

    #[test]
    fn side_attestation_rejects_invalid_level() {
        let node = mk_node();
        let target = mk_node();
        assert!(super::make_side_attestation(&node, &target.sig.pub_key, "invalid", None).is_err());
    }

    #[test]
    fn room_flag_builder_emits_valid_shape() {
        let node = mk_node();
        let room = mk_room();
        let env = super::make_room_flag(&node, &room.sig.pub_key, "eid123", "spam", Some("reason"))
            .expect("room.flag builder should work");
        assert_eq!(env.d.t, "room.flag");
        let c = env.d.c.as_ref().unwrap();
        assert_eq!(c.get("category").and_then(|v| v.as_str()), Some("spam"));
        validate_event_content(&env).expect("room.flag should validate");
    }

    #[test]
    fn room_migrate_builder_emits_valid_shape() {
        let node = mk_node();
        let room = mk_room();
        let new_room = mk_room();
        let env = super::make_room_migrate(&node, &room, &new_room.sig.pub_key, Some("upgrading"))
            .expect("room.migrate builder should work");
        assert_eq!(env.d.t, "room.migrate");
        let c = env.d.c.as_ref().unwrap();
        assert_eq!(c.get("new_room").and_then(|v| v.as_str()), Some(new_room.sig.pub_key.as_str()));
        validate_event_content(&env).expect("room.migrate should validate");
    }
}
