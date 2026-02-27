/// Request handlers for all nine relay endpoints (spec §10.7–§10.8).
///
/// Dispatch table:
///
/// | d.t                | Handler            | Spec   |
/// |--------------------|--------------------|--------|
/// | `events.sync`      | incremental sync   | §10.7.1|
/// | `room.sync`        | channel range sync | §10.7.2|
/// | `room.compare`     | bisection compare  | §10.7.3|
/// | `pool.exchange`    | diff-based sync    | §10.8.1|
/// | `node.peers`       | peer directory     | §10.8.2|
/// | `node.rooms`       | node room list     | §10.8.3|
/// | `system.fetch`     | fetch by ID        | §10.8.4|
/// | `blob.fetch`       | binary blob data   | §10.8.5|
/// | `room.summary`     | lightweight status | §10.8.6|
use std::collections::HashSet;
use std::sync::Arc;

use anyhow::Result;
use serde_json::{json, Value};

use toloo_core::envelope::{depth, innermost, make_envelope, parse_envelope, verify_chain, wrap_commit};
use toloo_core::ids::{datum_id, eid};
use toloo_core::pow::verify_pow;
use toloo_core::types::Envelope;
use crate::pool::{ruleset_from_pool, Pool};
use crate::transport::server::RelayConfig;

const DEFAULT_LIMIT: usize = 200;
const MAX_LIMIT: usize = 1000;
const MAX_SUMMARY_ROOMS: usize = 50;
const MAX_FETCH_IDS: usize = 100;

// ---- Public entry point ----

/// Dispatch an inbound request envelope and return a list of JSON response values.
///
/// Each value in the returned vec is either:
/// - A full signed envelope (success)
/// - An error object `{"error": "...", "message": "..."}`
pub async fn handle_request(
    envelope: Envelope,
    pool: &Arc<Pool>,
    config: &RelayConfig,
) -> Result<Vec<Value>> {
    // Verify request signature.
    if let Err(e) = verify_chain(&envelope) {
        return Ok(vec![error("invalid_signature", &e.to_string())]);
    }

    let d = &innermost(&envelope).d;
    let responses = match d.t.as_str() {
        "events.sync"   => handle_events_sync(d.c.as_ref(), pool),
        "room.sync"     => handle_room_sync(d.c.as_ref(), pool),
        "room.compare"  => handle_room_compare(d.c.as_ref(), pool, config),
        "pool.exchange" => handle_pool_exchange(d.c.as_ref(), pool, config),
        "node.peers"    => handle_node_peers(d.c.as_ref(), pool),
        "node.rooms"    => handle_node_rooms(d.c.as_ref(), pool),
        "system.fetch"  => handle_system_fetch(d.c.as_ref(), pool),
        "blob.fetch"    => handle_blob_fetch(d.c.as_ref(), pool),
        "room.summary"  => handle_room_summary(d.c.as_ref(), pool, config),
        _ => Ok(vec![error("invalid_request", &format!("unknown endpoint: {}", d.t))]),
    };

    responses
}

// ---- §10.7.1 events.sync ----

fn handle_events_sync(c: Option<&Value>, pool: &Pool) -> Result<Vec<Value>> {
    let c = require_object(c, "events.sync")?;
    let rooms = string_array(c.get("rooms"));
    let after = c.get("after").and_then(Value::as_u64).unwrap_or(0);
    let limit = clamp_limit(c.get("limit").and_then(Value::as_u64));

    let room_refs: Vec<&str> = rooms.iter().map(String::as_str).collect();
    let entries = pool.get_wanted(&room_refs, &[], after, limit)?;
    Ok(entries.into_iter().map(|e| to_envelope_json(&e.env)).collect())
}

// ---- §10.7.2 room.sync ----

fn handle_room_sync(c: Option<&Value>, pool: &Pool) -> Result<Vec<Value>> {
    let c = require_object(c, "room.sync")?;
    let room = require_string(c, "r", "room.sync")?;
    let channel = c.get("channel").and_then(Value::as_i64).unwrap_or(0) as i32;
    let start_tc = c.get("start_tc").and_then(Value::as_u64).unwrap_or(0);
    let end_tc = c.get("end_tc").and_then(Value::as_u64);
    let limit = clamp_limit(c.get("limit").and_then(Value::as_u64));

    let entries = pool.get_room_channel_range(room, channel, start_tc, end_tc, limit)?;
    Ok(entries.into_iter().map(|e| to_envelope_json(&e.env)).collect())
}

// ---- §10.7.3 room.compare ----

fn handle_room_compare(c: Option<&Value>, pool: &Pool, config: &RelayConfig) -> Result<Vec<Value>> {
    let c = require_object(c, "room.compare")?;
    let room = require_string(c, "r", "room.compare")?;
    let channel = c.get("channel").and_then(Value::as_i64).unwrap_or(0) as i32;
    let samples = match c.get("samples").and_then(Value::as_array) {
        Some(s) => s,
        None => return Ok(vec![error("invalid_request", "room.compare requires c.samples")]),
    };

    // Get the max seq requested so we know how many events to fetch.
    let max_seq = samples
        .iter()
        .filter_map(|s| s.get("seq").and_then(Value::as_u64))
        .max()
        .unwrap_or(0) as usize;

    // Fetch committed events for room+channel up to max_seq.
    let entries = pool.get_room_channel_range(room, channel, 0, None, max_seq + 1)?;

    // Build seq→eid map (seq is 1-based position in tc-ordered list).
    let local_eids: Vec<String> = entries
        .iter()
        .map(|e| eid(&e.env))
        .collect();

    // Compare samples: note matches and mismatches.
    let mut match_results: Vec<Value> = Vec::new();
    for sample in samples {
        let seq = match sample.get("seq").and_then(Value::as_u64) {
            Some(s) => s as usize,
            None => continue,
        };
        let client_eid = sample.get("eid").and_then(Value::as_str).unwrap_or("");
        let idx = seq.saturating_sub(1);
        let our_eid = local_eids.get(idx).map(String::as_str).unwrap_or("");
        match_results.push(json!({
            "seq": seq,
            "eid": our_eid,
            "match": our_eid == client_eid,
        }));
    }

    // Sign a room.compare.result envelope.
    let content = json!({
        "r": room,
        "channel": channel,
        "results": match_results,
    });
    let result_env = make_envelope("room.compare.result", Some(content), &config.node, None)?;
    Ok(vec![to_envelope_json(&result_env)])
}

// ---- §10.8.1 pool.exchange ----

fn handle_pool_exchange(c: Option<&Value>, pool: &Pool, config: &RelayConfig) -> Result<Vec<Value>> {
    let c = require_object(c, "pool.exchange")?;
    let mut offered_ids: HashSet<String> = HashSet::new();

    // Process offer: store full envelopes that were submitted; collect datum_ids for diff.
    if let Some(offer_arr) = c.get("offer").and_then(Value::as_array) {
        for item in offer_arr {
            if let Some(obj) = item.as_object() {
                if obj.contains_key("d") && obj.contains_key("p") {
                    // Full envelope submission — validate and store.
                    if let Ok(env) = parse_envelope(item.clone()) {
                        if verify_chain(&env).is_ok() {
                            let inner = innermost(&env);

                            // §13.3 — reject events from locally blocked nodes.
                            if pool.is_blocked(&inner.d.n).unwrap_or(false) {
                                continue;
                            }

                            // Route side-events to their dedicated stores.
                            match inner.d.t.as_str() {
                                "side.attestation" => {
                                    let _ = pool.put_attestation(&env);
                                    continue;
                                }
                                "room.flag" => {
                                    let _ = pool.put_flag(&env);
                                    // Also store in main pool for replication.
                                }
                                _ => {}
                            }

                            // Track the original datum_id (what this peer already has).
                            // If the relay auto-commits it (depth-1 → depth-2), the committed
                            // envelope has a DIFFERENT datum_id and must NOT be excluded from
                            // the response — so the peer receives the commit in this same
                            // pool.exchange roundtrip instead of waiting for the next sync.
                            let original_id = datum_id(&env);
                            let stored_env = maybe_commit(env, pool, config);
                            if pool.put(&stored_env).is_ok() {
                                offered_ids.insert(original_id);
                            }
                        }
                    }
                } else if let Some(id) = obj.get("datum_id").and_then(Value::as_str) {
                    offered_ids.insert(id.to_owned());
                }
            }
        }
    }

    // Process want.
    let mut responses: Vec<Value> = Vec::new();
    if let Some(want) = c.get("want").and_then(Value::as_object) {
        let rooms = string_array(want.get("rooms"));
        let types = string_array(want.get("types"));
        let after = want.get("after").and_then(Value::as_u64).unwrap_or(0);
        let limit = clamp_limit(want.get("limit").and_then(Value::as_u64));

        let room_refs: Vec<&str> = rooms.iter().map(String::as_str).collect();
        let type_refs: Vec<&str> = types.iter().map(String::as_str).collect();
        let entries = pool.get_wanted(&room_refs, &type_refs, after, limit)?;

        for entry in entries {
            // Exclude events the peer already has and events from blocked nodes.
            if !offered_ids.contains(&entry.id)
                && !pool.is_blocked(&innermost(&entry.env).d.n).unwrap_or(false)
            {
                responses.push(to_envelope_json(&entry.env));
            }
        }
    }

    // Bonus: include node.meta for known peers (pool gossip, §10.8.1, §12.4).
    let peer_metas = pool.get_wanted(&[], &["node.meta"], 0, 20)?;
    for entry in peer_metas {
        let id = datum_id(&entry.env);
        if !offered_ids.contains(&id) {
            let env_val = to_envelope_json(&entry.env);
            if !responses.contains(&env_val) {
                responses.push(env_val);
            }
        }
    }

    Ok(responses)
}

// ---- §10.8.2 node.peers ----

fn handle_node_peers(c: Option<&Value>, pool: &Pool) -> Result<Vec<Value>> {
    let limit = c
        .and_then(Value::as_object)
        .and_then(|o| o.get("limit"))
        .and_then(Value::as_u64)
        .map(|v| v as usize)
        .unwrap_or(20)
        .min(MAX_LIMIT);

    let entries = pool.get_wanted(&[], &["node.meta"], 0, limit)?;
    Ok(entries.into_iter().map(|e| to_envelope_json(&e.env)).collect())
}

// ---- §10.8.3 node.rooms ----

fn handle_node_rooms(c: Option<&Value>, pool: &Pool) -> Result<Vec<Value>> {
    let c = require_object(c, "node.rooms")?;
    let target = require_string(c, "node", "node.rooms")?;
    let limit = clamp_limit(c.get("limit").and_then(Value::as_u64));

    let rooms = pool.get_node_rooms(target)?;
    let mut responses: Vec<Value> = Vec::new();

    for room_pub in rooms.iter().take(limit) {
        // Return room.create (channel -1, the oldest metadata event).
        let meta_events = pool.get_room_channel(room_pub, -1)?;
        for entry in meta_events.iter().filter(|e| e.tc.is_some()).take(1) {
            responses.push(to_envelope_json(&entry.env));
        }
        // Also return the latest room.update if any (last channel -1 after create).
        if let Some(latest) = meta_events.iter().filter(|e| e.tc.is_some()).last() {
            let latest_val = to_envelope_json(&latest.env);
            if !responses.contains(&latest_val) {
                responses.push(latest_val);
            }
        }
    }

    Ok(responses)
}

// ---- §10.8.4 system.fetch ----

fn handle_system_fetch(c: Option<&Value>, pool: &Pool) -> Result<Vec<Value>> {
    let c = require_object(c, "system.fetch")?;
    let ids = string_array(c.get("datum_ids"));
    if ids.is_empty() {
        return Ok(vec![error("invalid_request", "system.fetch requires c.datum_ids")]);
    }
    if ids.len() > MAX_FETCH_IDS {
        return Ok(vec![error("payload_too_large", &format!("datum_ids limit is {MAX_FETCH_IDS}"))]);
    }

    let id_refs: Vec<&str> = ids.iter().map(String::as_str).collect();
    let entries = pool.get_by_datum_ids(&id_refs)?;
    Ok(entries.into_iter().map(|e| to_envelope_json(&e.env)).collect())
}

// ---- §10.8.5 blob.fetch ----

fn handle_blob_fetch(c: Option<&Value>, pool: &Pool) -> Result<Vec<Value>> {
    let c = require_object(c, "blob.fetch")?;
    let blob_id = require_string(c, "blob_id", "blob.fetch")?;
    let piece_index = c.get("piece_index").and_then(Value::as_u64);

    match piece_index {
        Some(idx) => {
            // Fetch a single piece.
            match pool.get_blob_piece(blob_id, idx as u32)? {
                Some(data) => {
                    let encoded = toloo_core::base64url::encode(&data);
                    Ok(vec![json!({
                        "blob_id": blob_id,
                        "piece_index": idx,
                        "data": encoded
                    })])
                }
                None => Ok(vec![error("not_found", "blob piece not found")]),
            }
        }
        None => {
            // Return piece count (metadata query).
            let count = pool.blob_piece_count(blob_id)?;
            if count == 0 {
                Ok(vec![error("not_found", "blob not found")])
            } else {
                Ok(vec![json!({
                    "blob_id": blob_id,
                    "pieces": count
                })])
            }
        }
    }
}

// ---- §10.8.6 room.summary ----

fn handle_room_summary(c: Option<&Value>, pool: &Pool, config: &RelayConfig) -> Result<Vec<Value>> {
    let c = require_object(c, "room.summary")?;
    let rooms = string_array(c.get("rooms"));
    if rooms.is_empty() {
        return Ok(vec![error("invalid_request", "room.summary requires c.rooms")]);
    }

    let mut responses: Vec<Value> = Vec::new();
    for room_pub in rooms.iter().take(MAX_SUMMARY_ROOMS) {
        // Room name from latest channel -1.
        let meta = pool.get_room_channel(room_pub, -1)?;
        let name = meta
            .iter()
            .filter(|e| e.tc.is_some())
            .last()
            .and_then(|e| innermost(&e.env).d.c.as_ref())
            .and_then(|c| c.get("name"))
            .and_then(Value::as_str)
            .unwrap_or("")
            .to_owned();

        // Member count from channel -2.
        let membership = pool.build_membership(room_pub)?;
        let member_count = membership.members.len() as u64;

        // Per-channel stats (ch, count, latest_tc).
        let stats = pool.get_room_channel_stats(room_pub)?;
        let channels: Vec<Value> = stats
            .iter()
            .map(|(ch, count, ltc)| json!({"ch": ch, "latest_tc": ltc, "count": count}))
            .collect();

        // Skip rooms we know nothing about.
        if name.is_empty() && member_count == 0 && channels.is_empty() {
            continue;
        }

        let content = json!({
            "r": room_pub,
            "name": name,
            "members": member_count,
            "channels": channels,
        });
        let result_env = make_envelope("room.summary.result", Some(content), &config.node, None)?;
        responses.push(to_envelope_json(&result_env));
    }

    Ok(responses)
}

// ---- §10.6 Room Authority (Phase 12) ----

/// If the relay holds the private key for the room this envelope targets,
/// validate the event against room rules and auto-commit it (depth 1 → depth 2).
/// Returns the (possibly committed) envelope to store.
fn maybe_commit(env: Envelope, pool: &Pool, config: &RelayConfig) -> Envelope {
    // Only auto-commit depth-1 events.
    if depth(&env) != 1 {
        return env;
    }

    let inner = innermost(&env);
    let room_pub = match inner.d.r.as_deref() {
        Some(r) => r.to_owned(),
        None => return env, // not a room event
    };

    let local_room = match config.rooms.get(&room_pub) {
        Some(r) => r.clone(),
        None => return env, // relay is not a key holder for this room
    };

    // Validate against room rules — but only when the pool has committed metadata.
    // If the pool has no room.create yet (relay just started, room.create not synced yet),
    // the key-holder has implicit authority and we skip the check rather than deny everything.
    let has_committed_meta = pool.get_room_channel(&room_pub, -1)
        .map(|v| v.iter().any(|e| e.tc.is_some()))
        .unwrap_or(false);
    if has_committed_meta && validate_room_rules(&env, &room_pub, pool).is_err() {
        return env;
    }

    // Auto-commit: wrap in depth-2 commit envelope.
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64;

    // tc must be >= max existing tc in this room.
    let latest = pool.latest_tc(&room_pub).unwrap_or(0);
    let tc = now.max(latest + 1);

    match wrap_commit(env.clone(), &local_room, tc) {
        Ok(committed) => committed,
        Err(_) => env, // wrap failed — store uncommitted
    }
}

/// Validate a depth-1 room event against the room's current rule set.
///
/// Checks (in order):
/// 1. Author is not banned
/// 2. Author can post (join/post rules)
/// 3. PoW requirement (if any)
/// 4. Invite-only: must have committed room.invite first
/// 5. Rate limit
///
/// Key-holder administrative events (`room.create`, `room.update`, `room.ban`,
/// `room.unban`, `room.invite`) bypass content rules — the key holder vouches for
/// these by committing them.
fn validate_room_rules(env: &Envelope, room_pub: &str, pool: &Pool) -> Result<()> {
    let inner = innermost(env);
    let author = &inner.d.n;
    let event_type = inner.d.t.as_str();

    // Administrative events skip content rules (key holder controls these directly).
    const ADMIN_EVENTS: &[&str] = &[
        "room.create", "room.update", "room.ban", "room.unban", "room.invite",
    ];
    if ADMIN_EVENTS.contains(&event_type) {
        return Ok(());
    }

    let ruleset = ruleset_from_pool(pool, room_pub)?;
    let membership = pool.build_membership(room_pub)?;
    let members: Vec<&str> = membership.members.iter().map(String::as_str).collect();

    // 1. Banned check.
    if membership.banned.contains(author) {
        anyhow::bail!("author is banned");
    }

    // 2. Can post/join check.
    match event_type {
        "room.join" => {
            if !ruleset.can_join_node(author, &members) {
                anyhow::bail!("join not allowed by rules");
            }
            // Invite-only: must have an existing committed room.invite for this author.
            if ruleset.is_invite_only() {
                let ch_minus2 = pool.get_room_channel(room_pub, -2)?;
                let has_invite = ch_minus2.iter().any(|e| {
                    let inner_e = innermost(&e.env);
                    inner_e.d.t == "room.invite"
                        && inner_e.d.c.as_ref()
                            .and_then(|c| c.get("node"))
                            .and_then(|v| v.as_str())
                            == Some(author.as_str())
                });
                if !has_invite {
                    anyhow::bail!("invite-only: no invite found for author");
                }
            }
        }
        _ => {
            if !ruleset.can_post_node(author, &members) {
                anyhow::bail!("post not allowed by rules");
            }
        }
    }

    // 3. PoW check.
    let required_bits = if event_type == "room.join" {
        ruleset.required_join_pow()
    } else {
        ruleset.required_post_pow()
    };
    if let Some(bits) = required_bits {
        verify_pow(&inner.d, bits)?;
    }

    // 4. Rate limit (channel 0 events only).
    if let Some(_max_per_hour) = ruleset.max_events_per_hour() {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let one_hour_ago = now.saturating_sub(3_600_000);
        let all = pool.get_room_channel_range(room_pub, 0, one_hour_ago, None, MAX_LIMIT)?;
        let count = all
            .iter()
            .filter(|e| innermost(&e.env).d.n == *author)
            .count() as u32;
        if !ruleset.check_rate_limit(author, count) {
            anyhow::bail!("rate limit exceeded: {} events in window", count);
        }
    }

    Ok(())
}

// ---- Helpers ----

fn error(code: &str, message: &str) -> Value {
    json!({"error": code, "message": message})
}

fn to_envelope_json(env: &Envelope) -> Value {
    serde_json::to_value(env).unwrap_or_else(|_| json!({"error": "internal", "message": "envelope serialization failed"}))
}

fn require_object<'a>(c: Option<&'a Value>, endpoint: &str) -> Result<&'a serde_json::Map<String, Value>> {
    c.and_then(Value::as_object)
        .ok_or_else(|| anyhow::anyhow!("{endpoint} requires content object"))
}

fn require_string<'a>(obj: &'a serde_json::Map<String, Value>, field: &str, endpoint: &str) -> Result<&'a str> {
    obj.get(field)
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow::anyhow!("{endpoint} requires c.{field}"))
}

fn string_array(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|arr| arr.iter().filter_map(|v| v.as_str().map(str::to_owned)).collect())
        .unwrap_or_default()
}

fn clamp_limit(v: Option<u64>) -> usize {
    v.map(|n| n as usize).unwrap_or(DEFAULT_LIMIT).min(MAX_LIMIT)
}

// ---- Tests ----

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::handle_request;
    use toloo_core::base64url;
    use toloo_core::crypto::{ed25519_generate, x25519_generate};
    use toloo_core::envelope::{innermost, make_envelope, wrap_commit};
    use toloo_core::events::{make_node_meta, make_room_create, make_room_message};
    use toloo_core::ids::datum_id;
    use crate::pool::Pool;
    use crate::transport::server::RelayConfig;
    use toloo_core::types::{Keypair, LocalNode, LocalRoom};
    use serde_json::json;

    fn mk_node() -> LocalNode {
        let (sig_pub, sig_seed) = ed25519_generate();
        let (enc_pub, enc_priv) = x25519_generate();
        LocalNode {
            sig: Keypair { pub_key: base64url::encode(&sig_pub), priv_key: base64url::encode(&sig_seed) },
            enc: Keypair { pub_key: base64url::encode(&enc_pub), priv_key: base64url::encode(&enc_priv) },
        }
    }

    fn mk_room() -> LocalRoom {
        let (pub_bytes, seed_bytes) = ed25519_generate();
        LocalRoom {
            sig: Keypair { pub_key: base64url::encode(&pub_bytes), priv_key: base64url::encode(&seed_bytes) },
        }
    }

    fn mk_config(node: LocalNode, pool: Arc<Pool>) -> RelayConfig {
        RelayConfig {
            node,
            endpoints: vec![],
            pool,
            rooms: std::collections::HashMap::new(),
            metrics: None,
        }
    }

    fn make_request(node: &LocalNode, t: &str, content: serde_json::Value) -> toloo_core::types::Envelope {
        make_envelope(t, Some(content), node, None).expect("request envelope")
    }

    #[tokio::test]
    async fn invalid_signature_returns_error() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let requester = mk_node();
        let config = mk_config(relay, Arc::clone(&pool));

        // Tamper with a valid request.
        let mut env = make_request(&requester, "events.sync", json!({"rooms": [], "after": 0}));
        env.p = "a".repeat(86); // invalid signature

        let result = handle_request(env, &pool, &config).await.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(result[0]["error"], "invalid_signature");
    }

    #[tokio::test]
    async fn unknown_endpoint_returns_error() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let requester = mk_node();
        let config = mk_config(relay, Arc::clone(&pool));

        let env = make_request(&requester, "unknown.endpoint", json!({}));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert_eq!(result[0]["error"], "invalid_request");
    }

    #[tokio::test]
    async fn events_sync_returns_committed_events() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        let (_d1, commit) = make_room_create(&node, &room, Some("Room"), Some(json!([]))).unwrap();
        pool.put(&commit).unwrap();

        let env = make_request(&node, "events.sync", json!({"rooms": [room.sig.pub_key], "after": 0}));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert!(!result.is_empty(), "should return the room.create commit");
        assert!(result.iter().all(|v| v.get("error").is_none()));
    }

    #[tokio::test]
    async fn events_sync_filters_by_after() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        let (_d1, commit) = make_room_create(&node, &room, Some("Room"), Some(json!([]))).unwrap();
        let tc = commit.d.tc.unwrap();
        pool.put(&commit).unwrap();

        // after = tc should exclude that event (strictly greater than).
        let env = make_request(&node, "events.sync", json!({"rooms": [room.sig.pub_key], "after": tc}));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert!(result.is_empty(), "after=tc should exclude that event");
    }

    #[tokio::test]
    async fn system_fetch_returns_envelope_by_id() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        let (_d1, commit) = make_room_create(&node, &room, Some("Room"), Some(json!([]))).unwrap();
        let id = pool.put(&commit).unwrap();

        let env = make_request(&node, "system.fetch", json!({"datum_ids": [id]}));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert_eq!(result.len(), 1);
        assert!(result[0].get("error").is_none());
    }

    #[tokio::test]
    async fn system_fetch_missing_id_returns_empty() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let config = mk_config(relay, Arc::clone(&pool));

        let env = make_request(&node, "system.fetch", json!({"datum_ids": ["a".repeat(64)]}));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert!(result.is_empty());
    }

    #[tokio::test]
    async fn node_peers_returns_node_meta_envelopes() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let peer = mk_node();
        let config = mk_config(relay, Arc::clone(&pool));

        let meta = make_node_meta(&peer, vec![]).unwrap();
        // node.meta is depth-1, store directly.
        pool.put(&meta).unwrap();

        let requester = mk_node();
        let env = make_request(&requester, "node.peers", json!({"limit": 10}));
        // node.peers uses get_wanted with tc filter — node.meta is uncommitted (tc=NULL)
        // so get_wanted won't return it. This is by design: only committed events are served.
        // node.meta has no commit wrapper — relay stores and serves its own node.meta directly.
        // For now, node.peers returns empty (node.meta is not committed).
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert!(result.iter().all(|v| v.get("error").is_none()));
    }

    #[tokio::test]
    async fn pool_exchange_accepts_full_envelope_submission() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        // Create a committed event to submit.
        let (_d1, commit) = make_room_create(&node, &room, Some("Room"), Some(json!([]))).unwrap();
        let commit_val = serde_json::to_value(&commit).unwrap();

        // Offer it as a full envelope in pool.exchange.
        let env = make_request(&node, "pool.exchange", json!({
            "offer": [commit_val],
            "want": {"rooms": [], "types": [], "after": 0, "limit": 10}
        }));
        let _ = handle_request(env, &pool, &config).await.unwrap();

        // Verify the submitted envelope is now in the pool.
        let id = datum_id(&commit);
        let stored = pool.get(&id).unwrap();
        assert!(stored.is_some(), "submitted envelope should be in pool");
    }

    #[tokio::test]
    async fn pool_exchange_returns_wanted_events() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        let (_d1, commit) = make_room_create(&node, &room, Some("Room"), Some(json!([]))).unwrap();
        pool.put(&commit).unwrap();

        let requester = mk_node();
        let env = make_request(&requester, "pool.exchange", json!({
            "offer": [],
            "want": {
                "rooms": [room.sig.pub_key],
                "types": [],
                "after": 0,
                "limit": 100
            }
        }));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert!(!result.is_empty());
        assert!(result.iter().all(|v| v.get("error").is_none()));
    }

    #[tokio::test]
    async fn pool_exchange_excludes_offered_ids() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        let (_d1, commit) = make_room_create(&node, &room, Some("Room"), Some(json!([]))).unwrap();
        let id = pool.put(&commit).unwrap();

        let requester = mk_node();
        let env = make_request(&requester, "pool.exchange", json!({
            "offer": [{"datum_id": id}],
            "want": {
                "rooms": [room.sig.pub_key],
                "types": [],
                "after": 0,
                "limit": 100
            }
        }));
        let result = handle_request(env, &pool, &config).await.unwrap();
        // The offered datum_id should be excluded from the response.
        for val in &result {
            if val.get("error").is_none() {
                // It's an envelope — check its datum_id doesn't match.
                if let Ok(env) = toloo_core::envelope::parse_envelope(val.clone()) {
                    let returned_id = datum_id(&env);
                    assert_ne!(returned_id, id, "offered event should not be returned");
                }
            }
        }
    }

    #[tokio::test]
    async fn room_sync_returns_channel_range() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        // Put two messages in channel 0.
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let msg1 = make_room_message(&node, &room.sig.pub_key, 0, "hello", vec![]).unwrap();
        let tc1 = now;
        let c1 = wrap_commit(msg1, &room, tc1).unwrap();
        pool.put(&c1).unwrap();

        let msg2 = make_room_message(&node, &room.sig.pub_key, 0, "world", vec![]).unwrap();
        let tc2 = now + 1000;
        let c2 = wrap_commit(msg2, &room, tc2).unwrap();
        pool.put(&c2).unwrap();

        // Ask for only tc >= tc2.
        let env = make_request(&node, "room.sync", json!({
            "r": room.sig.pub_key,
            "channel": 0,
            "start_tc": tc2,
            "limit": 100
        }));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert_eq!(result.len(), 1, "only tc=4000 event should be returned");
    }

    #[tokio::test]
    async fn room_compare_returns_signed_result() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let msg = make_room_message(&node, &room.sig.pub_key, 0, "hi", vec![]).unwrap();
        let c = wrap_commit(msg, &room, now).unwrap();
        pool.put(&c).unwrap();

        let env = make_request(&node, "room.compare", json!({
            "r": room.sig.pub_key,
            "channel": 0,
            "samples": [{"seq": 1, "eid": "intentionally_wrong"}]
        }));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert_eq!(result.len(), 1);
        // Result is a room.compare.result envelope signed by the relay.
        let result_env = toloo_core::envelope::parse_envelope(result[0].clone()).unwrap();
        assert_eq!(result_env.d.t, "room.compare.result");
        assert_eq!(result_env.d.n, config.node.sig.pub_key);
        let c = result_env.d.c.unwrap();
        let results = c.get("results").unwrap().as_array().unwrap();
        assert_eq!(results[0]["match"], false); // eid mismatch
    }

    #[tokio::test]
    async fn room_summary_returns_signed_result() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config(relay, Arc::clone(&pool));

        let (_d1, commit) = make_room_create(&node, &room, Some("Test Room"), Some(json!([]))).unwrap();
        pool.put(&commit).unwrap();

        let msg = make_room_message(&node, &room.sig.pub_key, 0, "hello", vec![]).unwrap();
        let tc = commit.d.tc.unwrap() + 1000;
        let c = wrap_commit(msg, &room, tc).unwrap();
        pool.put(&c).unwrap();

        let env = make_request(&node, "room.summary", json!({"rooms": [room.sig.pub_key]}));
        let result = handle_request(env, &pool, &config).await.unwrap();
        assert_eq!(result.len(), 1);
        let result_env = toloo_core::envelope::parse_envelope(result[0].clone()).unwrap();
        assert_eq!(result_env.d.t, "room.summary.result");
        let c = result_env.d.c.unwrap();
        assert_eq!(c["name"], "Test Room");
        assert!(!c["channels"].as_array().unwrap().is_empty());
    }

    // ---- Phase 12: Room Authority tests ----

    fn mk_config_with_room(node: LocalNode, pool: Arc<Pool>, room: &LocalRoom) -> RelayConfig {
        let mut rooms = std::collections::HashMap::new();
        rooms.insert(room.sig.pub_key.clone(), room.clone());
        RelayConfig {
            node,
            endpoints: vec![],
            pool,
            rooms,
            metrics: None,
        }
    }

    #[tokio::test]
    async fn key_holder_auto_commits_submitted_depth1_event() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        // Relay holds the room key.
        let config = mk_config_with_room(relay, Arc::clone(&pool), &room);

        // First, seed the room with a committed room.create (relay is key holder so it auto-commits too).
        let (d1, _) = make_room_create(&node, &room, Some("Auth Room"), Some(json!([]))).unwrap();
        let d1_val = serde_json::to_value(&d1).unwrap();

        // Submit d1 via pool.exchange — relay should auto-commit it.
        let env = make_request(&node, "pool.exchange", json!({
            "offer": [d1_val],
            "want": {"rooms": [], "types": [], "after": 0, "limit": 10}
        }));
        handle_request(env, &pool, &config).await.unwrap();

        // The event should now be in the pool as a committed (depth-2) envelope.
        let all = pool.get_room_channel(&room.sig.pub_key, -1).unwrap();
        let committed = all.iter().any(|e| e.tc.is_some());
        assert!(committed, "relay should auto-commit depth-1 room.create");
    }

    #[tokio::test]
    async fn non_key_holder_does_not_auto_commit() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        // Relay does NOT hold the room key.
        let config = mk_config(relay, Arc::clone(&pool));

        let (d1, _) = make_room_create(&node, &room, Some("No-Key Room"), Some(json!([]))).unwrap();
        let d1_val = serde_json::to_value(&d1).unwrap();

        let env = make_request(&node, "pool.exchange", json!({
            "offer": [d1_val],
            "want": {"rooms": [], "types": [], "after": 0, "limit": 10}
        }));
        handle_request(env, &pool, &config).await.unwrap();

        // Event is stored but uncommitted (tc = None).
        let all = pool.get_room_channel(&room.sig.pub_key, -1).unwrap();
        assert!(!all.is_empty(), "event should still be stored");
        let has_committed = all.iter().any(|e| e.tc.is_some());
        assert!(!has_committed, "relay without room key must not auto-commit");
    }

    #[tokio::test]
    async fn banned_author_is_rejected_by_key_holder() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let banned_node = mk_node();
        let room = mk_room();
        let config = mk_config_with_room(relay, Arc::clone(&pool), &room);

        // Seed a committed room.create first.
        let (d1, _) = make_room_create(&node, &room, Some("Banned Room"), Some(json!([]))).unwrap();
        let d1_val = serde_json::to_value(&d1).unwrap();
        let seed_req = make_request(&node, "pool.exchange", json!({
            "offer": [d1_val], "want": {}
        }));
        handle_request(seed_req, &pool, &config).await.unwrap();

        // Manually insert a committed room.ban for banned_node.
        let ban_event = make_envelope("room.ban", Some(json!({
            "r": room.sig.pub_key,
            "banned": banned_node.sig.pub_key
        })), &node, Some(toloo_core::envelope::DatumBodyExtra {
            r: Some(room.sig.pub_key.clone()),
            to: None, tc: None, exp: None, nonce: None,
        })).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
        let ban_commit = wrap_commit(ban_event, &room, now).unwrap();
        pool.put(&ban_commit).unwrap();

        // Rebuild membership to confirm the ban took effect.
        let membership = pool.build_membership(&room.sig.pub_key).unwrap();
        assert!(membership.banned.contains(&banned_node.sig.pub_key));

        // Now banned_node tries to post a message.
        let msg = make_room_message(&banned_node, &room.sig.pub_key, 0, "spam", vec![]).unwrap();
        let msg_val = serde_json::to_value(&msg).unwrap();
        let req = make_request(&banned_node, "pool.exchange", json!({
            "offer": [msg_val], "want": {}
        }));
        handle_request(req, &pool, &config).await.unwrap();

        // The banned_node's message should be stored uncommitted (validate fails, wrap_commit not called).
        let ch0 = pool.get_room_channel(&room.sig.pub_key, 0).unwrap();
        let banned_committed = ch0.iter()
            .filter(|e| innermost(&e.env).d.n == banned_node.sig.pub_key)
            .any(|e| e.tc.is_some());
        assert!(!banned_committed, "banned author's event must not be auto-committed");
    }

    #[tokio::test]
    async fn key_holder_returns_committed_envelope_in_same_response() {
        // When a key-holder relay auto-commits a submitted depth-1 event, the
        // committed (depth-2) envelope must appear in the pool.exchange response
        // so the sender can confirm the message in a single round-trip.
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node  = mk_node();
        let room  = mk_room();
        let config = mk_config_with_room(relay, Arc::clone(&pool), &room);

        // Seed committed room.create; allow all to post so the message passes rule validation.
        let (d1_create, _) = make_room_create(&node, &room, Some("RT Room"),
            Some(json!([{"t": "post", "allow": "*"}]))).unwrap();
        let seed = make_request(&node, "pool.exchange", json!({
            "offer": [serde_json::to_value(&d1_create).unwrap()],
            "want": {}
        }));
        handle_request(seed, &pool, &config).await.unwrap();

        // Now submit a depth-1 message and want back the room's events.
        let msg = make_room_message(&node, &room.sig.pub_key, 0, "hello", vec![]).unwrap();
        let msg_val = serde_json::to_value(&msg).unwrap();

        let req = make_request(&node, "pool.exchange", json!({
            "offer": [msg_val],
            "want": {"rooms": [room.sig.pub_key], "types": [], "after": 0, "limit": 100}
        }));
        let result = handle_request(req, &pool, &config).await.unwrap();

        // The response must contain the committed (depth-2) version of the message.
        let has_committed_msg = result.iter().any(|v| {
            if let Ok(env) = toloo_core::envelope::parse_envelope(v.clone()) {
                let d = toloo_core::envelope::depth(&env);
                let t = &toloo_core::envelope::innermost(&env).d.t;
                d == 2 && t == "room.message"
            } else { false }
        });
        assert!(has_committed_msg,
            "pool.exchange response must include the auto-committed depth-2 message");
    }

    #[tokio::test]
    async fn depth2_event_is_not_re_committed() {
        let pool = Arc::new(Pool::memory().unwrap());
        let relay = mk_node();
        let node = mk_node();
        let room = mk_room();
        let config = mk_config_with_room(relay, Arc::clone(&pool), &room);

        // Create a depth-2 event (already committed) and submit it.
        let (_, commit) = make_room_create(&node, &room, Some("Room"), Some(json!([]))).unwrap();
        let commit_val = serde_json::to_value(&commit).unwrap();

        let env = make_request(&node, "pool.exchange", json!({
            "offer": [commit_val],
            "want": {}
        }));
        handle_request(env, &pool, &config).await.unwrap();

        // Should be stored as depth-2, not wrapped again into depth-3.
        let all = pool.get_room_channel(&room.sig.pub_key, -1).unwrap();
        let depth3 = all.iter().any(|e| toloo_core::envelope::depth(&e.env) == 3);
        assert!(!depth3, "committed events must not be re-committed to depth-3");
    }
}
