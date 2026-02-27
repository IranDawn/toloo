use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::Arc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use serde_json::json;

use toloo_core::base64url;
use toloo_core::crypto::{ed25519_generate, x25519_generate};
use toloo_core::envelope::{innermost, make_envelope, parse_envelope, verify_chain};
use toloo_core::events::{make_node_meta, make_room_create, make_room_join, make_room_message};
use toloo_core::ids::eid;
use toloo_core::types::{Envelope, Keypair, LocalNode, LocalRoom};
use toloo_core::vectors::VectorSet;
use toloo_lib::discovery::{decode as discovery_decode, encode_file, encode_uri};
use toloo_lib::pool::Pool;
use toloo_lib::transport::server::{EndpointConfig, RelayConfig, run_relay};

// ---- CLI definition ----

#[derive(Parser)]
#[command(
    name = "toloo",
    about = "Toloo Protocol v0.2 — censorship-resistant messaging",
    long_about = "\
Toloo Protocol v0.2 reference implementation.

Quick start:
  toloo keygen > identity.json
  toloo create-room --name \"My Room\" --identity identity.json
  toloo sync ws://localhost:17701 <room_pub>
  toloo send ws://localhost:17701 <room_pub> \"Hello\" --identity identity.json"
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new node identity (Ed25519 signing + X25519 encryption keypairs).
    ///
    /// Prints a JSON object. Redirect to a file and keep it secure:
    ///   toloo keygen > identity.json
    Keygen,

    /// Create a new room and print its invite URI.
    ///
    /// Creates a room keypair, signs the room.create event, and prints a
    /// toloo:// URI that others can import to join the room.
    /// The room keypair is saved to a file (needed for key-holder relay mode).
    ///
    /// Example:
    ///   toloo create-room --name "Resistance" --identity identity.json
    #[command(name = "create-room")]
    CreateRoom {
        /// Optional room display name.
        #[arg(long)]
        name: Option<String>,
        /// Path to node identity JSON (from `keygen`). Falls back to env vars.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Submit the room.create envelope to this relay after creation.
        #[arg(long)]
        relay: Option<String>,
        /// Where to save the room keypair JSON.
        /// Default: toloo-room-<first8chars>.json
        #[arg(long)]
        room_out: Option<PathBuf>,
    },

    /// Import envelopes from a toloo:// URI or a .toloo file.
    ///
    /// Decodes and verifies each envelope, then prints a human-readable summary.
    /// The first envelope in a room invite is typically the committed room.create.
    ///
    /// Examples:
    ///   toloo import "toloo://BASE64..."
    ///   toloo import seed-nodes.toloo
    Import {
        /// A toloo:// URI string or path to a .toloo file.
        input: String,
    },

    /// Sign and send a message to a room via a relay.
    ///
    /// Example:
    ///   toloo send ws://localhost:17701 <room_pub> "Hello" --identity identity.json
    Send {
        /// WebSocket URL of the relay.
        relay: String,
        /// Room public key (base64url, 43 chars).
        room: String,
        /// Message body text.
        body: String,
        /// Path to node identity JSON (from `keygen`).
        #[arg(long)]
        identity: PathBuf,
    },

    /// Perform a pool.exchange with a relay and print (or save) received envelopes.
    ///
    /// Examples:
    ///   toloo sync ws://localhost:17701 <room_pub>
    ///   toloo sync ws://localhost:17701 <room_pub> --output dump.toloo
    ///   toloo sync ws://localhost:17701 <room_pub> --offer invite.toloo
    Sync {
        /// WebSocket URL of the relay (e.g. ws://localhost:17701).
        relay: String,
        /// Room public key (base64url, 43 chars) to sync.
        room: String,
        /// Only fetch events after this timestamp (ms). Defaults to 0 (full sync).
        #[arg(long, default_value = "0")]
        after: u64,
        /// Path to node identity JSON. If omitted, a throwaway identity is used.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Save received envelopes to a .toloo file instead of printing to stdout.
        #[arg(long)]
        output: Option<PathBuf>,
        /// Include envelopes from this toloo:// URI or .toloo file in the offer.
        #[arg(long)]
        offer: Option<String>,
    },

    /// Start the relay server (TCP encrypted + optional WebSocket).
    ///
    /// Requires a node identity via --identity or env vars:
    ///   TOLOO_SIG_PUB, TOLOO_SIG_PRIV, TOLOO_ENC_PUB, TOLOO_ENC_PRIV
    Relay {
        /// Bind address.
        #[arg(long, default_value = "0.0.0.0")]
        host: String,
        /// TCP port (x25519-v0.2 encrypted).
        #[arg(long, default_value = "7700")]
        port: u16,
        /// Optional WebSocket port (plain JSON — use behind a TLS terminator).
        #[arg(long)]
        ws_port: Option<u16>,
        /// Path to SQLite database file. Omit for in-memory (data lost on exit).
        #[arg(long)]
        db: Option<PathBuf>,
        /// Path to node identity JSON.
        #[arg(long)]
        identity: Option<PathBuf>,
        /// Path to room keypair JSON for key-holder / auto-commit mode.
        /// Can be repeated for multiple rooms.
        #[arg(long)]
        room_key: Vec<PathBuf>,
    },

    /// Print deterministic test vectors for Toloo v0.2 (spec §Appendix E).
    Vectors,
}

// ---- Entry point ----

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Commands::Keygen => cmd_keygen(),
        Commands::CreateRoom { name, identity, relay, room_out } => {
            cmd_create_room(name, identity, relay, room_out).await
        }
        Commands::Import { input } => cmd_import(input),
        Commands::Send { relay, room, body, identity } => {
            cmd_send(relay, room, body, identity).await
        }
        Commands::Sync { relay, room, after, identity, output, offer } => {
            cmd_sync(relay, room, after, identity, output, offer).await
        }
        Commands::Relay { host, port, ws_port, db, identity, room_key } => {
            cmd_relay(host, port, ws_port, db, identity, room_key).await
        }
        Commands::Vectors => cmd_vectors(),
    }
}

// ================================================================
// keygen
// ================================================================

fn cmd_keygen() -> Result<()> {
    let (sig_pub, sig_seed) = ed25519_generate();
    let (enc_pub, enc_priv) = x25519_generate();
    let identity = json!({
        "sig_pub":  base64url::encode(&sig_pub),
        "sig_priv": base64url::encode(&sig_seed),
        "enc_pub":  base64url::encode(&enc_pub),
        "enc_priv": base64url::encode(&enc_priv),
    });
    println!("{}", serde_json::to_string_pretty(&identity)?);
    Ok(())
}

// ================================================================
// create-room
// ================================================================

async fn cmd_create_room(
    name: Option<String>,
    identity: Option<PathBuf>,
    relay: Option<String>,
    room_out: Option<PathBuf>,
) -> Result<()> {
    let node = load_node_identity(identity)?;

    // Generate room keypair.
    let (room_pub_bytes, room_seed) = ed25519_generate();
    let room = LocalRoom {
        sig: Keypair {
            pub_key:  base64url::encode(&room_pub_bytes),
            priv_key: base64url::encode(&room_seed),
        },
    };

    // Default rules: anyone can join and post.
    let default_rules = json!([
        { "t": "join", "allow": "*" },
        { "t": "post", "allow": "*" }
    ]);
    let (_authored, committed) =
        make_room_create(&node, &room, name.as_deref(), Some(default_rules))?;

    // Build invite URI: committed room.create + creator's node.meta.
    // The node.meta lets importers know how to reach the creator (peer bootstrap).
    let node_meta = make_node_meta(&node, vec![])?;
    let invite_uri = encode_uri(&[committed.clone(), node_meta])?;

    // Save room keypair for key-holder relay mode.
    let room_keypair_json = serde_json::to_string_pretty(&json!({
        "sig_pub":  room.sig.pub_key,
        "sig_priv": room.sig.priv_key,
    }))?;
    let room_file = room_out.unwrap_or_else(|| {
        PathBuf::from(format!("toloo-room-{}.json", &room.sig.pub_key[..8]))
    });
    std::fs::write(&room_file, &room_keypair_json)
        .with_context(|| format!("failed to write room keypair to {}", room_file.display()))?;

    // Optionally submit to relay.
    if let Some(relay_url) = &relay {
        let committed_json = serde_json::to_string(&committed)?;
        eprintln!("[toloo] submitting room.create to {relay_url}");
        ws_pool_exchange(relay_url, &node, vec![committed_json], vec![], 0).await
            .with_context(|| format!("failed to submit to {relay_url}"))?;
        eprintln!("[toloo] submitted.");
    }

    // Output.
    let output = json!({
        "room_pub":          room.sig.pub_key,
        "room_keypair_file": room_file.display().to_string(),
        "invite_uri":        invite_uri,
    });
    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

// ================================================================
// import
// ================================================================

fn cmd_import(input: String) -> Result<()> {
    // Read from file or treat directly as URI / inline content.
    let raw = if input.starts_with("toloo://") {
        input.clone()
    } else {
        let path = std::path::Path::new(&input);
        if path.exists() {
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read {input}"))?
        } else {
            // Not a file, try treating as raw content (e.g. pasted toloo:// URI).
            input.clone()
        }
    };

    let envelopes = discovery_decode(&raw).context("failed to decode — not a valid toloo:// URI or .toloo file")?;

    eprintln!("[toloo] {} envelope(s) found\n", envelopes.len());

    for (i, env) in envelopes.iter().enumerate() {
        let inner = innermost(env);
        let event_id = eid(env);
        let t        = &inner.d.t;
        let author   = &inner.d.n;
        let ts       = inner.d.ts;

        println!("── Envelope {} ─────────────────────────", i + 1);
        println!("  type:   {t}");
        println!("  eid:    {event_id}");
        println!("  author: {author}");
        println!("  ts:     {ts}");

        match t.as_str() {
            "room.create" | "commit" => {
                let c = innermost(env);
                // For a commit, room pub = d.n of the outer (room signs commits).
                // For a depth-1 room.create, room pub = d.r.
                let room_pub = if env.d.t == "commit" {
                    env.d.n.clone()
                } else {
                    c.d.r.clone().unwrap_or_else(|| c.d.n.clone())
                };
                println!("  room:   {room_pub}");
                if let Some(name) = c.d.c.as_ref()
                    .and_then(|c| c.get("name"))
                    .and_then(|v| v.as_str())
                {
                    println!("  name:   {name}");
                }
                if let Some(rules) = c.d.c.as_ref().and_then(|c| c.get("rules")) {
                    println!("  rules:  {}", serde_json::to_string(rules)?);
                }
                println!();
                println!("  → To join this room:");
                println!("      room_pub = {room_pub}");
            }
            "node.meta" => {
                if let Some(endpoints) = inner.d.c.as_ref()
                    .and_then(|c| c.get("endpoints"))
                    .and_then(|v| v.as_array())
                {
                    for ep in endpoints {
                        let proto = ep.get("proto").and_then(|v| v.as_str()).unwrap_or("?");
                        let host  = ep.get("host").and_then(|v| v.as_str()).unwrap_or("?");
                        let port  = ep.get("port").and_then(|v| v.as_u64()).unwrap_or(0);
                        println!("  endpoint: {proto}://{host}:{port}");
                    }
                }
                println!();
                println!("  → Connect to peer: {author}");
            }
            "room.message" => {
                let body = inner.d.c.as_ref()
                    .and_then(|c| c.get("body"))
                    .and_then(|v| v.as_str())
                    .unwrap_or("(no body)");
                let room = inner.d.r.as_deref().unwrap_or("?");
                println!("  room:   {room}");
                println!("  body:   {body}");
            }
            _ => {}
        }
        println!();
    }

    Ok(())
}

// ================================================================
// send
// ================================================================

async fn cmd_send(
    relay_url: String,
    room_pub:  String,
    body:      String,
    identity:  PathBuf,
) -> Result<()> {
    let node = load_node_identity(Some(identity))?;

    // Sign the join envelope first (relay needs it to authorise the post).
    // This is best-effort — the relay may already have a join for this node.
    let join_env = make_room_join(&node, &room_pub, None)?;
    let join_json = serde_json::to_string(&join_env)?;

    // Sign the message.
    let msg_env  = make_room_message(&node, &room_pub, 0, &body, vec![])?;
    let msg_json = serde_json::to_string(&msg_env)?;
    let event_id = eid(&msg_env);

    eprintln!("[toloo] node:    {}", node.sig.pub_key);
    eprintln!("[toloo] room:    {room_pub}");
    eprintln!("[toloo] relay:   {relay_url}");
    eprintln!("[toloo] eid:     {event_id}");

    // Offer both join + message in a single exchange.
    // Want back the room messages to confirm commit.
    ws_pool_exchange(
        &relay_url,
        &node,
        vec![join_json, msg_json],
        vec![room_pub],
        0,
    ).await.context("relay exchange failed")?;

    eprintln!("[toloo] sent.");
    println!("{event_id}");
    Ok(())
}

// ================================================================
// sync
// ================================================================

async fn cmd_sync(
    relay_url: String,
    room_pub:  String,
    after:     u64,
    identity:  Option<PathBuf>,
    output:    Option<PathBuf>,
    offer_src: Option<String>,
) -> Result<()> {
    let node = match identity {
        Some(p) => load_node_identity(Some(p))?,
        None    => throwaway_node(),
    };

    // Build offer from a .toloo file or toloo:// URI if requested.
    let offer: Vec<String> = match offer_src {
        None => vec![],
        Some(src) => {
            let raw = if src.starts_with("toloo://") {
                src
            } else {
                std::fs::read_to_string(&src)
                    .with_context(|| format!("failed to read offer file: {src}"))?
            };
            discovery_decode(&raw)
                .context("failed to decode offer input")?
                .iter()
                .map(|e| serde_json::to_string(e).unwrap())
                .collect()
        }
    };

    eprintln!("[toloo] connecting to {relay_url}");
    let envelopes = ws_pool_exchange(
        &relay_url, &node, offer, vec![room_pub], after,
    ).await?;
    eprintln!("[toloo] received {} envelope(s)", envelopes.len());

    match output {
        Some(path) => {
            let content = encode_file(&envelopes)?;
            std::fs::write(&path, content)
                .with_context(|| format!("failed to write {}", path.display()))?;
            eprintln!("[toloo] saved to {}", path.display());
        }
        None => {
            // Print each envelope as one JSON line (machine-readable).
            for env in &envelopes {
                println!("{}", serde_json::to_string(env)?);
            }
        }
    }
    Ok(())
}

// ================================================================
// relay
// ================================================================

async fn cmd_relay(
    host:           String,
    port:           u16,
    ws_port:        Option<u16>,
    db:             Option<PathBuf>,
    identity:       Option<PathBuf>,
    room_key_paths: Vec<PathBuf>,
) -> Result<()> {
    let node = load_node_identity(identity)?;

    let pool = match db {
        Some(path) => {
            let s = path.to_str().context("invalid DB path")?;
            Arc::new(Pool::open(s).context("failed to open database")?)
        }
        None => {
            eprintln!("[toloo] warning: no --db specified, using in-memory pool (data lost on exit)");
            Arc::new(Pool::memory()?)
        }
    };

    let mut rooms: HashMap<String, LocalRoom> = HashMap::new();
    for path in room_key_paths {
        let room = load_room_keypair(&path)?;
        eprintln!("[toloo] loaded room key: {}", room.sig.pub_key);
        rooms.insert(room.sig.pub_key.clone(), room);
    }

    let meta = make_node_meta(&node, vec![])?;
    pool.put(&meta)?;

    let tcp_addr: std::net::SocketAddr =
        format!("{host}:{port}").parse().context("invalid TCP address")?;

    let mut endpoints = vec![
        EndpointConfig { addr: tcp_addr, proto: "tcp".to_owned(), skin: Some("x25519-v0.2".to_owned()), path: None, tls: None },
    ];

    if let Some(wp) = ws_port {
        let ws_addr: std::net::SocketAddr =
            format!("{host}:{wp}").parse().context("invalid WS address")?;
        endpoints.push(EndpointConfig { addr: ws_addr, proto: "ws".to_owned(), skin: None, path: None, tls: None });
        eprintln!("[toloo] WS  {ws_addr}");
    }

    eprintln!("[toloo] node: {}", node.sig.pub_key);
    eprintln!("[toloo] TCP/x25519-v0.2  {tcp_addr}");

    let config = Arc::new(RelayConfig { node, endpoints, pool, rooms, metrics: None });
    run_relay(config).await
}

// ================================================================
// vectors
// ================================================================

fn cmd_vectors() -> Result<()> {
    let v = VectorSet::compute().context("failed to compute test vectors")?;

    let output = json!({
        "version": "0.2",
        "note": "All [REF] values for toloo/E-test-vectors.md",
        "identities": {
            "arta": {
                "sig_seed_hex": v.arta.sig_seed_hex,
                "sig_pub_hex":  v.arta.sig_pub_hex,
                "sig_pub_b64":  v.arta.sig_pub_b64,
                "enc_seed_hex": v.arta.enc_seed_hex,
                "enc_pub_hex":  v.arta.enc_pub_hex,
                "enc_pub_b64":  v.arta.enc_pub_b64,
            },
            "babak": {
                "sig_seed_hex": v.babak.sig_seed_hex,
                "sig_pub_hex":  v.babak.sig_pub_hex,
                "sig_pub_b64":  v.babak.sig_pub_b64,
                "enc_seed_hex": v.babak.enc_seed_hex,
                "enc_pub_hex":  v.babak.enc_pub_hex,
                "enc_pub_b64":  v.babak.enc_pub_b64,
            },
            "mithra": {
                "sig_seed_hex": v.mithra.sig_seed_hex,
                "sig_pub_hex":  v.mithra.sig_pub_hex,
                "sig_pub_b64":  v.mithra.sig_pub_b64,
                "enc_seed_hex": v.mithra.enc_seed_hex,
                "enc_pub_hex":  v.mithra.enc_pub_hex,
                "enc_pub_b64":  v.mithra.enc_pub_b64,
            },
            "room": {
                "sig_seed_hex": v.room.sig_seed_hex,
                "sig_pub_hex":  v.room.sig_pub_hex,
                "sig_pub_b64":  v.room.sig_pub_b64,
            },
            "relay": {
                "sig_seed_hex": v.relay.sig_seed_hex,
                "sig_pub_hex":  v.relay.sig_pub_hex,
                "sig_pub_b64":  v.relay.sig_pub_b64,
                "enc_seed_hex": v.relay.enc_seed_hex,
                "enc_pub_hex":  v.relay.enc_pub_hex,
                "enc_pub_b64":  v.relay.enc_pub_b64,
            },
        },
        "canonical_json": {
            "e3_1": v.e3_1_canonical, "e3_2": v.e3_2_canonical,
            "e3_3": v.e3_3_canonical, "e3_4": v.e3_4_canonical, "e3_5": v.e3_5_canonical,
        },
        "envelope_signing": {
            "e4_1_canonical_hex": v.e4_1_canonical_hex,
            "e4_1_sig_hex":       v.e4_1_sig_hex,
            "e4_1_sig_b64":       v.e4_1_sig_b64,
            "e4_1_envelope":      serde_json::to_value(&v.e4_1_envelope)?,
        },
        "commit": {
            "e5_1_outer_canonical": v.e5_1_outer_canonical,
            "e5_1_outer_sig_b64":   v.e5_1_outer_sig_b64,
            "e5_1_envelope":        serde_json::to_value(&v.e5_1_commit)?,
        },
        "identity": {
            "e6_1_eid":         v.e6_1_eid,
            "e6_3_datum_id_d1": v.e6_3_datum_id_d1,
            "e6_3_datum_id_d2": v.e6_3_datum_id_d2,
        },
        "private_message": {
            "e7_eph_pub_hex":    v.e7_eph_pub_hex,
            "e7_eph_pub_b64":    v.e7_eph_pub_b64,
            "e7_shared_hex":     v.e7_shared_hex,
            "e7_salt_hex":       v.e7_salt_hex,
            "e7_okm_hex":        v.e7_okm_hex,
            "e7_key_hex":        v.e7_key_hex,
            "e7_nonce_hex":      v.e7_nonce_hex,
            "e7_ciphertext_b64": v.e7_ciphertext_b64,
        },
        "endpoint_encryption": {
            "e8_initiator_eph_pub_hex": v.e8_initiator_eph_pub_hex,
            "e8_responder_eph_pub_hex": v.e8_responder_eph_pub_hex,
            "e8_shared_hex":            v.e8_shared_hex,
            "e8_okm_hex":               v.e8_okm_hex,
            "e8_k_i2r_hex":             v.e8_k_i2r_hex,
            "e8_k_r2i_hex":             v.e8_k_r2i_hex,
            "e8_transcript_hex":        v.e8_transcript_hex,
            "e8_proof_b64":             v.e8_proof_b64,
        },
        "proof_of_work": {
            "e9_required_bits":    16,
            "e9_winning_nonce":    v.e9_winning_nonce,
            "e9_winning_hash_hex": v.e9_winning_hash_hex,
        },
        "base64url": v.e13_cases.iter()
            .map(|(hex_in, b64_out)| json!({"hex": hex_in, "b64": b64_out}))
            .collect::<Vec<_>>(),
    });

    println!("{}", serde_json::to_string_pretty(&output)?);
    Ok(())
}

// ================================================================
// Shared WebSocket helper
// ================================================================

/// Perform a pool.exchange over WebSocket and return all received envelopes.
async fn ws_pool_exchange(
    relay_url:  &str,
    node:       &LocalNode,
    offer:      Vec<String>,
    want_rooms: Vec<String>,
    after:      u64,
) -> Result<Vec<Envelope>> {
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    let offer_values: Vec<serde_json::Value> = offer
        .iter()
        .filter_map(|j| serde_json::from_str(j).ok())
        .collect();

    let request = make_envelope(
        "pool.exchange",
        Some(json!({
            "offer": offer_values,
            "want": {
                "rooms": want_rooms,
                "after": after,
                "limit": 1000,
            }
        })),
        node,
        None,
    )?;

    let (mut ws, _) = connect_async(relay_url)
        .await
        .with_context(|| format!("failed to connect to {relay_url}"))?;

    ws.send(Message::Text(serde_json::to_string(&request)?.into()))
        .await
        .context("WS send failed")?;

    let mut results = Vec::new();
    while let Some(msg) = ws.next().await {
        match msg? {
            Message::Text(text) => {
                match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(v) => {
                        if v.get("done").is_some() { break; }
                        if v.get("error").is_some() {
                            eprintln!("[toloo] relay error: {v}");
                            continue;
                        }
                        match parse_envelope(v) {
                            Ok(env) if verify_chain(&env).is_ok() => results.push(env),
                            Ok(_)  => eprintln!("[toloo] dropped: invalid chain"),
                            Err(e) => eprintln!("[toloo] dropped: {e}"),
                        }
                    }
                    Err(e) => eprintln!("[toloo] parse error: {e}"),
                }
            }
            Message::Close(_) => break,
            Message::Ping(p)  => { ws.send(Message::Pong(p)).await.ok(); }
            _                 => {}
        }
    }
    let _ = ws.close(None).await;
    Ok(results)
}

// ================================================================
// Identity loading
// ================================================================

fn throwaway_node() -> LocalNode {
    let (sig_pub, sig_seed) = ed25519_generate();
    let (enc_pub, enc_priv) = x25519_generate();
    LocalNode {
        sig: Keypair { pub_key: base64url::encode(&sig_pub), priv_key: base64url::encode(&sig_seed) },
        enc: Keypair { pub_key: base64url::encode(&enc_pub), priv_key: base64url::encode(&enc_priv) },
    }
}

fn load_node_identity(path: Option<PathBuf>) -> Result<LocalNode> {
    if let Some(p) = path {
        let s = std::fs::read_to_string(&p)
            .with_context(|| format!("failed to read identity file: {}", p.display()))?;
        let v: serde_json::Value = serde_json::from_str(&s).context("identity file is not valid JSON")?;
        return Ok(LocalNode {
            sig: Keypair { pub_key: req_str(&v, "sig_pub")?, priv_key: req_str(&v, "sig_priv")? },
            enc: Keypair { pub_key: req_str(&v, "enc_pub")?, priv_key: req_str(&v, "enc_priv")? },
        });
    }
    let sig_pub  = std::env::var("TOLOO_SIG_PUB").context("no --identity and TOLOO_SIG_PUB not set")?;
    let sig_priv = std::env::var("TOLOO_SIG_PRIV").context("TOLOO_SIG_PRIV not set")?;
    let enc_pub  = std::env::var("TOLOO_ENC_PUB").context("TOLOO_ENC_PUB not set")?;
    let enc_priv = std::env::var("TOLOO_ENC_PRIV").context("TOLOO_ENC_PRIV not set")?;
    Ok(LocalNode {
        sig: Keypair { pub_key: sig_pub, priv_key: sig_priv },
        enc: Keypair { pub_key: enc_pub, priv_key: enc_priv },
    })
}

fn load_room_keypair(path: &PathBuf) -> Result<LocalRoom> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("failed to read room key: {}", path.display()))?;
    let v: serde_json::Value = serde_json::from_str(&s).context("room key is not valid JSON")?;
    Ok(LocalRoom {
        sig: Keypair { pub_key: req_str(&v, "sig_pub")?, priv_key: req_str(&v, "sig_priv")? },
    })
}

fn req_str(v: &serde_json::Value, key: &str) -> Result<String> {
    v.get(key)
        .and_then(|s| s.as_str())
        .map(str::to_owned)
        .with_context(|| format!("missing field '{key}'"))
}
