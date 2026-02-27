use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use toloo_core::types::{LocalNode, LocalRoom};
use toloo_lib::transport::server::RelayMetrics;

// ══════════════════════════════════════════════════════════════════════
// Relay config DB (SQLite, persisted across restarts)
// ══════════════════════════════════════════════════════════════════════

pub struct AppDb {
    conn: rusqlite::Connection,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayConfigRecord {
    pub id:      String,
    pub proto:   String,
    pub host:    String,
    pub port:    u16,
    pub skin:    Option<String>,
    pub padding: Option<String>,
    pub path:    Option<String>,
    pub direct:  bool,
    /// Whether this relay was running when the app was last closed.
    pub active:  bool,
}

impl AppDb {
    pub fn open(path: &std::path::Path) -> Result<Self, String> {
        if let Some(dir) = path.parent() {
            std::fs::create_dir_all(dir).map_err(|e| e.to_string())?;
        }
        let conn = rusqlite::Connection::open(path).map_err(|e| e.to_string())?;
        conn.execute_batch("
            CREATE TABLE IF NOT EXISTS relay_configs (
                id      TEXT PRIMARY KEY,
                proto   TEXT NOT NULL,
                host    TEXT NOT NULL,
                port    INTEGER NOT NULL,
                skin    TEXT,
                padding TEXT,
                path    TEXT,
                direct  INTEGER NOT NULL DEFAULT 1,
                active  INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS blocklist (
                node_pub   TEXT PRIMARY KEY,
                kind       TEXT NOT NULL DEFAULT 'block',
                reason     TEXT,
                blocked_at INTEGER NOT NULL
            );
        ").map_err(|e| e.to_string())?;
        Ok(Self { conn })
    }

    pub fn save(&self, r: &RelayConfigRecord) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR REPLACE INTO relay_configs
             (id, proto, host, port, skin, padding, path, direct, active)
             VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9)",
            rusqlite::params![
                r.id, r.proto, r.host, r.port as i64,
                r.skin, r.padding, r.path,
                r.direct as i64, r.active as i64
            ],
        ).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn delete(&self, id: &str) -> Result<(), String> {
        self.conn.execute("DELETE FROM relay_configs WHERE id = ?1", [id])
            .map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn list(&self) -> Result<Vec<RelayConfigRecord>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT id,proto,host,port,skin,padding,path,direct,active
             FROM relay_configs ORDER BY rowid"
        ).map_err(|e| e.to_string())?;
        // Bind rows to a variable so that the MappedRows borrow on `stmt` is
        // consumed and dropped before `stmt` goes out of scope.
        let rows: Vec<RelayConfigRecord> = stmt.query_map([], |row| Ok(RelayConfigRecord {
            id:      row.get(0)?,
            proto:   row.get(1)?,
            host:    row.get(2)?,
            port:    row.get::<_, i64>(3)? as u16,
            skin:    row.get(4)?,
            padding: row.get(5)?,
            path:    row.get(6)?,
            direct:  row.get::<_, i64>(7)? != 0,
            active:  row.get::<_, i64>(8)? != 0,
        }))
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
        Ok(rows)
    }

    pub fn set_active(&self, id: &str, active: bool) -> Result<(), String> {
        self.conn.execute(
            "UPDATE relay_configs SET active = ?1 WHERE id = ?2",
            rusqlite::params![active as i64, id],
        ).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn block_node(&self, node_pub: &str, kind: &str, reason: Option<&str>, now: u64) -> Result<(), String> {
        self.conn.execute(
            "INSERT OR REPLACE INTO blocklist (node_pub, kind, reason, blocked_at) VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![node_pub, kind, reason, now as i64],
        ).map(|_| ()).map_err(|e| e.to_string())
    }

    pub fn unblock_node(&self, node_pub: &str) -> Result<bool, String> {
        let changed = self.conn.execute(
            "DELETE FROM blocklist WHERE node_pub = ?1", [node_pub],
        ).map_err(|e| e.to_string())?;
        Ok(changed > 0)
    }

    pub fn get_blocklist(&self) -> Result<Vec<(String, String, Option<String>, u64)>, String> {
        let mut stmt = self.conn.prepare(
            "SELECT node_pub, kind, reason, blocked_at FROM blocklist ORDER BY blocked_at DESC"
        ).map_err(|e| e.to_string())?;
        let rows: Vec<(String, String, Option<String>, u64)> = stmt.query_map([], |row| {
            let ts: i64 = row.get(3)?;
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, ts as u64))
        })
        .map_err(|e| e.to_string())?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| e.to_string())?;
        Ok(rows)
    }

    pub fn is_blocked(&self, node_pub: &str) -> Result<bool, String> {
        let exists: bool = self.conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM blocklist WHERE node_pub = ?1)",
            [node_pub],
            |row| row.get(0),
        ).map_err(|e| e.to_string())?;
        Ok(exists)
    }
}

// ══════════════════════════════════════════════════════════════════════
// App state
// ══════════════════════════════════════════════════════════════════════

pub struct LocalRelayEntry {
    pub runtime_id: u32,
    pub config_id:  String,
    pub stop_tx:    tokio::sync::oneshot::Sender<()>,
    pub invite_uri: String,
    pub proto:      String,
    pub host:       String,
    pub port:       u16,
    pub skin:       Option<String>,
    pub metrics:    Arc<RelayMetrics>,
}

pub struct AppState {
    pub node:          Mutex<Option<LocalNode>>,
    pub rooms:         Mutex<HashMap<String, LocalRoom>>,  // room_pub → LocalRoom (key held by this node)
    pub relays:        Mutex<Vec<LocalRelayEntry>>,
    pub relay_id_next: Mutex<u32>,
    pub db:            Mutex<Option<AppDb>>,
}

// ══════════════════════════════════════════════════════════════════════
// Commands
// ══════════════════════════════════════════════════════════════════════

mod commands {
    use std::collections::HashMap;
    use std::net::SocketAddr;
    use std::sync::Arc;

    use serde::{Deserialize, Serialize};
    use serde_json::Value;

    use toloo_core::base64url;
    use toloo_core::crypto::{ed25519_generate, x25519_generate};
    use toloo_core::envelope::{depth, innermost, make_envelope, parse_envelope, verify_chain, wrap_ack};
    use toloo_core::events::{make_node_meta, make_room_create, make_room_join, make_room_message, make_side_attestation, make_room_flag};
    use toloo_core::keystore;
    use toloo_core::ids::eid;
    use toloo_core::types::{EndpointDescriptor, Envelope, Keypair, LocalNode, LocalRoom};
    use toloo_lib::discovery::{
        decode as discovery_decode,
        encode_file as discovery_encode_file,
        encode_uri as discovery_encode_uri,
    };
    use toloo_lib::pool::Pool;
    use toloo_lib::transport::server::{EndpointConfig, run_relay, RelayConfig, RelayMetrics};
    use toloo_lib::transport::tls::make_self_signed_acceptor;
    use futures_util::{SinkExt, StreamExt};
    use tokio_tungstenite::{connect_async, tungstenite::Message};

    use super::{AppDb, AppState, LocalRelayEntry, RelayConfigRecord};

    // ─── Return types ─────────────────────────────────────────────────

    #[derive(Debug, Serialize, Deserialize, Clone)]
    pub struct RelayInfo {
        pub runtime_id: u32,
        pub config_id:  String,
        pub invite_uri: String,
        pub proto:      String,
        pub host:       String,
        pub port:       u16,
        pub skin:       Option<String>,
        pub active:     usize,
        pub total:      usize,
        pub bytes_in:   u64,
        pub bytes_out:  u64,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct NodeInfo {
        pub sig_pub:   String,
        pub enc_pub:   String,
        pub node_json: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct MessageItem {
        pub eid:           String,
        pub author:        String,
        pub body:          String,
        pub ts:            u64,
        pub depth:         u8,
        pub envelope_json: String,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct InviteInfo {
        pub room_pub:       String,
        pub room_name:      Option<String>,
        pub creator:        String,
        pub invite_uri:     String,
        pub envelope_jsons: Vec<String>,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct BlocklistItem {
        pub node_pub:   String,
        pub kind:       String,
        pub reason:     Option<String>,
        pub blocked_at: u64,
    }

    // ─── Helpers ──────────────────────────────────────────────────────

    fn to_err<E: std::fmt::Display>(e: E) -> String { e.to_string() }

    fn node_info(node: &LocalNode) -> Result<NodeInfo, String> {
        Ok(NodeInfo {
            sig_pub:   node.sig.pub_key.clone(),
            enc_pub:   node.enc.pub_key.clone(),
            node_json: serde_json::to_string(node).map_err(to_err)?,
        })
    }

    fn parse_env_str(json: &str) -> Result<Envelope, String> {
        let v: Value = serde_json::from_str(json).map_err(to_err)?;
        parse_envelope(v).map_err(to_err)
    }

    fn serialize_env(env: &Envelope) -> Result<String, String> {
        serde_json::to_string(env).map_err(to_err)
    }

    fn message_item(env: &Envelope) -> Option<MessageItem> {
        let inner = innermost(env);
        if inner.d.t != "room.message" { return None; }
        let body = inner.d.c.as_ref()?.get("body")?.as_str()?.to_owned();
        Some(MessageItem {
            eid:           eid(env),
            author:        inner.d.n.clone(),
            body,
            ts:            inner.d.ts,
            depth:         depth(env),
            envelope_json: serde_json::to_string(env).ok()?,
        })
    }

    fn throwaway_node() -> LocalNode {
        let (sig_pub, sig_seed) = ed25519_generate();
        let (enc_pub, enc_priv) = x25519_generate();
        LocalNode {
            sig: Keypair { pub_key: base64url::encode(&sig_pub),  priv_key: base64url::encode(&sig_seed) },
            enc: Keypair { pub_key: base64url::encode(&enc_pub),  priv_key: base64url::encode(&enc_priv) },
        }
    }

    fn relay_info(entry: &LocalRelayEntry) -> RelayInfo {
        use std::sync::atomic::Ordering;
        RelayInfo {
            runtime_id: entry.runtime_id,
            config_id:  entry.config_id.clone(),
            invite_uri: entry.invite_uri.clone(),
            proto:      entry.proto.clone(),
            host:       entry.host.clone(),
            port:       entry.port,
            skin:       entry.skin.clone(),
            active:     entry.metrics.active.load(Ordering::Relaxed),
            total:      entry.metrics.total.load(Ordering::Relaxed),
            bytes_in:   entry.metrics.bytes_in.load(Ordering::Relaxed),
            bytes_out:  entry.metrics.bytes_out.load(Ordering::Relaxed),
        }
    }

    fn with_db<F, T>(state: &AppState, f: F) -> Result<T, String>
    where F: FnOnce(&AppDb) -> Result<T, String>
    {
        let guard = state.db.lock().unwrap();
        let db = guard.as_ref().ok_or_else(|| "relay DB not initialised".to_owned())?;
        f(db)
    }

    fn detect_lan_ip() -> String {
        use std::net::UdpSocket;
        if let Ok(s) = UdpSocket::bind("0.0.0.0:0") {
            if s.connect("8.8.8.8:80").is_ok() {
                if let Ok(addr) = s.local_addr() {
                    return addr.ip().to_string();
                }
            }
        }
        "127.0.0.1".to_owned()
    }

    // ─── Identity ─────────────────────────────────────────────────────

    #[tauri::command]
    pub fn keygen(state: tauri::State<AppState>) -> Result<NodeInfo, String> {
        let (sig_pub, sig_seed) = ed25519_generate();
        let (enc_pub, enc_priv) = x25519_generate();
        let node = LocalNode {
            sig: Keypair { pub_key: base64url::encode(&sig_pub),  priv_key: base64url::encode(&sig_seed) },
            enc: Keypair { pub_key: base64url::encode(&enc_pub),  priv_key: base64url::encode(&enc_priv) },
        };
        let info = node_info(&node)?;
        *state.node.lock().unwrap() = Some(node);
        Ok(info)
    }

    #[tauri::command]
    pub fn load_node(node_json: String, state: tauri::State<AppState>) -> Result<NodeInfo, String> {
        let node: LocalNode = serde_json::from_str(&node_json).map_err(to_err)?;
        let info = node_info(&node)?;
        *state.node.lock().unwrap() = Some(node);
        Ok(info)
    }

    #[tauri::command]
    pub fn get_node(state: tauri::State<AppState>) -> Option<NodeInfo> {
        state.node.lock().unwrap().as_ref().and_then(|n| node_info(n).ok())
    }

    // ─── Room lifecycle ───────────────────────────────────────────────

    #[tauri::command]
    pub fn create_room(
        name:       Option<String>,
        rules_json: Option<String>,
        state:      tauri::State<AppState>,
    ) -> Result<(String, String, String), String> {
        let guard = state.node.lock().unwrap();
        let node  = guard.as_ref().ok_or("No identity loaded")?;

        let (room_pub_bytes, room_seed) = ed25519_generate();
        let room = LocalRoom {
            sig: Keypair {
                pub_key:  base64url::encode(&room_pub_bytes),
                priv_key: base64url::encode(&room_seed),
            },
        };

        let rules: Option<Value> = rules_json.as_deref()
            .map(serde_json::from_str).transpose().map_err(to_err)?;

        let (_authored, committed) =
            make_room_create(node, &room, name.as_deref(), rules).map_err(to_err)?;

        // Persist the room key so local relays can auto-commit events for this room.
        state.rooms.lock().unwrap().insert(room.sig.pub_key.clone(), room.clone());

        let invite_uri    = discovery_encode_uri(&[committed.clone()]).map_err(to_err)?;
        let committed_json = serialize_env(&committed)?;
        Ok((room.sig.pub_key.clone(), committed_json, invite_uri))
    }

    #[tauri::command]
    pub fn join_room(room_pub: String, state: tauri::State<AppState>) -> Result<String, String> {
        let guard = state.node.lock().unwrap();
        let node  = guard.as_ref().ok_or("No identity loaded")?;
        serialize_env(&make_room_join(node, &room_pub, None).map_err(to_err)?)
    }

    // ─── Messaging ────────────────────────────────────────────────────

    #[tauri::command]
    pub fn sign_message(
        room_pub: String,
        channel:  i32,
        body:     String,
        state:    tauri::State<AppState>,
    ) -> Result<String, String> {
        let guard = state.node.lock().unwrap();
        let node  = guard.as_ref().ok_or("No identity loaded")?;
        serialize_env(&make_room_message(node, &room_pub, channel, &body, vec![]).map_err(to_err)?)
    }

    /// Wrap a depth-2 committed envelope in a depth-3 ack signed by the local node.
    /// The ack signals relays to stop active forwarding (terminal envelope, spec §6.2.3).
    #[tauri::command]
    pub fn ack_commit(committed_json: String, state: tauri::State<AppState>) -> Result<String, String> {
        let guard = state.node.lock().unwrap();
        let node  = guard.as_ref().ok_or("No identity loaded")?;
        let commit = parse_env_str(&committed_json)?;
        if depth(&commit) != 2 {
            return Err(format!("ack_commit: expected depth-2, got depth-{}", depth(&commit)));
        }
        serialize_env(&wrap_ack(commit, node).map_err(to_err)?)
    }

    // ─── Network / pool.exchange ──────────────────────────────────────

    /// Collect valid envelopes from a flat JSON array returned by HTTP/TCP transports.
    fn collect_envelopes(values: Vec<Value>) -> Result<Vec<String>, String> {
        let mut results = Vec::new();
        for v in values {
            if v.get("error").is_some() || v.get("done").is_some() { continue; }
            if let Ok(env) = parse_envelope(v) {
                if verify_chain(&env).is_ok() {
                    results.push(serde_json::to_string(&env).map_err(to_err)?);
                }
            }
        }
        Ok(results)
    }

    /// pool.exchange over HTTP (plain or TLS, optionally with x25519-v0.2 skin).
    ///
    /// Skin is specified as query params: `?skin=x25519-v0.2&key=RELAY_ENC_PUB_BASE64URL`.
    /// When present the request body is wrapped in per-request ECDH+AEAD and the
    /// response is decrypted before envelope parsing.
    async fn pool_exchange_http(url: &str, request_json: &str) -> Result<Vec<String>, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use toloo_core::{base64url, crypto};

        // Split off query string before further URL parsing.
        let (base_url, query) = match url.find('?') {
            Some(i) => (&url[..i], Some(&url[i+1..])),
            None    => (url, None),
        };

        // Parse ?skin=...&key=... query params.
        let mut skin_name: Option<&str> = None;
        let mut skin_key:  Option<&str> = None;
        if let Some(q) = query {
            for part in q.split('&') {
                if let Some(v) = part.strip_prefix("skin=") { skin_name = Some(v); }
                if let Some(v) = part.strip_prefix("key=")  { skin_key  = Some(v); }
            }
        }

        // Apply x25519-v0.2 skin: encrypt request, record response keys.
        let (actual_body_str, resp_keys) = if skin_name == Some("x25519-v0.2") {
            let relay_enc_pub_b64 = skin_key.ok_or("skin=x25519-v0.2 but no key= param")?;
            let relay_enc_pub = base64url::decode(relay_enc_pub_b64).map_err(to_err)?;
            let (eph_pub_bytes, eph_priv_bytes) = crypto::x25519_generate();
            let shared = crypto::x25519_shared_secret(&eph_priv_bytes, &relay_enc_pub).map_err(to_err)?;

            let mut salt_data = Vec::with_capacity(eph_pub_bytes.len() + relay_enc_pub.len());
            salt_data.extend_from_slice(&eph_pub_bytes);
            salt_data.extend_from_slice(&relay_enc_pub);
            let salt = crypto::sha256(&salt_data);

            let okm_req = crypto::hkdf_sha256(&shared, &salt, b"toloo-http-req-v0.2", 44);
            let mut key_req   = [0u8; 32];
            let mut nonce_req = [0u8; 12];
            key_req.copy_from_slice(&okm_req[0..32]);
            nonce_req.copy_from_slice(&okm_req[32..44]);
            let ciphertext = crypto::chacha20_encrypt(&key_req, &nonce_req, request_json.as_bytes());

            let skin_body = serde_json::json!({
                "eph": base64url::encode(&eph_pub_bytes),
                "enc": base64url::encode(&ciphertext),
            }).to_string();

            let okm_resp = crypto::hkdf_sha256(&shared, &salt, b"toloo-http-resp-v0.2", 44);
            let mut key_resp   = [0u8; 32];
            let mut nonce_resp = [0u8; 12];
            key_resp.copy_from_slice(&okm_resp[0..32]);
            nonce_resp.copy_from_slice(&okm_resp[32..44]);

            (skin_body, Some((key_resp, nonce_resp)))
        } else {
            (request_json.to_owned(), None)
        };

        // Parse http[s]://host[:port][/path] (using base_url, query stripped).
        let is_https = base_url.starts_with("https://");
        let without_scheme = base_url.strip_prefix("https://")
            .or_else(|| base_url.strip_prefix("http://"))
            .ok_or("invalid HTTP(S) URL")?;

        let (host_port, path) = match without_scheme.find('/') {
            Some(i) => (&without_scheme[..i], &without_scheme[i..]),
            None    => (without_scheme, "/"),
        };
        let default_port = if is_https { 443u16 } else { 80 };
        let (host, port) = match host_port.rfind(':') {
            Some(i) => (&host_port[..i], host_port[i+1..].parse::<u16>().map_err(to_err)?),
            None    => (host_port, default_port),
        };

        let body   = actual_body_str.as_bytes();
        let req_headers = format!(
            "POST {} HTTP/1.1\r\nHost: {host_port}\r\n\
             Content-Type: application/json\r\nContent-Length: {}\r\n\
             Connection: close\r\n\r\n",
            path, body.len()
        );

        let stream = tokio::net::TcpStream::connect(format!("{host}:{port}"))
            .await.map_err(to_err)?;

        // Branch for TLS vs plain.
        let resp_body: Vec<u8> = if is_https {
            use tokio_rustls::rustls;
            use tokio_rustls::TlsConnector;
            use std::sync::Arc;

            // Accept self-signed certs: provide a verifier that passes everything.
            #[derive(Debug)]
            struct AcceptAny;
            impl rustls::client::danger::ServerCertVerifier for AcceptAny {
                fn verify_server_cert(
                    &self, _end_entity: &rustls::pki_types::CertificateDer<'_>,
                    _intermediates: &[rustls::pki_types::CertificateDer<'_>],
                    _server_name: &rustls::pki_types::ServerName<'_>,
                    _ocsp_response: &[u8],
                    _now: rustls::pki_types::UnixTime,
                ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
                    Ok(rustls::client::danger::ServerCertVerified::assertion())
                }
                fn verify_tls12_signature(&self, _msg: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
                }
                fn verify_tls13_signature(&self, _msg: &[u8], _cert: &rustls::pki_types::CertificateDer<'_>, _dss: &rustls::DigitallySignedStruct) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
                    Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
                }
                fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
                    rustls::crypto::ring::default_provider().signature_verification_algorithms.supported_schemes()
                }
            }

            let tls_cfg = rustls::ClientConfig::builder_with_provider(
                Arc::new(rustls::crypto::ring::default_provider())
            )
            .with_safe_default_protocol_versions().map_err(to_err)?
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(AcceptAny))
            .with_no_client_auth();

            let connector  = TlsConnector::from(Arc::new(tls_cfg));
            let server_name = rustls::pki_types::ServerName::try_from(host.to_owned())
                .map_err(to_err)?;
            let mut tls = connector.connect(server_name, stream).await.map_err(to_err)?;
            tls.write_all(req_headers.as_bytes()).await.map_err(to_err)?;
            tls.write_all(body).await.map_err(to_err)?;
            tls.flush().await.map_err(to_err)?;
            read_http_response_body(&mut tls).await?
        } else {
            let mut plain = stream;
            plain.write_all(req_headers.as_bytes()).await.map_err(to_err)?;
            plain.write_all(body).await.map_err(to_err)?;
            plain.flush().await.map_err(to_err)?;
            read_http_response_body(&mut plain).await?
        };

        // Decrypt response if skin was applied.
        let plaintext = if let Some((key_resp, nonce_resp)) = resp_keys {
            let envelope: Value = serde_json::from_slice(&resp_body).map_err(to_err)?;
            let enc_b64 = envelope["enc"].as_str()
                .ok_or("skin response missing 'enc' field")?;
            let ciphertext = base64url::decode(enc_b64).map_err(to_err)?;
            crypto::chacha20_decrypt(&key_resp, &nonce_resp, &ciphertext)
                .map_err(to_err)?
        } else {
            resp_body
        };

        let values: Vec<Value> = serde_json::from_slice(&plaintext).map_err(to_err)?;
        collect_envelopes(values)
    }

    /// Read an HTTP/1.1 response, return the body bytes.
    async fn read_http_response_body<S>(stream: &mut S) -> Result<Vec<u8>, String>
    where S: tokio::io::AsyncRead + Unpin
    {
        use tokio::io::AsyncReadExt;
        let mut header_buf: Vec<u8> = Vec::with_capacity(2048);
        loop {
            let mut byte = [0u8; 1];
            match stream.read(&mut byte).await {
                Ok(0) | Err(_) => break,
                Ok(_) => header_buf.push(byte[0]),
            }
            if header_buf.ends_with(b"\r\n\r\n") { break; }
            if header_buf.len() > 16 * 1024 { return Err("HTTP response headers too large".to_owned()); }
        }
        let header_str = std::str::from_utf8(&header_buf).map_err(to_err)?;
        let mut content_length: Option<usize> = None;
        for line in header_str.split("\r\n").skip(1) {
            if let Some(rest) = line.to_ascii_lowercase().strip_prefix("content-length:") {
                content_length = rest.trim().parse().ok();
            }
        }
        if let Some(len) = content_length {
            let mut buf = vec![0u8; len];
            stream.read_exact(&mut buf).await.map_err(to_err)?;
            Ok(buf)
        } else {
            let mut buf = Vec::new();
            stream.read_to_end(&mut buf).await.map_err(to_err)?;
            Ok(buf)
        }
    }

    /// pool.exchange over plain TCP (4-byte BE length-prefixed frames).
    /// Sends one request frame, then half-closes to signal done, reads until EOF.
    async fn pool_exchange_tcp(url: &str, request_json: &str) -> Result<Vec<String>, String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let host_port = url.strip_prefix("tcp://").ok_or("invalid TCP URL")?;
        let mut stream = tokio::net::TcpStream::connect(host_port).await.map_err(to_err)?;

        let body   = request_json.as_bytes();
        let prefix = (body.len() as u32).to_be_bytes();
        stream.write_all(&prefix).await.map_err(to_err)?;
        stream.write_all(body).await.map_err(to_err)?;
        stream.flush().await.map_err(to_err)?;
        // Half-close the write side: the server sees EOF on its next read and
        // closes the connection after flushing all its response frames.
        stream.shutdown().await.map_err(to_err)?;

        let mut results = Vec::new();
        loop {
            let mut len_buf = [0u8; 4];
            match stream.read_exact(&mut len_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e.to_string()),
            }
            let len = u32::from_be_bytes(len_buf) as usize;
            if len > 1 << 20 { return Err(format!("TCP frame too large: {len}")); }
            let mut payload = vec![0u8; len];
            stream.read_exact(&mut payload).await.map_err(to_err)?;

            if let Ok(text) = std::str::from_utf8(&payload) {
                if let Ok(v) = serde_json::from_str::<Value>(text) {
                    if v.get("error").is_some() || v.get("done").is_some() { continue; }
                    if let Ok(env) = parse_envelope(v) {
                        if verify_chain(&env).is_ok() {
                            results.push(serde_json::to_string(&env).map_err(to_err)?);
                        }
                    }
                }
            }
        }
        Ok(results)
    }

    #[tauri::command]
    pub async fn pool_exchange(
        relay_url:  String,
        offer:      Vec<String>,
        want_rooms: Vec<String>,
        after:      u64,
        state:      tauri::State<'_, AppState>,
    ) -> Result<Vec<String>, String> {
        let node: LocalNode = {
            let guard = state.node.lock().unwrap();
            guard.clone().unwrap_or_else(throwaway_node)
        };

        let offer_items: Vec<Value> = offer
            .iter()
            .filter_map(|j| serde_json::from_str(j).ok())
            .collect();

        let request = make_envelope(
            "pool.exchange",
            Some(serde_json::json!({
                "offer": offer_items,
                "want": { "rooms": want_rooms, "after": after, "limit": 200 }
            })),
            &node, None,
        ).map_err(to_err)?;

        let request_json = serde_json::to_string(&request).map_err(to_err)?;

        // Route by URL scheme.
        if relay_url.starts_with("http://") || relay_url.starts_with("https://") {
            return pool_exchange_http(&relay_url, &request_json).await;
        }
        if relay_url.starts_with("tcp://") {
            return pool_exchange_tcp(&relay_url, &request_json).await;
        }

        // ws:// or wss:// — WebSocket path.
        let (mut ws, _) = connect_async(&relay_url).await.map_err(to_err)?;
        ws.send(Message::Text(request_json.into())).await.map_err(to_err)?;

        let mut results = Vec::new();
        while let Some(msg) = ws.next().await {
            let text = match msg.map_err(to_err)? {
                Message::Text(t)  => t.to_string(),
                Message::Close(_) => break,
                Message::Ping(p)  => { ws.send(Message::Pong(p)).await.ok(); continue; }
                _ => continue,
            };
            if let Ok(v) = serde_json::from_str::<Value>(&text) {
                if v.get("done").is_some()  { break; }
                if v.get("error").is_some() { continue; }
                if let Ok(env) = parse_envelope(v) {
                    if verify_chain(&env).is_ok() {
                        results.push(serde_json::to_string(&env).map_err(to_err)?);
                    }
                }
            }
        }
        let _ = ws.close(None).await;
        Ok(results)
    }

    #[tauri::command]
    pub async fn fetch_messages(
        relay_url: String,
        room_pub:  String,
        after:     u64,
        state:     tauri::State<'_, AppState>,
    ) -> Result<Vec<MessageItem>, String> {
        let envelopes = pool_exchange(relay_url, vec![], vec![room_pub], after, state).await?;
        Ok(envelopes.iter().filter_map(|j| {
            let env = parse_envelope(serde_json::from_str(j).ok()?).ok()?;
            message_item(&env)
        }).collect())
    }

    // ─── Relay config DB commands ─────────────────────────────────────

    /// Save a new relay config to the database (initially inactive).
    /// The `id` field must be a unique string generated by the frontend (e.g. UUID).
    #[tauri::command]
    pub fn relay_save_config(
        id:      String,
        proto:   String,
        host:    String,
        port:    u16,
        skin:    Option<String>,
        padding: Option<String>,
        path:    Option<String>,
        direct:  bool,
        state:   tauri::State<AppState>,
    ) -> Result<RelayConfigRecord, String> {
        let record = RelayConfigRecord { id, proto, host, port, skin, padding, path, direct, active: false };
        with_db(&state, |db| db.save(&record))?;
        Ok(record)
    }

    /// Delete a saved relay config. Stops it first if it is currently running.
    #[tauri::command]
    pub fn relay_delete_config(id: String, state: tauri::State<AppState>) -> Result<(), String> {
        // Stop if running.
        {
            let mut relays = state.relays.lock().unwrap();
            if let Some(pos) = relays.iter().position(|r| r.config_id == id) {
                let entry = relays.remove(pos);
                let _ = entry.stop_tx.send(());
            }
        }
        with_db(&state, |db| db.delete(&id))
    }

    /// Return all saved relay configs from the database.
    #[tauri::command]
    pub fn relay_list_configs(state: tauri::State<AppState>) -> Result<Vec<RelayConfigRecord>, String> {
        with_db(&state, |db| db.list())
    }

    // ─── Relay runtime commands ───────────────────────────────────────

    /// Start a saved relay by its config ID.
    /// Loads the config from the DB, starts the relay thread, marks the config as active.
    #[tauri::command]
    pub fn relay_start(config_id: String, state: tauri::State<AppState>) -> Result<RelayInfo, String> {
        let cfg = with_db(&state, |db| {
            db.list()?.into_iter()
                .find(|r| r.id == config_id)
                .ok_or_else(|| format!("relay config {config_id} not found"))
        })?;

        // Probe port availability.
        std::net::TcpListener::bind(format!("0.0.0.0:{}", cfg.port))
            .map_err(|e| format!("port {} unavailable: {e}", cfg.port))?;

        // Generate a fresh relay keypair each time it starts.
        let (sig_pub_bytes, sig_seed_bytes) = ed25519_generate();
        let (enc_pub_bytes, enc_priv_bytes)  = x25519_generate();
        let relay_node = LocalNode {
            sig: Keypair { pub_key: base64url::encode(&sig_pub_bytes), priv_key: base64url::encode(&sig_seed_bytes) },
            enc: Keypair { pub_key: base64url::encode(&enc_pub_bytes), priv_key: base64url::encode(&enc_priv_bytes) },
        };

        // For TLS protos (wss, https) generate a fresh self-signed cert.
        let needs_tls = cfg.proto == "wss" || cfg.proto == "https";
        let (tls_acceptor, cert_fp) = if needs_tls {
            match make_self_signed_acceptor(&cfg.host) {
                Ok((acc, _cert_der, fp)) => (Some(std::sync::Arc::new(acc)), Some(fp)),
                Err(e) => return Err(format!("TLS setup failed: {e}")),
            }
        } else {
            (None, None)
        };

        // Build endpoint descriptor for the invite URI.
        let mut extra: std::collections::HashMap<String, serde_json::Value> = Default::default();
        if let Some(fp) = cert_fp {
            extra.insert("cert_fp".to_owned(), serde_json::json!(fp));
        }
        let endpoint_desc = EndpointDescriptor {
            proto:   cfg.proto.clone(),
            host:    Some(cfg.host.clone()),
            port:    Some(cfg.port),
            path:    cfg.path.clone(),
            skin:    cfg.skin.clone(),
            key:     if cfg.skin.is_some() { Some(relay_node.enc.pub_key.clone()) } else { None },
            padding: cfg.padding.clone(),
            direct:  Some(cfg.direct),
            extra,
        };
        let node_meta  = make_node_meta(&relay_node, vec![endpoint_desc]).map_err(to_err)?;
        let invite_uri = discovery_encode_uri(&[node_meta]).map_err(to_err)?;

        let bind_addr: SocketAddr = format!("0.0.0.0:{}", cfg.port).parse().map_err(to_err)?;
        let transport_ep = EndpointConfig {
            addr:  bind_addr,
            proto: cfg.proto.clone(),
            skin:  cfg.skin.clone(),
            path:  cfg.path.clone(),
            tls:   tls_acceptor,
        };

        // Snapshot room keys the node currently holds — relay uses these to auto-commit.
        let rooms_snapshot: HashMap<String, LocalRoom> = state.rooms.lock().unwrap().clone();

        let (stop_tx, stop_rx) = tokio::sync::oneshot::channel::<()>();
        let metrics        = Arc::new(RelayMetrics::new());
        let metrics_thread = Arc::clone(&metrics);

        std::thread::spawn(move || {
            let rt = tokio::runtime::Builder::new_current_thread()
                .enable_all().build().expect("relay runtime");
            rt.block_on(async move {
                let pool = match Pool::memory() {
                    Ok(p)  => Arc::new(p),
                    Err(e) => { eprintln!("[toloo-app] relay pool init failed: {e}"); return; }
                };
                let config = Arc::new(RelayConfig {
                    node:      relay_node,
                    endpoints: vec![transport_ep],
                    pool,
                    rooms:     rooms_snapshot,
                    metrics:   Some(metrics_thread),
                });
                tokio::select! {
                    res = run_relay(config) => {
                        if let Err(e) = res { eprintln!("[toloo-app] relay error: {e}"); }
                    }
                    _ = stop_rx => {}
                }
            });
        });

        let runtime_id = {
            let mut next = state.relay_id_next.lock().unwrap();
            let id = *next; *next += 1; id
        };

        let entry = LocalRelayEntry {
            runtime_id,
            config_id: cfg.id.clone(),
            stop_tx,
            invite_uri,
            proto: cfg.proto.clone(),
            host:  cfg.host.clone(),
            port:  cfg.port,
            skin:  cfg.skin.clone(),
            metrics,
        };
        let info = relay_info(&entry);
        state.relays.lock().unwrap().push(entry);

        // Mark as active in DB.
        let _ = with_db(&state, |db| db.set_active(&cfg.id, true));

        Ok(info)
    }

    /// Stop a running relay by its runtime_id. Marks the config as inactive in the DB.
    #[tauri::command]
    pub fn relay_stop(runtime_id: u32, state: tauri::State<AppState>) -> Result<(), String> {
        let config_id = {
            let mut relays = state.relays.lock().unwrap();
            if let Some(pos) = relays.iter().position(|r| r.runtime_id == runtime_id) {
                let entry = relays.remove(pos);
                let id = entry.config_id.clone();
                let _ = entry.stop_tx.send(());
                Some(id)
            } else { None }
        };
        if let Some(id) = config_id {
            let _ = with_db(&state, |db| db.set_active(&id, false));
        }
        Ok(())
    }

    /// Return all running relays with live metrics.
    #[tauri::command]
    pub fn relay_list(state: tauri::State<AppState>) -> Vec<RelayInfo> {
        state.relays.lock().unwrap().iter().map(relay_info).collect()
    }

    /// Return the detected LAN IP (for pre-filling the relay host field in the UI).
    #[tauri::command]
    pub fn detect_lan_ip_cmd() -> String {
        detect_lan_ip()
    }

    // ─── Envelope utilities ───────────────────────────────────────────

    #[tauri::command]
    pub fn verify_envelope(envelope_json: String) -> Result<bool, String> {
        verify_chain(&parse_env_str(&envelope_json)?).map(|_| true).map_err(to_err)
    }

    #[tauri::command]
    pub fn envelope_eid(envelope_json: String) -> Result<String, String> {
        Ok(eid(&parse_env_str(&envelope_json)?))
    }

    // ─── Discovery ────────────────────────────────────────────────────

    #[tauri::command]
    pub fn encode_uri(envelope_jsons: Vec<String>) -> Result<String, String> {
        let envs: Result<Vec<Envelope>, String> =
            envelope_jsons.iter().map(|j| parse_env_str(j)).collect();
        discovery_encode_uri(&envs?).map_err(to_err)
    }

    #[tauri::command]
    pub fn encode_file(envelope_jsons: Vec<String>) -> Result<String, String> {
        let envs: Result<Vec<Envelope>, String> =
            envelope_jsons.iter().map(|j| parse_env_str(j)).collect();
        discovery_encode_file(&envs?).map_err(to_err)
    }

    #[tauri::command]
    pub fn decode(input: String) -> Result<Vec<String>, String> {
        discovery_decode(&input).map_err(to_err)?
            .iter().map(serialize_env).collect()
    }

    #[tauri::command]
    pub fn decode_invite(input: String) -> Result<InviteInfo, String> {
        let envelopes = discovery_decode(&input).map_err(to_err)?;

        let room_env = envelopes.iter().find(|e| {
            let t = &e.d.t;
            t == "commit" || innermost(e).d.t == "room.create"
        }).ok_or("no room.create envelope found in invite")?;

        let room_pub = if room_env.d.t == "commit" {
            room_env.d.n.clone()
        } else {
            room_env.d.r.clone().ok_or("room.create missing r field")?
        };

        let inner     = innermost(room_env);
        let creator   = inner.d.n.clone();
        let room_name = inner.d.c.as_ref()
            .and_then(|c| c.get("name"))
            .and_then(|v| v.as_str())
            .map(str::to_owned);

        let invite_uri     = discovery_encode_uri(&envelopes).map_err(to_err)?;
        let envelope_jsons = envelopes.iter().map(serde_json::to_string)
            .collect::<Result<Vec<_>, _>>().map_err(to_err)?;

        Ok(InviteInfo { room_pub, room_name, creator, invite_uri, envelope_jsons })
    }

    // ─── Encrypted identity ───────────────────────────────────────────

    #[tauri::command]
    pub fn encrypt_identity(passphrase: String, state: tauri::State<AppState>) -> Result<String, String> {
        let guard = state.node.lock().unwrap();
        let node = guard.as_ref().ok_or("No identity loaded")?;
        let node_json = serde_json::to_string(node).map_err(to_err)?;
        let encrypted = keystore::encrypt_key(node_json.as_bytes(), &passphrase).map_err(to_err)?;
        Ok(encrypted.blob)
    }

    #[tauri::command]
    pub fn load_encrypted_identity(
        encrypted_blob: String,
        passphrase:     String,
        state:          tauri::State<AppState>,
    ) -> Result<NodeInfo, String> {
        let encrypted = keystore::EncryptedKey { blob: encrypted_blob };
        let decrypted = keystore::decrypt_key(&encrypted, &passphrase).map_err(to_err)?;
        let node_json = std::str::from_utf8(&decrypted).map_err(to_err)?;
        let node: LocalNode = serde_json::from_str(node_json).map_err(to_err)?;
        let info = node_info(&node)?;
        *state.node.lock().unwrap() = Some(node);
        Ok(info)
    }

    // ─── Attestations ─────────────────────────────────────────────────

    #[tauri::command]
    pub fn create_attestation(
        target_node: String,
        level:       String,
        reason:      Option<String>,
        state:       tauri::State<AppState>,
    ) -> Result<String, String> {
        let guard = state.node.lock().unwrap();
        let node = guard.as_ref().ok_or("No identity loaded")?;
        let env = make_side_attestation(node, &target_node, &level, reason.as_deref()).map_err(to_err)?;
        serialize_env(&env)
    }

    // ─── Flags ────────────────────────────────────────────────────────

    #[tauri::command]
    pub fn create_flag(
        room_pub:   String,
        target_eid: String,
        category:   String,
        reason:     Option<String>,
        state:      tauri::State<AppState>,
    ) -> Result<String, String> {
        let guard = state.node.lock().unwrap();
        let node = guard.as_ref().ok_or("No identity loaded")?;
        let env = make_room_flag(node, &room_pub, &target_eid, &category, reason.as_deref()).map_err(to_err)?;
        serialize_env(&env)
    }

    // ─── Local moderation (blocklist) ─────────────────────────────────

    #[tauri::command]
    pub fn block_node_cmd(
        node_pub: String,
        reason:   Option<String>,
        state:    tauri::State<AppState>,
    ) -> Result<(), String> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(to_err)?
            .as_millis() as u64;
        with_db(&state, |db| db.block_node(&node_pub, "block", reason.as_deref(), now))
    }

    #[tauri::command]
    pub fn unblock_node_cmd(node_pub: String, state: tauri::State<AppState>) -> Result<(), String> {
        with_db(&state, |db| db.unblock_node(&node_pub).map(|_| ()))
    }

    #[tauri::command]
    pub fn get_blocklist_cmd(state: tauri::State<AppState>) -> Result<Vec<BlocklistItem>, String> {
        with_db(&state, |db| {
            db.get_blocklist().map(|rows| rows.into_iter().map(|(node_pub, kind, reason, blocked_at)| {
                BlocklistItem { node_pub, kind, reason, blocked_at }
            }).collect())
        })
    }

    #[tauri::command]
    pub fn is_blocked_cmd(node_pub: String, state: tauri::State<AppState>) -> Result<bool, String> {
        with_db(&state, |db| db.is_blocked(&node_pub))
    }
}

// ══════════════════════════════════════════════════════════════════════
// Entry point
// ══════════════════════════════════════════════════════════════════════

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .manage(AppState {
            node:          Mutex::new(None),
            rooms:         Mutex::new(HashMap::new()),
            relays:        Mutex::new(Vec::new()),
            relay_id_next: Mutex::new(0),
            db:            Mutex::new(None),
        })
        .setup(|app| {
            use tauri::Manager;
            let data_dir = app.path().app_data_dir()?;
            match AppDb::open(&data_dir.join("toloo-relays.db")) {
                Ok(db) => {
                    let state: tauri::State<AppState> = app.state();
                    *state.db.lock().unwrap() = Some(db);
                }
                Err(e) => eprintln!("[toloo-app] relay DB init failed: {e}"),
            }
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            commands::keygen,
            commands::load_node,
            commands::get_node,
            commands::create_room,
            commands::join_room,
            commands::sign_message,
            commands::ack_commit,
            commands::pool_exchange,
            commands::fetch_messages,
            commands::verify_envelope,
            commands::envelope_eid,
            commands::encode_uri,
            commands::encode_file,
            commands::decode,
            commands::decode_invite,
            commands::relay_save_config,
            commands::relay_delete_config,
            commands::relay_list_configs,
            commands::relay_start,
            commands::relay_stop,
            commands::relay_list,
            commands::detect_lan_ip_cmd,
            commands::encrypt_identity,
            commands::load_encrypted_identity,
            commands::create_attestation,
            commands::create_flag,
            commands::block_node_cmd,
            commands::unblock_node_cmd,
            commands::get_blocklist_cmd,
            commands::is_blocked_cmd,
        ])
        .run(tauri::generate_context!())
        .expect("error while running toloo app");
}
