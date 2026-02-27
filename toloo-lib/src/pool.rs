use std::collections::HashSet;

use std::io;

use anyhow::{anyhow, Context, Result};
use rusqlite::{params, Connection, OptionalExtension};

use toloo_core::canonical::canonical;
use toloo_core::envelope::{depth, innermost};
use toloo_core::ids::{channel_of, datum_id};
use toloo_core::rules::RuleSet;
use toloo_core::types::Envelope;

pub struct Pool {
    conn: Connection,
}

#[derive(Debug, Clone)]
pub struct PoolEntry {
    pub id: String,
    pub env: Envelope,
    pub room: Option<String>,
    pub n: String,
    pub to_node: Option<String>,
    pub ts: u64,
    pub tc: Option<u64>,
    pub event_type: String,
    pub channel: Option<i32>,
}

#[derive(Debug, Clone, Default)]
pub struct MembershipState {
    pub members: HashSet<String>,
    pub banned: HashSet<String>,
}

/// Result of a TOFU pin check (§4.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TofuResult {
    /// First time seeing this node — pin recorded.
    NewPin,
    /// Seen before and fingerprint matches.
    Match,
    /// Seen before but fingerprint changed — potential impersonation.
    Mismatch {
        expected: String,
        first_seen_at: u64,
    },
}

impl Pool {
    pub fn open(path: &str) -> Result<Self> {
        let conn = Connection::open(path)?;
        init_schema(&conn)?;
        Ok(Self { conn })
    }

    pub fn memory() -> Result<Self> {
        let conn = Connection::open_in_memory()?;
        init_schema(&conn)?;
        Ok(Self { conn })
    }

    /// Store envelope and return outermost datum_id. Duplicates are ignored.
    pub fn put(&self, env: &Envelope) -> Result<String> {
        let id = datum_id(env);
        let inner = innermost(env);
        let room = inner.d.r.clone();
        let author = inner.d.n.clone();
        let to_node = inner.d.to.clone();
        let ts = inner.d.ts as i64;
        let tc = env.d.tc.map(|v| v as i64);
        let event_type = inner.d.t.clone();
        let channel = channel_of(&inner.d).map(i64::from);
        let json = canonical(env)?;

        // Committed envelopes (depth 2) supersede uncommitted versions of same eid.
        // Private messages are intentionally excluded (room = None): the recipient's
        // depth-2 ack is a separate piece of information from the depth-1 original,
        // not a replacement. Both are retained so callers can see sent + acknowledged states.
        if tc.is_some() {
            if let Some(r) = room.as_deref() {
                self.conn.execute(
                    "DELETE FROM envelopes
                     WHERE room = ?1 AND n = ?2 AND ts = ?3 AND channel = ?4 AND tc IS NULL",
                    params![r, author, ts, channel],
                )?;
            }
        }

        // Acknowledged envelopes (depth 3) supersede committed versions of same eid.
        if depth(env) >= 3 {
            if let Some(r) = room.as_deref() {
                self.conn.execute(
                    "DELETE FROM envelopes
                     WHERE room = ?1 AND n = ?2 AND ts = ?3 AND channel = ?4 AND tc IS NOT NULL",
                    params![r, author, ts, channel],
                )?;
            }
        }

        let insert = self.conn.execute(
            "INSERT INTO envelopes
             (id, json, room, n, to_node, ts, tc, event_type, channel)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                id.clone(),
                json,
                room,
                author,
                to_node,
                ts,
                tc,
                event_type,
                channel
            ],
        );
        if let Err(err) = insert {
            if self.get(&id)?.is_none() {
                return Err(err.into());
            }
        }

        Ok(id)
    }

    pub fn get(&self, id: &str) -> Result<Option<Envelope>> {
        let json: Option<String> = self
            .conn
            .query_row(
                "SELECT json FROM envelopes WHERE id = ?1",
                params![id],
                |row| row.get(0),
            )
            .optional()?;

        json.map(|raw| serde_json::from_str(&raw).context("invalid stored envelope JSON"))
            .transpose()
    }

    pub fn get_room_channel(&self, room: &str, channel: i32) -> Result<Vec<PoolEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, json, room, n, to_node, ts, tc, event_type, channel
             FROM envelopes
             WHERE room = ?1 AND channel = ?2
             ORDER BY CASE WHEN tc IS NULL THEN 1 ELSE 0 END ASC, tc ASC, ts ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![room, channel], row_to_entry)?;
        collect_rows(rows)
    }

    /// Returns the latest commit timestamp (tc) for committed events in a room.
    /// For incremental sync, callers pass this value as `after` to fetch only
    /// newer commits.
    pub fn latest_tc(&self, room: &str) -> Result<u64> {
        let tc: Option<i64> = self
            .conn
            .query_row(
                "SELECT MAX(tc) FROM envelopes WHERE room = ?1 AND tc IS NOT NULL",
                params![room],
                |row| row.get(0),
            )
            .optional()?
            .flatten();

        match tc {
            Some(v) => to_u64(v),
            None => Ok(0),
        }
    }

    pub fn get_room_ids(&self, room: &str) -> Result<Vec<String>> {
        let mut stmt = self
            .conn
            .prepare("SELECT id FROM envelopes WHERE room = ?1 ORDER BY ts ASC, id ASC")?;
        let rows = stmt.query_map(params![room], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    pub fn get_private(&self, node_pub: &str) -> Result<Vec<PoolEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, json, room, n, to_node, ts, tc, event_type, channel
             FROM envelopes
             WHERE event_type IN ('private.message', 'private.read', 'private.blob')
               AND (n = ?1 OR to_node = ?1)
             ORDER BY CASE WHEN tc IS NULL THEN 1 ELSE 0 END ASC, tc ASC, ts ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![node_pub], row_to_entry)?;
        collect_rows(rows)
    }

    pub fn build_membership(&self, room: &str) -> Result<MembershipState> {
        let events = self.get_room_channel(room, -2)?;
        let mut state = MembershipState::default();

        for event in events {
            if event.tc.is_none() {
                continue;
            }
            let d = &innermost(&event.env).d;
            match d.t.as_str() {
                "room.join" => {
                    if !state.banned.contains(&d.n) {
                        state.members.insert(d.n.clone());
                    }
                }
                "room.leave" => {
                    state.members.remove(&d.n);
                }
                "room.ban" => {
                    if let Some(target) = d
                        .c
                        .as_ref()
                        .and_then(|c| c.get("banned"))
                        .and_then(|v| v.as_str())
                    {
                        state.members.remove(target);
                        state.banned.insert(target.to_owned());
                    }
                }
                "room.unban" => {
                    if let Some(target) = d
                        .c
                        .as_ref()
                        .and_then(|c| c.get("unbanned"))
                        .and_then(|v| v.as_str())
                    {
                        state.banned.remove(target);
                    }
                }
                "room.invite" => {}
                _ => {}
            }
        }

        Ok(state)
    }

    pub fn get_uncommitted(&self, room: &str) -> Result<Vec<PoolEntry>> {
        let mut stmt = self.conn.prepare(
            "SELECT id, json, room, n, to_node, ts, tc, event_type, channel
             FROM envelopes
             WHERE room = ?1 AND tc IS NULL
             ORDER BY ts ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![room], row_to_entry)?;
        collect_rows(rows)
    }

    /// Return committed envelopes matching optional room and type filters, after `after_tc`.
    ///
    /// - `rooms`: if empty, all rooms are included.
    /// - `types`: if empty, all event types are included.
    /// - `after_tc`: only events with `tc > after_tc` (use 0 for all).
    /// - `limit`: maximum rows returned.
    pub fn get_wanted(
        &self,
        rooms: &[&str],
        types: &[&str],
        after_tc: u64,
        limit: usize,
    ) -> Result<Vec<PoolEntry>> {
        use rusqlite::types::Value as V;

        let mut sql = "SELECT id, json, room, n, to_node, ts, tc, event_type, channel \
                       FROM envelopes WHERE tc IS NOT NULL AND tc > ?"
            .to_owned();
        let mut params: Vec<V> = vec![V::Integer(after_tc as i64)];

        if !rooms.is_empty() {
            let ph = rooms.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND room IN ({ph})"));
            for r in rooms {
                params.push(V::Text(r.to_string()));
            }
        }
        if !types.is_empty() {
            let ph = types.iter().map(|_| "?").collect::<Vec<_>>().join(",");
            sql.push_str(&format!(" AND event_type IN ({ph})"));
            for t in types {
                params.push(V::Text(t.to_string()));
            }
        }

        sql.push_str(" ORDER BY tc ASC, ts ASC, id ASC LIMIT ?");
        params.push(V::Integer(limit as i64));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), row_to_entry)?;
        collect_rows(rows)
    }

    /// Return committed events for a room+channel in the given tc range.
    pub fn get_room_channel_range(
        &self,
        room: &str,
        channel: i32,
        start_tc: u64,
        end_tc: Option<u64>,
        limit: usize,
    ) -> Result<Vec<PoolEntry>> {
        use rusqlite::types::Value as V;

        let mut sql = "SELECT id, json, room, n, to_node, ts, tc, event_type, channel \
                       FROM envelopes \
                       WHERE room = ? AND channel = ? AND tc IS NOT NULL AND tc >= ?"
            .to_owned();
        let mut params: Vec<V> = vec![
            V::Text(room.to_owned()),
            V::Integer(channel as i64),
            V::Integer(start_tc as i64),
        ];

        if let Some(end) = end_tc {
            sql.push_str(" AND tc <= ?");
            params.push(V::Integer(end as i64));
        }

        sql.push_str(" ORDER BY tc ASC, ts ASC, id ASC LIMIT ?");
        params.push(V::Integer(limit as i64));

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), row_to_entry)?;
        collect_rows(rows)
    }

    /// Fetch envelopes by a list of datum IDs.
    pub fn get_by_datum_ids(&self, ids: &[&str]) -> Result<Vec<PoolEntry>> {
        if ids.is_empty() {
            return Ok(vec![]);
        }
        use rusqlite::types::Value as V;

        let ph = ids.iter().map(|_| "?").collect::<Vec<_>>().join(",");
        let sql = format!(
            "SELECT id, json, room, n, to_node, ts, tc, event_type, channel \
             FROM envelopes WHERE id IN ({ph}) ORDER BY tc ASC, ts ASC, id ASC"
        );
        let params: Vec<V> = ids.iter().map(|id| V::Text(id.to_string())).collect();

        let mut stmt = self.conn.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params), row_to_entry)?;
        collect_rows(rows)
    }

    /// Return per-channel stats (channel, committed_count, latest_tc) for a room.
    /// Only non-negative channels (user content) are included.
    pub fn get_room_channel_stats(&self, room: &str) -> Result<Vec<(i32, u64, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT channel, COUNT(*), MAX(tc) \
             FROM envelopes \
             WHERE room = ?1 AND channel >= 0 AND tc IS NOT NULL \
             GROUP BY channel ORDER BY channel ASC",
        )?;
        let rows = stmt.query_map(params![room], |row| {
            let ch: i32 = row.get(0)?;
            let count: i64 = row.get(1)?;
            let max_tc: i64 = row.get(2)?;
            Ok((ch, count as u64, max_tc as u64))
        })?;
        collect_rows(rows)
    }

    /// Return distinct room public keys where `node_pub` has events.
    pub fn get_node_rooms(&self, node_pub: &str) -> Result<Vec<String>> {
        let mut stmt = self.conn.prepare(
            "SELECT DISTINCT room FROM envelopes \
             WHERE n = ?1 AND room IS NOT NULL ORDER BY room ASC",
        )?;
        let rows = stmt.query_map(params![node_pub], |row| row.get::<_, String>(0))?;
        collect_rows(rows)
    }

    // ── TOFU Pin Storage (§4.4, §11.3.1) ──────────────────────────────

    /// Check (and optionally record) a TOFU pin for a node.
    /// `fingerprint` is the hex-encoded SHA-256 of the node's public key.
    pub fn check_tofu_pin(&self, node_pub: &str, fingerprint: &str, now: u64) -> Result<TofuResult> {
        let existing: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT fingerprint, first_seen_at FROM tofu_pins WHERE node_pub = ?1",
                params![node_pub],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;

        match existing {
            Some((stored_fp, first_seen)) => {
                if stored_fp == fingerprint {
                    Ok(TofuResult::Match)
                } else {
                    Ok(TofuResult::Mismatch {
                        expected: stored_fp,
                        first_seen_at: first_seen as u64,
                    })
                }
            }
            None => {
                self.conn.execute(
                    "INSERT INTO tofu_pins (node_pub, first_seen_at, fingerprint) VALUES (?1, ?2, ?3)",
                    params![node_pub, now as i64, fingerprint],
                )?;
                Ok(TofuResult::NewPin)
            }
        }
    }

    /// Get the stored TOFU pin for a node, if any.
    pub fn get_tofu_pin(&self, node_pub: &str) -> Result<Option<(String, u64)>> {
        let result: Option<(String, i64)> = self
            .conn
            .query_row(
                "SELECT fingerprint, first_seen_at FROM tofu_pins WHERE node_pub = ?1",
                params![node_pub],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()?;
        Ok(result.map(|(fp, ts)| (fp, ts as u64)))
    }

    // ── Blob Piece Storage (§11.7) ─────────────────────────────────────

    /// Store a single blob piece.
    pub fn put_blob_piece(&self, blob_id: &str, piece_index: u32, data: &[u8]) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO blob_pieces (blob_id, piece_index, data) VALUES (?1, ?2, ?3)",
            params![blob_id, piece_index as i64, data],
        )?;
        Ok(())
    }

    /// Fetch a single blob piece.
    pub fn get_blob_piece(&self, blob_id: &str, piece_index: u32) -> Result<Option<Vec<u8>>> {
        self.conn
            .query_row(
                "SELECT data FROM blob_pieces WHERE blob_id = ?1 AND piece_index = ?2",
                params![blob_id, piece_index as i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(Into::into)
    }

    /// Fetch all pieces for a blob, ordered by index. Returns None if any piece is missing.
    pub fn get_blob(&self, blob_id: &str, expected_pieces: u32) -> Result<Option<Vec<Vec<u8>>>> {
        let mut stmt = self.conn.prepare(
            "SELECT piece_index, data FROM blob_pieces WHERE blob_id = ?1 ORDER BY piece_index ASC",
        )?;
        let rows: Vec<(i64, Vec<u8>)> = stmt
            .query_map(params![blob_id], |row| Ok((row.get(0)?, row.get(1)?)))?
            .collect::<rusqlite::Result<Vec<_>>>()?;

        if rows.len() != expected_pieces as usize {
            return Ok(None);
        }
        for (i, (idx, _)) in rows.iter().enumerate() {
            if *idx != i as i64 {
                return Ok(None);
            }
        }
        Ok(Some(rows.into_iter().map(|(_, data)| data).collect()))
    }

    /// Count stored pieces for a blob.
    pub fn blob_piece_count(&self, blob_id: &str) -> Result<u32> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM blob_pieces WHERE blob_id = ?1",
            params![blob_id],
            |row| row.get(0),
        )?;
        Ok(count as u32)
    }

    // ── Local Moderation / Blocklist (§13.3) ───────────────────────────

    /// Block a node. `kind` is "block" or "spam".
    pub fn block_node(&self, node_pub: &str, kind: &str, reason: Option<&str>, now: u64) -> Result<()> {
        self.conn.execute(
            "INSERT OR REPLACE INTO blocklist (node_pub, kind, reason, blocked_at) VALUES (?1, ?2, ?3, ?4)",
            params![node_pub, kind, reason, now as i64],
        )?;
        Ok(())
    }

    /// Unblock a node.
    pub fn unblock_node(&self, node_pub: &str) -> Result<bool> {
        let changed = self.conn.execute(
            "DELETE FROM blocklist WHERE node_pub = ?1",
            params![node_pub],
        )?;
        Ok(changed > 0)
    }

    /// Check if a node is blocked.
    pub fn is_blocked(&self, node_pub: &str) -> Result<bool> {
        let exists: bool = self
            .conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM blocklist WHERE node_pub = ?1)",
                params![node_pub],
                |row| row.get(0),
            )?;
        Ok(exists)
    }

    /// Get all blocked nodes.
    pub fn get_blocklist(&self) -> Result<Vec<(String, String, Option<String>, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT node_pub, kind, reason, blocked_at FROM blocklist ORDER BY blocked_at DESC",
        )?;
        let rows = stmt.query_map([], |row| {
            let ts: i64 = row.get(3)?;
            Ok((row.get(0)?, row.get(1)?, row.get(2)?, ts as u64))
        })?;
        collect_rows(rows)
    }

    // ── Attestation Storage (§8.3–§8.5) ────────────────────────────────

    /// Store an attestation envelope.
    pub fn put_attestation(&self, env: &Envelope) -> Result<String> {
        let id = datum_id(env);
        let inner = innermost(env);
        let attester = inner.d.n.clone();
        let c = inner.d.c.as_ref().ok_or_else(|| anyhow!("attestation missing content"))?;
        let target = c.get("target").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("attestation missing c.target"))?;
        let level = c.get("level").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("attestation missing c.level"))?;
        let ts = inner.d.ts as i64;
        let json = toloo_core::canonical::canonical(env)?;

        self.conn.execute(
            "INSERT OR IGNORE INTO attestations (id, json, attester, target, level, ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, json, attester, target, level, ts],
        )?;
        Ok(id)
    }

    /// Get all attestations about a target node.
    pub fn get_attestations_for(&self, target: &str) -> Result<Vec<Envelope>> {
        let mut stmt = self.conn.prepare(
            "SELECT json FROM attestations WHERE target = ?1 ORDER BY ts ASC",
        )?;
        let rows = stmt.query_map(params![target], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            out.push(serde_json::from_str(&json).context("invalid stored attestation JSON")?);
        }
        Ok(out)
    }

    /// Get attestation counts for a target: (positive, negative, neutral).
    pub fn attestation_counts(&self, target: &str) -> Result<(u64, u64, u64)> {
        let mut pos = 0u64;
        let mut neg = 0u64;
        let mut neu = 0u64;
        let mut stmt = self.conn.prepare(
            "SELECT level, COUNT(*) FROM attestations WHERE target = ?1 GROUP BY level",
        )?;
        let rows = stmt.query_map(params![target], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)?))
        })?;
        for row in rows {
            let (level, count) = row?;
            match level.as_str() {
                "positive" => pos = count as u64,
                "negative" => neg = count as u64,
                "neutral" => neu = count as u64,
                _ => {}
            }
        }
        Ok((pos, neg, neu))
    }

    // ── Room Flag Aggregation (§13.8) ──────────────────────────────────

    /// Store a room.flag event.
    pub fn put_flag(&self, env: &Envelope) -> Result<String> {
        let id = datum_id(env);
        let inner = innermost(env);
        let room = inner.d.r.as_deref()
            .ok_or_else(|| anyhow!("room.flag missing room"))?;
        let c = inner.d.c.as_ref().ok_or_else(|| anyhow!("room.flag missing content"))?;
        let target_eid = c.get("target").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("room.flag missing c.target"))?;
        let category = c.get("category").and_then(|v| v.as_str())
            .ok_or_else(|| anyhow!("room.flag missing c.category"))?;
        let flagger = inner.d.n.clone();
        let ts = inner.d.ts as i64;

        self.conn.execute(
            "INSERT OR IGNORE INTO room_flags (id, room, target_eid, category, flagger, ts) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, room, target_eid, category, flagger, ts],
        )?;
        Ok(id)
    }

    /// Get flag count for a specific event in a room.
    pub fn flag_count(&self, room: &str, target_eid: &str) -> Result<u64> {
        let count: i64 = self.conn.query_row(
            "SELECT COUNT(*) FROM room_flags WHERE room = ?1 AND target_eid = ?2",
            params![room, target_eid],
            |row| row.get(0),
        )?;
        Ok(count as u64)
    }

    /// Get flag counts by category for a specific event.
    pub fn flag_counts_by_category(&self, room: &str, target_eid: &str) -> Result<Vec<(String, u64)>> {
        let mut stmt = self.conn.prepare(
            "SELECT category, COUNT(*) FROM room_flags \
             WHERE room = ?1 AND target_eid = ?2 GROUP BY category ORDER BY category ASC",
        )?;
        let rows = stmt.query_map(params![room, target_eid], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, i64>(1)? as u64))
        })?;
        collect_rows(rows)
    }

    // ── Storage Pruning (§11.5) ────────────────────────────────────────

    /// Prune events older than `retention_days` for a room. Returns count of deleted rows.
    pub fn prune_retention(&self, room: &str, retention_days: u64) -> Result<u64> {
        let cutoff_ms = retention_days * 86_400_000;
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| anyhow!("system clock error"))?
            .as_millis() as u64;
        let threshold = now.saturating_sub(cutoff_ms) as i64;

        let deleted = self.conn.execute(
            "DELETE FROM envelopes WHERE room = ?1 AND ts < ?2",
            params![room, threshold],
        )?;
        Ok(deleted as u64)
    }

    /// Prune uncommitted events older than `ttl_ms`. Returns count of deleted rows.
    pub fn prune_uncommitted(&self, room: &str, ttl_ms: u64) -> Result<u64> {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_err(|_| anyhow!("system clock error"))?
            .as_millis() as u64;
        let threshold = now.saturating_sub(ttl_ms) as i64;

        let deleted = self.conn.execute(
            "DELETE FROM envelopes WHERE room = ?1 AND tc IS NULL AND ts < ?2",
            params![room, threshold],
        )?;
        Ok(deleted as u64)
    }

    /// Run pruning for a room using its rule set. Returns (retention_pruned, uncommitted_pruned).
    pub fn prune_room(&self, room: &str, rules: &RuleSet) -> Result<(u64, u64)> {
        let mut ret_pruned = 0u64;
        let mut unc_pruned = 0u64;

        if let Some(days) = rules.retention_days() {
            if days > 0 {
                ret_pruned = self.prune_retention(room, days)?;
            }
        }
        if let Some(ttl_ms) = rules.uncommitted_ttl_ms() {
            if ttl_ms > 0 {
                unc_pruned = self.prune_uncommitted(room, ttl_ms)?;
            }
        }

        Ok((ret_pruned, unc_pruned))
    }

    // ── Export / Import (§11.10) ────────────────────────────────────────

    /// Export all envelopes for a room as a JSON array string.
    pub fn export_room(&self, room: &str) -> Result<Vec<Envelope>> {
        let mut stmt = self.conn.prepare(
            "SELECT json FROM envelopes WHERE room = ?1 ORDER BY ts ASC, id ASC",
        )?;
        let rows = stmt.query_map(params![room], |row| row.get::<_, String>(0))?;
        let mut out = Vec::new();
        for row in rows {
            let json = row?;
            out.push(serde_json::from_str(&json).context("invalid stored envelope JSON")?);
        }
        Ok(out)
    }

    /// Import envelopes into the pool. Validates signatures before storing.
    /// Returns count of successfully imported envelopes.
    pub fn import_envelopes(&self, envelopes: &[Envelope]) -> Result<u64> {
        let mut count = 0u64;
        for env in envelopes {
            if toloo_core::envelope::verify_chain(env).is_ok() {
                self.put(env)?;
                count += 1;
            }
        }
        Ok(count)
    }

}

fn init_schema(conn: &Connection) -> Result<()> {
    conn.execute_batch(
        r#"
        CREATE TABLE IF NOT EXISTS envelopes (
            id      TEXT PRIMARY KEY,
            json    TEXT NOT NULL,
            room    TEXT,
            n       TEXT NOT NULL,
            to_node TEXT,
            ts      INTEGER NOT NULL,
            tc      INTEGER,
            event_type TEXT NOT NULL,
            channel INTEGER
        );

        CREATE INDEX IF NOT EXISTS idx_room    ON envelopes(room);
        CREATE INDEX IF NOT EXISTS idx_n       ON envelopes(n);
        CREATE INDEX IF NOT EXISTS idx_to_node ON envelopes(to_node);
        CREATE INDEX IF NOT EXISTS idx_room_ch ON envelopes(room, channel, tc);

        -- TOFU pin storage (§4.4, §11.3.1)
        CREATE TABLE IF NOT EXISTS tofu_pins (
            node_pub      TEXT PRIMARY KEY,
            first_seen_at INTEGER NOT NULL,
            fingerprint   TEXT NOT NULL
        );

        -- Blob piece storage (§11.7)
        CREATE TABLE IF NOT EXISTS blob_pieces (
            blob_id     TEXT NOT NULL,
            piece_index INTEGER NOT NULL,
            data        BLOB NOT NULL,
            PRIMARY KEY (blob_id, piece_index)
        );

        -- Local moderation blocklist (§13.3)
        CREATE TABLE IF NOT EXISTS blocklist (
            node_pub   TEXT PRIMARY KEY,
            kind       TEXT NOT NULL DEFAULT 'block',
            reason     TEXT,
            blocked_at INTEGER NOT NULL
        );

        -- Attestation storage (§8.3–§8.5)
        CREATE TABLE IF NOT EXISTS attestations (
            id         TEXT PRIMARY KEY,
            json       TEXT NOT NULL,
            attester   TEXT NOT NULL,
            target     TEXT NOT NULL,
            level      TEXT NOT NULL,
            ts         INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_att_target   ON attestations(target);
        CREATE INDEX IF NOT EXISTS idx_att_attester  ON attestations(attester);

        -- Room flag aggregation (§13.8)
        CREATE TABLE IF NOT EXISTS room_flags (
            id          TEXT PRIMARY KEY,
            room        TEXT NOT NULL,
            target_eid  TEXT NOT NULL,
            category    TEXT NOT NULL,
            flagger     TEXT NOT NULL,
            ts          INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_flags_room   ON room_flags(room);
        CREATE INDEX IF NOT EXISTS idx_flags_target ON room_flags(room, target_eid);
    "#,
    )?;
    Ok(())
}

fn row_to_entry(row: &rusqlite::Row<'_>) -> rusqlite::Result<PoolEntry> {
    let json: String = row.get(1)?;
    let env: Envelope = serde_json::from_str(&json).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(
            1,
            rusqlite::types::Type::Text,
            Box::new(e),
        )
    })?;

    let ts_i64: i64 = row.get(5)?;
    let tc_i64: Option<i64> = row.get(6)?;

    let ts = to_u64_sql(ts_i64, 5)?;
    let tc = tc_i64.map(|v| to_u64_sql(v, 6)).transpose()?;

    Ok(PoolEntry {
        id: row.get(0)?,
        env,
        room: row.get(2)?,
        n: row.get(3)?,
        to_node: row.get(4)?,
        ts,
        tc,
        event_type: row.get(7)?,
        channel: row.get::<_, Option<i32>>(8)?,
    })
}

fn collect_rows<I, T>(rows: I) -> Result<Vec<T>>
where
    I: IntoIterator<Item = rusqlite::Result<T>>,
{
    let mut out = Vec::new();
    for row in rows {
        out.push(row?);
    }
    Ok(out)
}

fn to_u64(v: i64) -> Result<u64> {
    if v < 0 {
        return Err(anyhow!("negative integer cannot convert to u64"));
    }
    Ok(v as u64)
}

fn to_u64_sql(v: i64, idx: usize) -> rusqlite::Result<u64> {
    if v < 0 {
        return Err(rusqlite::Error::FromSqlConversionFailure(
            idx,
            rusqlite::types::Type::Integer,
            Box::new(io::Error::new(
                io::ErrorKind::InvalidData,
                "negative integer cannot convert to u64",
            )),
        ));
    }
    Ok(v as u64)
}

/// Load a `RuleSet` from the latest committed channel -1 envelope in the pool.
/// Returns an empty `RuleSet` if no metadata exists yet.
pub fn ruleset_from_pool(pool: &Pool, room: &str) -> Result<RuleSet> {
    let meta_events = pool.get_room_channel(room, -1)?;
    let latest_committed = meta_events.iter().filter(|e| e.tc.is_some()).last();
    let Some(entry) = latest_committed else {
        return Ok(RuleSet::default());
    };
    let inner = innermost(&entry.env);
    let rules_val = inner.d.c.as_ref().and_then(|c| c.get("rules"));
    match rules_val {
        Some(v) => Ok(RuleSet::from_json(v)),
        None => Ok(RuleSet::default()),
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use toloo_core::base64url;
    use toloo_core::crypto::{ed25519_generate, x25519_generate};
    use toloo_core::envelope::{sign_envelope, wrap_commit};
    use toloo_core::events::{make_room_create, make_room_update};
    use toloo_core::types::{DatumBody, Envelope, Keypair, LocalNode, LocalRoom};

    use super::{ruleset_from_pool, Pool};

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

    fn mk_room_event(
        author: &LocalNode,
        room: &LocalRoom,
        event_type: &str,
        ts: u64,
        content: serde_json::Value,
    ) -> Envelope {
        let d = DatumBody {
            n: author.sig.pub_key.clone(),
            v: "0.2".to_owned(),
            t: event_type.to_owned(),
            ts,
            r: Some(room.sig.pub_key.clone()),
            to: None,
            c: Some(content),
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        sign_envelope(d, &author.sig.priv_key).expect("sign should succeed")
    }

    fn mk_private_message(sender: &LocalNode, recipient_sig: &str, ts: u64) -> Envelope {
        let d = DatumBody {
            n: sender.sig.pub_key.clone(),
            v: "0.2".to_owned(),
            t: "private.message".to_owned(),
            ts,
            r: None,
            to: Some(recipient_sig.to_owned()),
            c: Some(json!({"encrypted": "abc", "eph": sender.enc.pub_key})),
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        sign_envelope(d, &sender.sig.priv_key).expect("sign should succeed")
    }

    #[test]
    fn put_get_and_deduplicate_by_datum_id() {
        let pool = Pool::memory().expect("pool should initialize");
        let node = mk_node();
        let room = mk_room();
        let env = mk_room_event(&node, &room, "room.message", 100, json!({"ch": 0, "body": "x"}));

        let id1 = pool.put(&env).expect("put should succeed");
        let id2 = pool.put(&env).expect("duplicate put should succeed");
        assert_eq!(id1, id2);

        let got = pool.get(&id1).expect("get should succeed").expect("must exist");
        assert_eq!(got.p, env.p);

        let entries = pool
            .get_room_channel(&room.sig.pub_key, 0)
            .expect("query should succeed");
        assert_eq!(entries.len(), 1);
    }

    #[test]
    fn committed_event_replaces_uncommitted_with_same_eid() {
        let pool = Pool::memory().expect("pool should initialize");
        let author = mk_node();
        let room = mk_room();
        let inner =
            mk_room_event(&author, &room, "room.message", 101, json!({"ch": 2, "body": "hello"}));

        pool.put(&inner).expect("put depth1");
        assert_eq!(
            pool.get_uncommitted(&room.sig.pub_key)
                .expect("query")
                .len(),
            1
        );

        let commit = wrap_commit(inner, &room, 200).expect("commit should wrap");
        pool.put(&commit).expect("put depth2");

        let channel_entries = pool
            .get_room_channel(&room.sig.pub_key, 2)
            .expect("query should succeed");
        assert_eq!(channel_entries.len(), 1);
        assert_eq!(channel_entries[0].tc, Some(200));
        assert_eq!(
            pool.get_uncommitted(&room.sig.pub_key)
                .expect("query")
                .len(),
            0
        );
    }

    #[test]
    fn latest_tc_and_room_ids_work_for_committed_room_events() {
        let pool = Pool::memory().expect("pool should initialize");
        let author = mk_node();
        let room = mk_room();

        let e1 = mk_room_event(&author, &room, "room.message", 1000, json!({"ch": 1, "body": "a"}));
        let e2 = mk_room_event(&author, &room, "room.message", 2000, json!({"ch": 1, "body": "b"}));
        let c1 = wrap_commit(e1, &room, 3000).expect("commit");
        let c2 = wrap_commit(e2, &room, 4000).expect("commit");

        let id1 = pool.put(&c1).expect("put");
        let id2 = pool.put(&c2).expect("put");

        let ids = pool.get_room_ids(&room.sig.pub_key).expect("ids query");
        assert_eq!(ids.len(), 2);
        assert!(ids.contains(&id1));
        assert!(ids.contains(&id2));

        let latest = pool.latest_tc(&room.sig.pub_key).expect("latest");
        assert_eq!(latest, 4000);
    }

    #[test]
    fn get_private_returns_sender_and_receiver_events() {
        let pool = Pool::memory().expect("pool should initialize");
        let arta = mk_node();
        let babak = mk_node();
        let mithra = mk_node();

        let ab = mk_private_message(&arta, &babak.sig.pub_key, 10);
        let ca = mk_private_message(&mithra, &arta.sig.pub_key, 11);
        let bc = mk_private_message(&babak, &mithra.sig.pub_key, 12);

        pool.put(&ab).expect("put");
        pool.put(&ca).expect("put");
        pool.put(&bc).expect("put");

        let arta_private = pool.get_private(&arta.sig.pub_key).expect("query");
        assert_eq!(arta_private.len(), 2);
        assert!(arta_private.iter().all(|e| e.room.is_none()));
    }

    #[test]
    fn build_membership_replays_channel_minus_two_committed_only() {
        let pool = Pool::memory().expect("pool should initialize");
        let key_holder = mk_room();
        let arta = mk_node();
        let babak = mk_node();

        let join_arta = mk_room_event(&arta, &key_holder, "room.join", 100, json!({}));
        let ban_arta = mk_room_event(
            &babak,
            &key_holder,
            "room.ban",
            101,
            json!({ "banned": arta.sig.pub_key }),
        );
        let unban_arta = mk_room_event(
            &babak,
            &key_holder,
            "room.unban",
            102,
            json!({ "unbanned": arta.sig.pub_key }),
        );
        let invite = mk_room_event(
            &babak,
            &key_holder,
            "room.invite",
            103,
            json!({ "invitee": arta.sig.pub_key }),
        );
        let join_arta_again = mk_room_event(&arta, &key_holder, "room.join", 104, json!({}));

        // One uncommitted membership event should not affect final state.
        pool.put(&join_arta).expect("put");

        for (e, tc) in [
            (ban_arta, 1001u64),
            (unban_arta, 1002u64),
            (invite, 1003u64),
            (join_arta_again, 1004u64),
        ] {
            let committed = wrap_commit(e, &key_holder, tc).expect("commit");
            pool.put(&committed).expect("put committed");
        }

        let state = pool.build_membership(&key_holder.sig.pub_key).expect("membership");
        assert!(state.members.contains(&arta.sig.pub_key));
        assert!(!state.banned.contains(&arta.sig.pub_key));
    }

    // ---- ruleset_from_pool ----

    #[test]
    fn from_room_meta_returns_empty_for_unknown_room() {
        let pool = Pool::memory().expect("pool");
        let rs = ruleset_from_pool(&pool, "NONEXISTENT_ROOM_SIG").expect("should not error");
        assert!(rs.rules().is_empty());
        assert!(!rs.can_join());
    }

    #[test]
    fn from_room_meta_reads_rules_from_pool() {
        let pool = Pool::memory().expect("pool");
        let node = mk_node();
        let room = mk_room();
        let rules = json!([{"t": "join", "allow": "*"}, {"t": "post", "allow": "*"}]);

        let (_d1, commit) = make_room_create(&node, &room, Some("Test Room"), Some(rules))
            .expect("room.create");
        pool.put(&commit).expect("put");

        let rs = ruleset_from_pool(&pool, &room.sig.pub_key).expect("from_room_meta");
        assert!(rs.can_join());
        assert!(rs.can_post());
    }

    #[test]
    fn from_room_meta_uses_latest_committed_channel_minus_one() {
        let pool = Pool::memory().expect("pool");
        let node = mk_node();
        let room = mk_room();

        let rules1 = json!([{"t": "join", "allow": "*"}]);
        let (_d1, commit1) = make_room_create(&node, &room, Some("Room"), Some(rules1))
            .expect("room.create");
        pool.put(&commit1).expect("put c1");

        let rules2 = json!([{"t": "join", "allow": "*"}, {"t": "post", "allow": "*"}]);
        let update = make_room_update(&node, &room, None, Some(rules2)).expect("room.update");
        let tc2 = commit1.d.tc.unwrap() + 1000;
        let commit2 = wrap_commit(update, &room, tc2).expect("commit2");
        pool.put(&commit2).expect("put c2");

        let rs = ruleset_from_pool(&pool, &room.sig.pub_key).expect("from_room_meta");
        assert!(rs.can_join());
        assert!(rs.can_post(), "latest update should enable posting");
    }

    // ---- TOFU pin storage ----

    #[test]
    fn tofu_new_pin_then_match() {
        let pool = Pool::memory().expect("pool");
        let result = pool.check_tofu_pin("NODE_A", "fp_aaa", 1000).unwrap();
        assert_eq!(result, super::TofuResult::NewPin);

        let result = pool.check_tofu_pin("NODE_A", "fp_aaa", 2000).unwrap();
        assert_eq!(result, super::TofuResult::Match);
    }

    #[test]
    fn tofu_mismatch_on_fingerprint_change() {
        let pool = Pool::memory().expect("pool");
        pool.check_tofu_pin("NODE_B", "fp_original", 100).unwrap();
        let result = pool.check_tofu_pin("NODE_B", "fp_changed", 200).unwrap();
        match result {
            super::TofuResult::Mismatch { expected, first_seen_at } => {
                assert_eq!(expected, "fp_original");
                assert_eq!(first_seen_at, 100);
            }
            other => panic!("expected Mismatch, got {other:?}"),
        }
    }

    // ---- Blob piece storage ----

    #[test]
    fn blob_piece_store_and_fetch() {
        let pool = Pool::memory().expect("pool");
        pool.put_blob_piece("blob1", 0, b"piece0").unwrap();
        pool.put_blob_piece("blob1", 1, b"piece1").unwrap();

        assert_eq!(pool.blob_piece_count("blob1").unwrap(), 2);
        assert_eq!(pool.get_blob_piece("blob1", 0).unwrap().unwrap(), b"piece0");
        assert_eq!(pool.get_blob_piece("blob1", 1).unwrap().unwrap(), b"piece1");
        assert!(pool.get_blob_piece("blob1", 2).unwrap().is_none());
    }

    #[test]
    fn get_blob_returns_all_pieces_in_order() {
        let pool = Pool::memory().expect("pool");
        pool.put_blob_piece("blob2", 0, b"aaa").unwrap();
        pool.put_blob_piece("blob2", 1, b"bbb").unwrap();
        pool.put_blob_piece("blob2", 2, b"ccc").unwrap();

        let pieces = pool.get_blob("blob2", 3).unwrap().unwrap();
        assert_eq!(pieces.len(), 3);
        assert_eq!(pieces[0], b"aaa");
        assert_eq!(pieces[2], b"ccc");

        // Wrong expected count returns None
        assert!(pool.get_blob("blob2", 2).unwrap().is_none());
    }

    // ---- Local moderation ----

    #[test]
    fn block_and_unblock_node() {
        let pool = Pool::memory().expect("pool");
        assert!(!pool.is_blocked("NODE_X").unwrap());

        pool.block_node("NODE_X", "block", Some("spam"), 1000).unwrap();
        assert!(pool.is_blocked("NODE_X").unwrap());

        let list = pool.get_blocklist().unwrap();
        assert_eq!(list.len(), 1);
        assert_eq!(list[0].0, "NODE_X");
        assert_eq!(list[0].1, "block");

        pool.unblock_node("NODE_X").unwrap();
        assert!(!pool.is_blocked("NODE_X").unwrap());
    }

    // ---- Attestation storage ----

    #[test]
    fn attestation_store_and_query() {
        let pool = Pool::memory().expect("pool");
        let attester = mk_node();
        let target = mk_node();

        let att = toloo_core::events::make_side_attestation(
            &attester, &target.sig.pub_key, "positive", Some("good peer"),
        ).unwrap();
        pool.put_attestation(&att).unwrap();

        let atts = pool.get_attestations_for(&target.sig.pub_key).unwrap();
        assert_eq!(atts.len(), 1);

        let (pos, neg, neu) = pool.attestation_counts(&target.sig.pub_key).unwrap();
        assert_eq!(pos, 1);
        assert_eq!(neg, 0);
        assert_eq!(neu, 0);
    }

    // ---- Room flag aggregation ----

    #[test]
    fn flag_store_and_count() {
        let pool = Pool::memory().expect("pool");
        let node = mk_node();
        let room = mk_room();

        let flag = toloo_core::events::make_room_flag(
            &node, &room.sig.pub_key, "eid_123", "spam", Some("offensive"),
        ).unwrap();
        pool.put_flag(&flag).unwrap();

        assert_eq!(pool.flag_count(&room.sig.pub_key, "eid_123").unwrap(), 1);

        let by_cat = pool.flag_counts_by_category(&room.sig.pub_key, "eid_123").unwrap();
        assert_eq!(by_cat.len(), 1);
        assert_eq!(by_cat[0], ("spam".to_owned(), 1));
    }

    // ---- Export / Import ----

    #[test]
    fn export_import_roundtrip() {
        let pool = Pool::memory().expect("pool");
        let node = mk_node();
        let room = mk_room();

        let (_d1, commit) = make_room_create(&node, &room, Some("Export Room"), Some(json!([])))
            .expect("room.create");
        pool.put(&commit).expect("put");

        let exported = pool.export_room(&room.sig.pub_key).unwrap();
        assert_eq!(exported.len(), 1);

        let pool2 = Pool::memory().expect("pool2");
        let imported = pool2.import_envelopes(&exported).unwrap();
        assert_eq!(imported, 1);

        let re_exported = pool2.export_room(&room.sig.pub_key).unwrap();
        assert_eq!(re_exported.len(), 1);
    }
}
