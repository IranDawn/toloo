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
}
