use serde_json::Value;

use crate::canonical::canonical_bytes;
use crate::crypto::sha256;
use crate::envelope::innermost;
use crate::types::{DatumBody, Envelope};

const CHANNEL_META: i32 = -1;
const CHANNEL_MEMBERSHIP: i32 = -2;
const CHANNEL_DEFAULT: i32 = 0;

/// Channel of an event from its innermost datum.
///
/// Returns `None` for private message types — they have no channel concept
/// and their identity is `{ts}:{n}` only (no channel prefix).
/// Returns `Some(ch)` for all room event types.
pub fn channel_of(d: &DatumBody) -> Option<i32> {
    match d.t.as_str() {
        "commit" => d
            .env
            .as_deref()
            .and_then(|inner| channel_of(&innermost(inner).d)),
        "room.create" | "room.update" => Some(CHANNEL_META),
        "room.join" | "room.leave" | "room.ban" | "room.unban" | "room.invite" => {
            Some(CHANNEL_MEMBERSHIP)
        }
        "room.message" | "room.react" | "room.edit" | "room.delete" | "room.blob" => {
            Some(channel_from_content(d.c.as_ref()).unwrap_or(CHANNEL_DEFAULT))
        }
        "private.message" | "private.read" | "private.blob" => None,
        _ => Some(CHANNEL_DEFAULT),
    }
}

/// Stable logical event identity, derived from innermost datum fields.
pub fn eid(env: &Envelope) -> String {
    let inner = innermost(env);
    if inner.d.r.is_some() {
        let ch = channel_of(&inner.d).unwrap_or(CHANNEL_DEFAULT);
        format!("{}:{}:{}", ch, inner.d.ts, inner.d.n)
    } else {
        format!("{}:{}", inner.d.ts, inner.d.n)
    }
}

/// Hash identity of the full envelope bytes (changes with wrapping depth).
pub fn datum_id(env: &Envelope) -> String {
    let bytes = canonical_bytes(env).expect("envelope canonical serialization should not fail");
    hex::encode(sha256(&bytes))
}

fn channel_from_content(c: Option<&Value>) -> Option<i32> {
    let c = c?.as_object()?;
    let ch = c.get("ch")?.as_i64()?;
    i32::try_from(ch).ok()
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use serde_json::json;

    use crate::base64url;
    use crate::crypto::{ed25519_generate, x25519_generate};
    use crate::envelope::{sign_envelope, wrap_commit};
    use crate::types::{DatumBody, Envelope, Keypair, LocalNode, LocalRoom};

    use super::{channel_of, datum_id, eid};

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

    fn mk_inner_room_event(node: &LocalNode, room: &LocalRoom, ts: u64, ch: i32) -> Envelope {
        let d = DatumBody {
            n: node.sig.pub_key.clone(),
            v: "0.2".to_owned(),
            t: "room.message".to_owned(),
            ts,
            r: Some(room.sig.pub_key.clone()),
            to: None,
            c: Some(json!({"ch": ch, "body": "hello"})),
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        sign_envelope(d, &node.sig.priv_key).expect("inner sign should succeed")
    }

    #[test]
    fn channel_mapping_for_reserved_types() {
        let meta = DatumBody {
            n: "n".to_owned(),
            v: "0.2".to_owned(),
            t: "room.create".to_owned(),
            ts: 1,
            r: Some("room".to_owned()),
            to: None,
            c: None,
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        assert_eq!(channel_of(&meta), Some(-1));

        let member = DatumBody {
            t: "room.join".to_owned(),
            ..meta.clone()
        };
        assert_eq!(channel_of(&member), Some(-2));
    }

    #[test]
    fn content_events_use_c_ch_or_default_zero() {
        let with_ch = DatumBody {
            n: "n".to_owned(),
            v: "0.2".to_owned(),
            t: "room.message".to_owned(),
            ts: 1,
            r: Some("room".to_owned()),
            to: None,
            c: Some(json!({"ch": 7})),
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        assert_eq!(channel_of(&with_ch), Some(7));

        let missing_ch = DatumBody {
            c: Some(json!({"body": "hello"})),
            ..with_ch.clone()
        };
        assert_eq!(channel_of(&missing_ch), Some(0));
    }

    #[test]
    fn commit_channel_is_derived_from_innermost() {
        let node = mk_node();
        let room = mk_room();
        let inner = mk_inner_room_event(&node, &room, 1000, 9);
        let commit = wrap_commit(inner, &room, 1001).expect("commit should wrap");
        assert_eq!(channel_of(&commit.d), Some(9));
    }

    #[test]
    fn private_message_types_have_no_channel() {
        let base = DatumBody {
            n: "n".to_owned(),
            v: "0.2".to_owned(),
            t: "private.message".to_owned(),
            ts: 1,
            r: None,
            to: Some("recipient".to_owned()),
            c: None,
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        assert_eq!(channel_of(&base), None);

        let read = DatumBody { t: "private.read".to_owned(), ..base.clone() };
        assert_eq!(channel_of(&read), None);

        let blob = DatumBody { t: "private.blob".to_owned(), ..base.clone() };
        assert_eq!(channel_of(&blob), None);
    }

    #[test]
    fn eid_uses_room_format_and_is_stable_across_depth() {
        let node = mk_node();
        let room = mk_room();
        let inner = mk_inner_room_event(&node, &room, 1710000000000, 3);
        let commit = wrap_commit(inner.clone(), &room, 1710000000001).expect("commit should wrap");

        let eid_inner = eid(&inner);
        let eid_commit = eid(&commit);

        assert_eq!(
            eid_inner,
            format!("3:1710000000000:{}", node.sig.pub_key)
        );
        assert_eq!(eid_inner, eid_commit);
    }

    #[test]
    fn eid_uses_direct_format_without_room() {
        let node = mk_node();
        let d = DatumBody {
            n: node.sig.pub_key.clone(),
            v: "0.2".to_owned(),
            t: "private.message".to_owned(),
            ts: 42,
            r: None,
            to: Some("recipient".to_owned()),
            c: Some(json!({"msg": "x"})),
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        };
        let env = sign_envelope(d, &node.sig.priv_key).expect("sign should succeed");
        assert_eq!(eid(&env), format!("42:{}", node.sig.pub_key));
    }

    #[test]
    fn datum_id_is_64_hex_and_changes_when_wrapped() {
        let node = mk_node();
        let room = mk_room();
        let inner = mk_inner_room_event(&node, &room, 999, 1);
        let commit = wrap_commit(inner.clone(), &room, 1000).expect("commit should wrap");

        let d1 = datum_id(&inner);
        let d2 = datum_id(&commit);
        assert_eq!(d1.len(), 64);
        assert_eq!(d2.len(), 64);
        assert_ne!(d1, d2);
        assert!(d1.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(d2.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
    }
}
