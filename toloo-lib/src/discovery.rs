/// `toloo://` URI and `.toloo` file encoding/decoding (spec §4.5).
///
/// Both formats encode the same data: one base64url-encoded signed envelope
/// per segment. The only difference is the separator:
///
/// - URI:  `toloo://` prefix, `.` separator
/// - File: `\n` separator, `#` comment lines, empty lines ignored
///
/// Encoding: `base64url(canonical({d, p}))` per envelope.
/// Decoding: base64url-decode → JSON → validate `{d, p}` structure → verify signature.
use anyhow::{Context, Result};

use toloo_core::base64url;
use toloo_core::canonical::canonical_bytes;
use toloo_core::envelope::{parse_envelope, verify_chain};
use toloo_core::types::Envelope;

const URI_PREFIX: &str = "toloo://";

// ---- Encoding ----

/// Encode one or more envelopes as a `toloo://` URI.
///
/// Each envelope is serialized as `base64url(canonical({d,p}))` and joined
/// with `.` after the `toloo://` prefix.
pub fn encode_uri(envelopes: &[Envelope]) -> Result<String> {
    let segments = encode_segments(envelopes)?;
    Ok(format!("{}{}", URI_PREFIX, segments.join(".")))
}

/// Encode one or more envelopes as `.toloo` file content (newline-separated).
pub fn encode_file(envelopes: &[Envelope]) -> Result<String> {
    let segments = encode_segments(envelopes)?;
    Ok(segments.join("\n"))
}

fn encode_segments(envelopes: &[Envelope]) -> Result<Vec<String>> {
    envelopes
        .iter()
        .enumerate()
        .map(|(i, env)| {
            let value = serde_json::to_value(env)
                .with_context(|| format!("envelope {i} serialization failed"))?;
            let bytes = canonical_bytes(&value)
                .with_context(|| format!("envelope {i} canonical serialization failed"))?;
            Ok(base64url::encode(&bytes))
        })
        .collect()
}

// ---- Decoding ----

/// Decode a `toloo://` URI or `.toloo` file content into verified envelopes.
///
/// Algorithm (spec §4.5.1):
/// 1. If input starts with `toloo://`, strip prefix and replace `.` with `\n`
/// 2. Split on `\n`
/// 3. Skip empty lines and lines starting with `#`
/// 4. Base64url-decode each line
/// 5. Parse JSON as `{d, p}` envelope
/// 6. Verify signature chain
///
/// Returns only envelopes that pass signature verification.
/// Returns an error if no valid envelopes are found.
pub fn decode(input: &str) -> Result<Vec<Envelope>> {
    let normalized = if input.starts_with(URI_PREFIX) {
        input[URI_PREFIX.len()..].replace('.', "\n")
    } else {
        input.to_owned()
    };

    let mut results = Vec::new();
    for line in normalized.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let bytes = base64url::decode(line)
            .with_context(|| format!("base64url decode failed for segment"))?;
        let value: serde_json::Value = serde_json::from_slice(&bytes)
            .with_context(|| format!("JSON parse failed for segment"))?;
        let env = parse_envelope(value)
            .with_context(|| format!("envelope parse failed for segment"))?;
        verify_chain(&env)
            .with_context(|| format!("signature verification failed for segment"))?;
        results.push(env);
    }

    if results.is_empty() {
        anyhow::bail!("no valid envelopes found in input");
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;
    use toloo_core::base64url;
    use toloo_core::crypto::ed25519_generate;
    use toloo_core::envelope::make_envelope;
    use toloo_core::events::make_node_meta;
    use toloo_core::types::{Keypair, LocalNode};
    use toloo_core::crypto::x25519_generate;
    use serde_json::json;

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

    #[test]
    fn single_envelope_uri_roundtrip() {
        let node = mk_node();
        let env = make_node_meta(&node, vec![]).unwrap();
        let uri = encode_uri(&[env.clone()]).unwrap();
        assert!(uri.starts_with("toloo://"), "URI must have toloo:// prefix");
        assert!(!uri[8..].contains('.') || uri[8..].split('.').count() == 1);

        let decoded = decode(&uri).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].d.n, env.d.n);
        assert_eq!(decoded[0].d.t, "node.meta");
    }

    #[test]
    fn multi_envelope_uri_roundtrip() {
        let node1 = mk_node();
        let node2 = mk_node();
        let env1 = make_node_meta(&node1, vec![]).unwrap();
        let env2 = make_node_meta(&node2, vec![]).unwrap();

        let uri = encode_uri(&[env1.clone(), env2.clone()]).unwrap();
        assert!(uri.starts_with("toloo://"));
        assert!(uri[8..].contains('.'), "multiple envelopes joined with .");

        let decoded = decode(&uri).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].d.n, env1.d.n);
        assert_eq!(decoded[1].d.n, env2.d.n);
    }

    #[test]
    fn file_format_roundtrip() {
        let node1 = mk_node();
        let node2 = mk_node();
        let env1 = make_node_meta(&node1, vec![]).unwrap();
        let env2 = make_node_meta(&node2, vec![]).unwrap();

        let file = encode_file(&[env1.clone(), env2.clone()]).unwrap();
        assert!(file.contains('\n'), "file format uses newlines");
        assert!(!file.starts_with("toloo://"), "file format has no URI prefix");

        let decoded = decode(&file).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].d.n, env1.d.n);
        assert_eq!(decoded[1].d.n, env2.d.n);
    }

    #[test]
    fn file_with_comments_and_blank_lines() {
        let node = mk_node();
        let env = make_node_meta(&node, vec![]).unwrap();
        let segment = encode_segments(&[env.clone()]).unwrap()[0].clone();

        let file_content = format!(
            "# Toloo seed nodes — updated 2026-02-01\n\
             # Organization A\n\
             {segment}\n\
             \n\
             # trailing comment\n"
        );

        let decoded = decode(&file_content).unwrap();
        assert_eq!(decoded.len(), 1);
        assert_eq!(decoded[0].d.n, env.d.n);
    }

    #[test]
    fn tampered_signature_is_rejected() {
        let node = mk_node();
        let mut env = make_node_meta(&node, vec![]).unwrap();
        env.p = "a".repeat(86); // invalid signature

        let result = encode_uri(&[env]);
        // encode_uri doesn't re-verify, so encoding succeeds.
        // But decoding must reject the tampered signature.
        if let Ok(uri) = result {
            let decoded = decode(&uri);
            assert!(decoded.is_err(), "tampered signature must be rejected");
        }
    }

    #[test]
    fn empty_input_returns_error() {
        assert!(decode("").is_err());
        assert!(decode("toloo://").is_err());
        assert!(decode("# just a comment").is_err());
    }

    #[test]
    fn uri_and_file_produce_same_envelopes() {
        let node = mk_node();
        let env = make_node_meta(&node, vec![]).unwrap();

        let uri = encode_uri(&[env.clone()]).unwrap();
        let file = encode_file(&[env.clone()]).unwrap();

        let from_uri = decode(&uri).unwrap();
        let from_file = decode(&file).unwrap();

        assert_eq!(from_uri[0].d.n, from_file[0].d.n);
        assert_eq!(from_uri[0].p, from_file[0].p);
    }

    #[test]
    fn first_envelope_determines_primary_intent() {
        let node = mk_node();
        let env = make_node_meta(&node, vec![]).unwrap();
        let uri = encode_uri(&[env]).unwrap();
        let decoded = decode(&uri).unwrap();
        // Primary intent: node.meta → "connect to this peer"
        assert_eq!(decoded[0].d.t, "node.meta");
    }

    #[test]
    fn room_invite_uri_contains_commit_and_node_meta() {
        use toloo_core::envelope::wrap_commit;
        use toloo_core::events::make_room_create;
        use toloo_core::types::LocalRoom;

        let node = mk_node();
        let room = {
            let (pub_bytes, seed_bytes) = ed25519_generate();
            LocalRoom {
                sig: Keypair {
                    pub_key: base64url::encode(&pub_bytes),
                    priv_key: base64url::encode(&seed_bytes),
                },
            }
        };
        let (d1, commit) = make_room_create(&node, &room, Some("Test Room"), Some(json!([]))).unwrap();
        let _ = d1;
        let peer_meta = make_node_meta(&node, vec![]).unwrap();

        // Room invite: committed room.create + peer node.meta
        let uri = encode_uri(&[commit, peer_meta]).unwrap();
        let decoded = decode(&uri).unwrap();
        assert_eq!(decoded.len(), 2);
        assert_eq!(decoded[0].d.t, "commit"); // primary intent: room invite
        assert_eq!(decoded[1].d.t, "node.meta"); // supporting context
    }
}
