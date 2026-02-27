/// Cross-implementation test vector verification (spec §Appendix E).
///
/// Each test corresponds to a section of E-test-vectors.md and verifies
/// the reference implementation produces the expected deterministic outputs.
/// Any correct Toloo v0.2 implementation given the same inputs MUST produce
/// identical outputs.
use toloo_core::base64url;
use toloo_core::canonical::canonical_bytes;
use toloo_core::crypto::{
    derive_endpoint_keys, ed25519_pub_from_seed, ed25519_verify, hkdf_sha256, sha256,
    x25519_shared_secret,
};
use toloo_core::envelope::{depth, innermost, verify_chain};
use toloo_core::ids::{datum_id, eid};
use toloo_core::pow::count_leading_zero_bits;
use toloo_core::private::decrypt_private;
use toloo_core::vectors::{
    hex_to_bytes, mk_node, mk_room, VectorSet,
    ARTA_ENC_SEED_HEX, ARTA_SIG_SEED_HEX,
    BABAK_ENC_SEED_HEX, BABAK_SIG_SEED_HEX,
    MITHRA_ENC_SEED_HEX, MITHRA_SIG_SEED_HEX,
    EPH_PRIV_SEED_HEX,
    INITIATOR_EPH_SEED_HEX, RESPONDER_EPH_SEED_HEX,
    RELAY_SIG_SEED_HEX, RELAY_ENC_SEED_HEX,
    ROOM_SIG_SEED_HEX,
};

// Shared fixture: compute once, test many
fn vectors() -> VectorSet {
    VectorSet::compute().expect("VectorSet::compute failed")
}

// ---- §E.2 Identity ----

#[test]
fn e2_arta_sig_pub_derived_from_seed() {
    let seed = hex_to_bytes(ARTA_SIG_SEED_HEX);
    let pub_bytes = ed25519_pub_from_seed(&seed).unwrap();
    let v = vectors();
    assert_eq!(hex::encode(&pub_bytes), v.arta.sig_pub_hex);
    assert_eq!(base64url::encode(&pub_bytes), v.arta.sig_pub_b64);
    assert_eq!(v.arta.sig_pub_b64.len(), 43, "Ed25519 pub = 43 base64url chars");
}

#[test]
fn e2_babak_sig_pub_derived_from_seed() {
    let seed = hex_to_bytes(BABAK_SIG_SEED_HEX);
    let pub_bytes = ed25519_pub_from_seed(&seed).unwrap();
    let v = vectors();
    assert_eq!(hex::encode(&pub_bytes), v.babak.sig_pub_hex);
}

#[test]
fn e2_room_has_no_enc_key() {
    let v = vectors();
    assert!(v.room.enc_pub_hex.is_none());
    assert!(v.room.enc_pub_b64.is_none());
}

#[test]
fn e2_enc_pub_length() {
    let v = vectors();
    for node in [&v.arta, &v.babak, &v.mithra, &v.relay] {
        let enc_b64 = node.enc_pub_b64.as_ref().unwrap();
        assert_eq!(enc_b64.len(), 43, "X25519 pub = 43 base64url chars: {enc_b64}");
    }
}

// ---- §E.3 Canonical JSON ----

#[test]
fn e3_1_key_ordering() {
    let v = vectors();
    assert_eq!(
        v.e3_1_canonical,
        r#"{"n":"ARTA_SIG","t":"room.message","ts":1710000000000,"v":"0.2"}"#
    );
}

#[test]
fn e3_2_nested_objects() {
    let v = vectors();
    assert_eq!(
        v.e3_2_canonical,
        r#"{"env":{"d":{"c":{"body":"hello","ch":0},"n":"ARTA_SIG","r":"ROOM_SIG","t":"room.message","ts":1710000000000,"v":"0.2"},"p":"INNER_SIG"},"n":"ROOM_SIG","t":"commit","tc":1710000100000,"ts":1710000100000,"v":"0.2"}"#
    );
}

#[test]
fn e3_3_unicode_preserved() {
    let v = vectors();
    // UTF-8 characters outside ASCII are preserved as-is (not escaped).
    assert_eq!(
        v.e3_3_canonical,
        "{\"c\":{\"body\":\"سلام\"},\"n\":\"TEST\",\"t\":\"room.message\",\"ts\":0,\"v\":\"0.2\"}"
    );
    assert!(v.e3_3_canonical.contains("سلام"), "Arabic chars must not be escaped");
}

#[test]
fn e3_4_numbers() {
    let v = vectors();
    assert_eq!(
        v.e3_4_canonical,
        r#"{"c":{"a":0,"b":-1,"c":1.5,"d":100},"n":"X","t":"test","ts":1710000000000,"v":"0.2"}"#
    );
}

#[test]
fn e3_5_empty_null_values() {
    let v = vectors();
    assert_eq!(
        v.e3_5_canonical,
        r#"{"c":{"bool":true,"empty":"","list":[],"null_val":null,"obj":{}},"n":"X","t":"test","ts":0,"v":"0.2"}"#
    );
}

// ---- §E.4 Envelope Signing ----

#[test]
fn e4_1_canonical_and_signature() {
    let v = vectors();
    // Canonical hex must be non-empty and valid UTF-8.
    assert!(!v.e4_1_canonical_hex.is_empty());
    // Signature must be 86 base64url chars (64 bytes).
    assert_eq!(v.e4_1_sig_b64.len(), 86, "Ed25519 sig = 86 base64url chars");
    // Hex and b64 must encode the same bytes.
    let from_hex = hex::decode(&v.e4_1_sig_hex).unwrap();
    let from_b64 = base64url::decode(&v.e4_1_sig_b64).unwrap();
    assert_eq!(from_hex, from_b64);
}

#[test]
fn e4_1_envelope_verifies() {
    let v = vectors();
    verify_chain(&v.e4_1_envelope).expect("depth-1 envelope must verify");
}

#[test]
fn e4_1_tampered_body_fails() {
    let mut env = vectors().e4_1_envelope.clone();
    // Modify body without re-signing.
    env.d.c = Some(serde_json::json!({"ch": 0, "body": "Hello, world!!"}));
    assert!(verify_chain(&env).is_err(), "tampered body must fail verification");
}

#[test]
fn e4_1_tampered_sig_fails() {
    let mut env = vectors().e4_1_envelope.clone();
    env.p = "a".repeat(86);
    assert!(verify_chain(&env).is_err(), "tampered sig must fail verification");
}

#[test]
fn e4_1_depth_is_1() {
    let v = vectors();
    assert_eq!(depth(&v.e4_1_envelope), 1);
}

// ---- §E.5 Depth-2 Commit ----

#[test]
fn e5_1_commit_verifies_both_layers() {
    let v = vectors();
    verify_chain(&v.e5_1_commit).expect("depth-2 commit must verify");
}

#[test]
fn e5_1_depth_is_2() {
    let v = vectors();
    assert_eq!(depth(&v.e5_1_commit), 2);
}

#[test]
fn e5_1_outer_signer_is_room() {
    let v = vectors();
    let room = mk_room(ROOM_SIG_SEED_HEX);
    assert_eq!(v.e5_1_commit.d.n, room.sig.pub_key);
    assert_eq!(v.e5_1_commit.d.t, "commit");
}

#[test]
fn e5_1_inner_signer_is_arta() {
    let v = vectors();
    let arta = mk_node(ARTA_SIG_SEED_HEX, ARTA_ENC_SEED_HEX);
    let inner = innermost(&v.e5_1_commit);
    assert_eq!(inner.d.n, arta.sig.pub_key);
    assert_eq!(inner.d.t, "room.message");
}

#[test]
fn e5_1_signer_alternation() {
    let v = vectors();
    let outer_n = &v.e5_1_commit.d.n;
    let inner_n = &innermost(&v.e5_1_commit).d.n;
    assert_ne!(outer_n, inner_n, "depth-1 and depth-2 signers must differ");
    // Outer signer (room) == inner's d.r
    assert_eq!(Some(outer_n.as_str()), innermost(&v.e5_1_commit).d.r.as_deref());
}

#[test]
fn e5_1_tc_is_commit_timestamp() {
    let v = vectors();
    assert_eq!(v.e5_1_commit.d.tc, Some(1710000100000));
    assert_eq!(v.e5_1_commit.d.ts, 1710000100000);
}

// ---- §E.6 Envelope Identity ----

#[test]
fn e6_1_eid_stable_across_depths() {
    let v = vectors();
    // eid of depth-2 == eid of its inner depth-1
    let eid_d1 = eid(&v.e4_1_envelope);
    let eid_d2 = eid(&v.e5_1_commit);
    assert_eq!(eid_d1, eid_d2, "eid must be stable across depths");
    assert_eq!(eid_d1, v.e6_1_eid);
}

#[test]
fn e6_1_eid_format_channel_prefixed() {
    let v = vectors();
    // Room message eid: ch:ts:n
    assert!(v.e6_1_eid.starts_with("0:"), "room eid starts with channel: {}", v.e6_1_eid);
    assert!(v.e6_1_eid.contains("1710000000000"), "eid contains timestamp");
}

#[test]
fn e6_3_datum_id_differs_between_depths() {
    let v = vectors();
    assert_ne!(
        v.e6_3_datum_id_d1,
        v.e6_3_datum_id_d2,
        "datum_id changes when envelope is wrapped"
    );
    // datum_id is a SHA-256 hex string (64 hex chars)
    assert_eq!(v.e6_3_datum_id_d1.len(), 64);
    assert_eq!(v.e6_3_datum_id_d2.len(), 64);
}

#[test]
fn e6_3_datum_id_is_canonical_sha256() {
    let v = vectors();
    let env_val = serde_json::to_value(&v.e4_1_envelope).unwrap();
    let canonical = canonical_bytes(&env_val).unwrap();
    let hash = sha256(&canonical);
    assert_eq!(hex::encode(hash), v.e6_3_datum_id_d1);
}

// ---- §E.7 Private Message Encryption ----

#[test]
fn e7_eph_pub_length() {
    let v = vectors();
    let pub_bytes = hex::decode(&v.e7_eph_pub_hex).unwrap();
    assert_eq!(pub_bytes.len(), 32);
    assert_eq!(v.e7_eph_pub_b64.len(), 43);
}

#[test]
fn e7_shared_secret_deterministic() {
    let v = vectors();
    let babak = mk_node(BABAK_SIG_SEED_HEX, BABAK_ENC_SEED_HEX);
    let eph_priv = hex_to_bytes(EPH_PRIV_SEED_HEX);
    let babak_enc_pub = base64url::decode(&babak.enc.pub_key).unwrap();
    let shared = x25519_shared_secret(&eph_priv, &babak_enc_pub).unwrap();
    assert_eq!(hex::encode(&shared), v.e7_shared_hex);
}

#[test]
fn e7_key_nonce_lengths() {
    let v = vectors();
    let key_bytes = hex::decode(&v.e7_key_hex).unwrap();
    let nonce_bytes = hex::decode(&v.e7_nonce_hex).unwrap();
    assert_eq!(key_bytes.len(), 32, "ChaCha20 key = 32 bytes");
    assert_eq!(nonce_bytes.len(), 12, "ChaCha20 nonce = 12 bytes");
}

#[test]
fn e7_decrypt_recovers_plaintext() {
    let v = vectors();
    let babak = mk_node(BABAK_SIG_SEED_HEX, BABAK_ENC_SEED_HEX);
    let cipher = toloo_core::private::PrivateCiphertext {
        eph: v.e7_eph_pub_b64.clone(),
        encrypted: v.e7_ciphertext_b64.clone(),
    };
    let plaintext = decrypt_private(&cipher, &babak.enc.priv_key).unwrap();
    assert_eq!(plaintext["body"], "Hello Babak");
}

#[test]
fn e7_tampered_ciphertext_fails() {
    let v = vectors();
    let babak = mk_node(BABAK_SIG_SEED_HEX, BABAK_ENC_SEED_HEX);
    let mut bad_ct = base64url::decode(&v.e7_ciphertext_b64).unwrap();
    bad_ct[0] ^= 0xff; // flip first byte
    let cipher = toloo_core::private::PrivateCiphertext {
        eph: v.e7_eph_pub_b64.clone(),
        encrypted: base64url::encode(&bad_ct),
    };
    assert!(decrypt_private(&cipher, &babak.enc.priv_key).is_err());
}

// ---- §E.8 Endpoint Encryption Handshake ----

#[test]
fn e8_both_sides_derive_same_shared_secret() {
    let v = vectors();
    // Initiator: X25519(init_priv, resp_pub)
    let init_priv = hex_to_bytes(INITIATOR_EPH_SEED_HEX);
    let resp_pub = hex::decode(&v.e8_responder_eph_pub_hex).unwrap();
    let shared_i = x25519_shared_secret(&init_priv, &resp_pub).unwrap();

    // Responder: X25519(resp_priv, init_pub)
    let resp_priv = hex_to_bytes(RESPONDER_EPH_SEED_HEX);
    let init_pub = hex::decode(&v.e8_initiator_eph_pub_hex).unwrap();
    let shared_r = x25519_shared_secret(&resp_priv, &init_pub).unwrap();

    assert_eq!(shared_i, shared_r, "both sides must derive the same shared secret");
    assert_eq!(hex::encode(&shared_i), v.e8_shared_hex);
}

#[test]
fn e8_derived_keys_length() {
    let v = vectors();
    let k_i2r = hex::decode(&v.e8_k_i2r_hex).unwrap();
    let k_r2i = hex::decode(&v.e8_k_r2i_hex).unwrap();
    assert_eq!(k_i2r.len(), 32);
    assert_eq!(k_r2i.len(), 32);
    assert_ne!(k_i2r, k_r2i, "directional keys must differ");
}

#[test]
fn e8_keys_from_derive_endpoint_keys() {
    let v = vectors();
    let shared = hex::decode(&v.e8_shared_hex).unwrap();
    let (k_i2r, k_r2i) = derive_endpoint_keys(&shared);
    assert_eq!(hex::encode(k_i2r), v.e8_k_i2r_hex);
    assert_eq!(hex::encode(k_r2i), v.e8_k_r2i_hex);
}

#[test]
fn e8_okm_first_half_is_k_i2r() {
    let v = vectors();
    let okm = hex::decode(&v.e8_okm_hex).unwrap();
    assert_eq!(hex::encode(&okm[0..32]), v.e8_k_i2r_hex);
    assert_eq!(hex::encode(&okm[32..64]), v.e8_k_r2i_hex);
}

#[test]
fn e8_proof_verifies_with_relay_pubkey() {
    let v = vectors();
    let relay_seed = hex_to_bytes(RELAY_SIG_SEED_HEX);
    let relay_pub = ed25519_pub_from_seed(&relay_seed).unwrap();
    let transcript = hex::decode(&v.e8_transcript_hex).unwrap();
    let proof_bytes = base64url::decode(&v.e8_proof_b64).unwrap();
    toloo_core::crypto::ed25519_verify(&transcript, &proof_bytes, &relay_pub)
        .expect("relay identity proof must verify");
}

#[test]
fn e8_transcript_is_init_pub_concat_resp_pub() {
    let v = vectors();
    let expected = format!("{}{}", v.e8_initiator_eph_pub_hex, v.e8_responder_eph_pub_hex);
    assert_eq!(v.e8_transcript_hex, expected);
    assert_eq!(v.e8_transcript_hex.len(), 128, "64 bytes = 128 hex chars");
}

// ---- §E.9 Proof of Work ----

#[test]
fn e9_winning_nonce_produces_16_leading_zero_bits() {
    let v = vectors();
    let hash_bytes = hex::decode(&v.e9_winning_hash_hex).unwrap();
    let hash_array: [u8; 32] = hash_bytes.try_into().unwrap();
    let zeros = count_leading_zero_bits(&hash_array);
    assert!(zeros >= 16, "winning nonce hash must have >=16 leading zero bits, got {zeros}");
}

#[test]
fn e9_leading_zero_bit_cases() {
    // §E.9.2 reference table
    let cases: Vec<(&str, u32)> = vec![
        ("00000000", 32),
        ("0000ffff", 16),
        ("00ffffff", 8),
        ("0fffffff", 4),
        ("7fffffff", 1),
        ("80000000", 0),
        ("ffffffff", 0),
    ];
    for (hex_prefix, expected_min) in cases {
        let mut hash = [0u8; 32];
        let prefix_bytes = hex::decode(hex_prefix).unwrap();
        hash[..prefix_bytes.len()].copy_from_slice(&prefix_bytes);
        let got = count_leading_zero_bits(&hash);
        assert!(
            got >= expected_min,
            "hash {hex_prefix}... expected >= {expected_min} leading zeros, got {got}"
        );
        if hex_prefix == "80000000" || hex_prefix == "ffffffff" {
            assert_eq!(got, 0, "must be exactly 0 for {hex_prefix}");
        }
        if hex_prefix == "7fffffff" {
            assert_eq!(got, 1, "must be exactly 1 for {hex_prefix}");
        }
    }
}

// ---- §E.10 Membership Reconstruction ----

#[test]
fn e10_basic_membership_sequence() {
    use toloo_core::events::{make_room_join, make_room_leave};
    use toloo_core::envelope::wrap_commit;
    use toloo_lib::pool::Pool;

    let pool = Pool::memory().unwrap();
    let mithra = mk_node(MITHRA_SIG_SEED_HEX, MITHRA_ENC_SEED_HEX);
    let room = mk_room(ROOM_SIG_SEED_HEX);

    let arta = mk_node(ARTA_SIG_SEED_HEX, ARTA_ENC_SEED_HEX);
    let babak = mk_node(BABAK_SIG_SEED_HEX, BABAK_ENC_SEED_HEX);
    let dave_seed = "ccddee11223344ccddee11223344ccddee11223344ccddee11223344ccddee11";
    let dave_enc_seed = "ddee11223344ccddee11223344ccddee11223344ccddee11223344ccddee1122";
    let dave = mk_node(dave_seed, dave_enc_seed);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let mut tc = now;
    let commit = |env, tc| wrap_commit(env, &room, tc).unwrap();

    // seq 1: Arta joins
    pool.put(&commit(make_room_join(&arta, &room.sig.pub_key, None).unwrap(), tc)).unwrap();
    tc += 100000;
    // seq 2: Babak joins
    pool.put(&commit(make_room_join(&babak, &room.sig.pub_key, None).unwrap(), tc)).unwrap();
    tc += 100000;
    // seq 3: Mithra joins
    pool.put(&commit(make_room_join(&mithra, &room.sig.pub_key, None).unwrap(), tc)).unwrap();
    tc += 100000;
    // seq 4: Babak leaves
    pool.put(&commit(make_room_leave(&babak, &room.sig.pub_key).unwrap(), tc)).unwrap();
    tc += 100000;
    // seq 5: Mithra bans Arta
    let ban = toloo_core::envelope::make_envelope(
        "room.ban",
        Some(serde_json::json!({"r": room.sig.pub_key, "banned": arta.sig.pub_key})),
        &mithra,
        Some(toloo_core::envelope::DatumBodyExtra { r: Some(room.sig.pub_key.clone()), to: None, tc: None, exp: None, nonce: None }),
    ).unwrap();
    pool.put(&commit(ban, tc)).unwrap();
    tc += 100000;
    // seq 6: Dave joins
    pool.put(&commit(make_room_join(&dave, &room.sig.pub_key, None).unwrap(), tc)).unwrap();

    let state = pool.build_membership(&room.sig.pub_key).unwrap();
    assert!(state.members.contains(&mithra.sig.pub_key), "Mithra should be member");
    assert!(state.members.contains(&dave.sig.pub_key), "Dave should be member");
    assert!(!state.members.contains(&arta.sig.pub_key), "Arta should be banned out");
    assert!(!state.members.contains(&babak.sig.pub_key), "Babak left");
    assert!(state.banned.contains(&arta.sig.pub_key), "Arta should be in banned set");
}

#[test]
fn e10_unban_then_rejoin() {
    use toloo_core::events::make_room_join;
    use toloo_core::envelope::{make_envelope, wrap_commit, DatumBodyExtra};
    use toloo_lib::pool::Pool;

    let pool = Pool::memory().unwrap();
    let mithra = mk_node(MITHRA_SIG_SEED_HEX, MITHRA_ENC_SEED_HEX);
    let room = mk_room(ROOM_SIG_SEED_HEX);
    let arta = mk_node(ARTA_SIG_SEED_HEX, ARTA_ENC_SEED_HEX);
    let commit = |env, tc| wrap_commit(env, &room, tc).unwrap();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH).unwrap().as_millis() as u64;
    let mut tc = now;

    // Ban Arta
    let ban = make_envelope(
        "room.ban",
        Some(serde_json::json!({"r": room.sig.pub_key, "banned": arta.sig.pub_key})),
        &mithra,
        Some(DatumBodyExtra { r: Some(room.sig.pub_key.clone()), to: None, tc: None, exp: None, nonce: None }),
    ).unwrap();
    pool.put(&commit(ban, tc)).unwrap();
    tc += 100000;

    // Unban Arta
    let unban = make_envelope(
        "room.unban",
        Some(serde_json::json!({"r": room.sig.pub_key, "unbanned": arta.sig.pub_key})),
        &mithra,
        Some(DatumBodyExtra { r: Some(room.sig.pub_key.clone()), to: None, tc: None, exp: None, nonce: None }),
    ).unwrap();
    pool.put(&commit(unban, tc)).unwrap();
    tc += 100000;

    // Arta rejoins
    pool.put(&commit(make_room_join(&arta, &room.sig.pub_key, None).unwrap(), tc)).unwrap();

    let state = pool.build_membership(&room.sig.pub_key).unwrap();
    assert!(state.members.contains(&arta.sig.pub_key), "Arta should be a member after unban+rejoin");
    assert!(state.banned.is_empty(), "banned set should be empty");
}

// ---- §E.11 Room Rule Evaluation ----

#[test]
fn e11_last_matching_rule_wins() {
    use toloo_core::rules::RuleSet;

    let arta = mk_node(ARTA_SIG_SEED_HEX, ARTA_ENC_SEED_HEX);
    let babak = mk_node(BABAK_SIG_SEED_HEX, BABAK_ENC_SEED_HEX);

    // Rule format: "allow": "*" = anyone, "deny": [key] = specific deny.
    // Last matching rule wins. Arta is denied by the second rule; Babak only hits the first.
    let rules = serde_json::json!([
        {"t": "post", "allow": "*"},
        {"t": "post", "deny": [arta.sig.pub_key]}
    ]);
    let rs = RuleSet::from_json(&rules);

    assert!(!rs.can_post_node(&arta.sig.pub_key, &[]), "Arta denied by last matching rule");
    assert!(rs.can_post_node(&babak.sig.pub_key, &[]), "Babak allowed by wildcard rule");
}

#[test]
fn e11_rate_limit_rule() {
    use toloo_core::rules::RuleSet;

    let rules = serde_json::json!([
        {"t": "rate_limit", "who": "*", "max": 10, "window": 60000}
    ]);
    let rs = RuleSet::from_json(&rules);
    let arta = mk_node(ARTA_SIG_SEED_HEX, ARTA_ENC_SEED_HEX);

    // 9 events in window: at 9, max is 10 → allowed
    assert!(rs.check_rate_limit(&arta.sig.pub_key, 9), "9 events allows one more (9 <= 10)");
    // 11 events in window: over limit → denied
    assert!(!rs.check_rate_limit(&arta.sig.pub_key, 11), "11 events in window = over limit, denied (11 > 10)");
}

// ---- §E.13 Base64url Encoding ----

#[test]
fn e13_encoding_cases() {
    let v = vectors();
    let expected = vec![
        (vec![], ""),
        (vec![0x00u8], "AA"),
        (vec![0xffu8], "_w"),
        (vec![0x00u8, 0xff], "AP8"),
        (vec![0xde, 0xad, 0xbe, 0xef], "3q2-7w"),
    ];

    for (input_bytes, expected_b64) in &expected {
        let got = base64url::encode(input_bytes);
        assert_eq!(&got, expected_b64, "base64url({}) = {expected_b64}", hex::encode(input_bytes));
    }

    // 32 zero bytes → 43-character base64url
    let zeros = base64url::encode(&[0u8; 32]);
    assert_eq!(zeros.len(), 43);
    assert_eq!(zeros, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA");

    // vector set cases match
    for (hex_in, expected_out) in &v.e13_cases {
        if hex_in.is_empty() {
            assert!(expected_out.is_empty());
            continue;
        }
        let bytes = hex::decode(hex_in).unwrap();
        let got = base64url::encode(&bytes);
        assert_eq!(&got, expected_out, "mismatch for hex {hex_in}");
    }
}

#[test]
fn e13_roundtrip() {
    let inputs: &[&[u8]] = &[
        b"",
        &[0x00],
        &[0xff],
        &[0xde, 0xad, 0xbe, 0xef],
        &[0u8; 32],
        &[0u8; 64],
    ];
    for input in inputs {
        let encoded = base64url::encode(input);
        let decoded = base64url::decode(&encoded).unwrap();
        assert_eq!(&decoded, input, "base64url roundtrip failed");
    }
}

#[test]
fn e13_no_padding_chars() {
    let cases = &[b"a".as_ref(), b"ab", b"abc", b"abcd"];
    for input in cases {
        let encoded = base64url::encode(input);
        assert!(!encoded.contains('='), "base64url must not contain padding: {encoded}");
        assert!(!encoded.contains('+'), "base64url must not contain +: {encoded}");
        assert!(!encoded.contains('/'), "base64url must not contain /: {encoded}");
    }
}

// ---- §E.14 Canonical Envelope Ordering ----

#[test]
fn e14_envelope_canonical_d_before_p() {
    let v = vectors();
    let env_val = serde_json::to_value(&v.e4_1_envelope).unwrap();
    let canonical = canonical_bytes(&env_val).unwrap();
    let s = std::str::from_utf8(&canonical).unwrap();
    assert!(s.starts_with("{\"d\":"), "canonical envelope must start with {{\"d\": — got: {s}");
}
