# TODO — Spec Gaps & Missing Features

Tracks features required for full Relay conformance (§D.6) that are
currently absent or stubbed. Items are ordered by implementation
dependency — later items may depend on earlier ones.

---

## 1. ✅ TOFU Pin Storage — §4.4, §11.3.1

**Crate:** `toloo-lib` (pool)

- [x] `tofu_pins` table in SQLite schema
- [x] `check_tofu_pin()` — first-seen recording, match/mismatch detection
- [x] `get_tofu_pin()` — query stored pin
- [x] Unit tests: new pin → match, fingerprint change → mismatch

---

## 2. ✅ Attestations — §8.3–§8.5

**Crate:** `toloo-core` (event builder) + `toloo-lib` (storage + pool)

- [x] `make_side_attestation()` event builder with level validation
- [x] `attestations` table in SQLite schema
- [x] `put_attestation()` / `get_attestations_for()` / `attestation_counts()`
- [x] Attestation routing in `pool.exchange` ingest
- [x] Content validation in `validate_event_content()`
- [x] Unit tests: builder shape, invalid level rejection, store/query, counts

---

## 3. ✅ Trust Evaluation — §8.6–§8.9

**Crate:** `toloo-lib` (trust module)

- [x] `TrustScore` struct with composite scoring
- [x] `evaluate_trust()` — attestation weight + direct experience
- [x] Attester-quality weighting via composite formula
- [x] Unit tests: neutral default, positive/negative attestation effects

---

## 4. ✅ Storage Pruning — §11.5

**Crate:** `toloo-lib` (pool) + `toloo-core` (rules)

- [x] `prune_retention()` — delete events older than retention window
- [x] `prune_uncommitted()` — expire uncommitted events past TTL
- [x] `prune_room()` — rule-driven pruning using `RuleSet`
- [x] `retention_days()` / `uncommitted_ttl_ms()` accessors on `RuleSet`

---

## 5. ✅ Blob Piece Storage — §11.7

**Crate:** `toloo-lib` (pool + handlers)

- [x] `blob_pieces` table in SQLite schema
- [x] `put_blob_piece()` / `get_blob_piece()` / `get_blob()` / `blob_piece_count()`
- [x] `blob.fetch` handler (single piece + metadata query)
- [x] Unit tests: store, fetch, ordered retrieval, count mismatch

---

## 6. ✅ Side-Events — §6, §14.5.3

**Crate:** `toloo-core` (builders) + `toloo-lib` (pool)

- [x] `make_side_fork()` event builder
- [x] `make_side_attestation()` event builder
- [x] Content validation for both side-event types
- [x] Side-event routing in `pool.exchange` ingest
- [x] Unit tests: builder shape, validation

---

## 7. ✅ Local Moderation — §13.3

**Crate:** `toloo-lib` (pool + handlers)

- [x] `blocklist` table with kind column (block/spam)
- [x] `block_node()` / `unblock_node()` / `is_blocked()` / `get_blocklist()`
- [x] Blocked-node filtering on `pool.exchange` ingest (reject events)
- [x] Blocked-node filtering on `pool.exchange` outbound (exclude from sync)
- [x] Unit tests: block, unblock, list

---

## 8. ✅ room.flag — §13.8

**Crate:** `toloo-core` (event builder) + `toloo-lib` (aggregation)

- [x] `make_room_flag()` event builder
- [x] `room_flags` table in SQLite schema
- [x] `put_flag()` / `flag_count()` / `flag_counts_by_category()`
- [x] Flag routing in `pool.exchange` ingest
- [x] Content validation for room.flag
- [x] Unit tests: builder shape, store, count, count-by-category

---

## 9. ✅ Export / Import — §11.10

**Crate:** `toloo-lib` (pool)

- [x] `export_room()` — export all envelopes for a room
- [x] `import_envelopes()` — validate signatures and import
- [x] Unit tests: export → import roundtrip

---

## 10. ✅ room.migrate — §14.4.2

**Crate:** `toloo-core` (event builder)

- [x] `make_room_migrate()` event builder
- [x] Content validation (new_room required)
- [x] Unit tests: builder shape, validation

---

## 11. ✅ obfs4/meek Transports — §9, §D.13.4

**Crate:** `toloo-lib` (transport/pluggable)

- [x] `PluggableTransport` trait (connect + accept)
- [x] `Obfs4Stub` / `MeekStub` implementations (return Unsupported)
- [x] `TransportRegistry` for runtime transport selection
- [x] Unit tests: registry, stub error behavior
- [ ] **Future:** Replace stubs with real obfs4/meek implementations

---

## 12. ✅ Key Zeroization — §D.15.1

**Crate:** `toloo-core` (types)

- [x] `Zeroize` + `ZeroizeOnDrop` derived on `Keypair`, `LocalNode`, `LocalRoom`
- [x] `zeroize` crate already used in `crypto.rs` for intermediate key material
- [x] Private key strings zeroed on drop

---

## 13. ✅ Encrypted-at-Rest Keys — §D.15.2

**Crate:** `toloo-core` (keystore module)

- [x] Argon2id KDF for passphrase → encryption key
- [x] `encrypt_key()` — wrap private key with ChaCha20-Poly1305
- [x] `decrypt_key()` — unwrap with passphrase
- [x] Random salt + nonce per encryption
- [x] Unit tests: roundtrip, wrong passphrase, empty passphrase, unique blobs

---

## 14. ✅ Retry with Backoff — §D.14

**Crate:** `toloo-lib` (transport/backoff)

- [x] `BackoffConfig` — initial delay, max delay, max retries, jitter
- [x] `Backoff` state tracker with `next_delay()` / `reset()`
- [x] Exponential growth with configurable cap
- [x] Jitter via xorshift64 PRNG
- [x] Unit tests: exponential growth, cap, max retries, reset, jitter variation
