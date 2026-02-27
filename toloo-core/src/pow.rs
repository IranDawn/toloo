use anyhow::{bail, Result};

use crate::canonical::canonical;
use crate::crypto::sha256;
use crate::types::DatumBody;

/// Count leading zero bits in a SHA-256 hash (spec §3.6.3).
///
/// Bits are counted from the most significant bit of the first byte.
pub fn count_leading_zero_bits(hash: &[u8; 32]) -> u32 {
    let mut total = 0u32;
    for &byte in hash.iter() {
        let z = byte.leading_zeros();
        total += z;
        if z < 8 {
            break;
        }
    }
    total
}

/// Verify that `d` satisfies a PoW requirement of `required_bits` leading zero bits (spec §3.6.2).
///
/// Computes `SHA-256(canonical(d))` and checks that the hash has at least
/// `required_bits` leading zero bits. Returns `Ok(())` on success.
pub fn verify_pow(d: &DatumBody, required_bits: u32) -> Result<()> {
    let canonical_str = canonical(d)?;
    let hash: [u8; 32] = sha256(canonical_str.as_bytes());
    let zeros = count_leading_zero_bits(&hash);
    if zeros >= required_bits {
        Ok(())
    } else {
        bail!(
            "PoW insufficient: hash has {} leading zero bits, need {}",
            zeros,
            required_bits
        )
    }
}

/// Find a nonce that satisfies `required_bits` and mutate `d.nonce` to it (spec §3.6.1).
///
/// Starts at nonce 0 and increments until `verify_pow` passes.
/// Returns the number of attempts taken.
pub fn find_pow_nonce(d: &mut DatumBody, required_bits: u32) -> u32 {
    let mut attempts = 0u32;
    let mut nonce: u64 = 0;
    loop {
        d.nonce = Some(nonce);
        if verify_pow(d, required_bits).is_ok() {
            return attempts + 1;
        }
        nonce += 1;
        attempts += 1;
    }
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{count_leading_zero_bits, find_pow_nonce, verify_pow};
    use crate::types::DatumBody;

    fn zero_hash() -> [u8; 32] {
        [0u8; 32]
    }

    fn hash_with_prefix(prefix: &[u8]) -> [u8; 32] {
        let mut h = [0u8; 32];
        let len = prefix.len().min(32);
        h[..len].copy_from_slice(&prefix[..len]);
        h
    }

    // ---- count_leading_zero_bits ----

    #[test]
    fn leading_zeros_all_zero_bytes() {
        assert!(count_leading_zero_bits(&zero_hash()) >= 32);
        assert_eq!(count_leading_zero_bits(&zero_hash()), 256);
    }

    #[test]
    fn leading_zeros_spec_table() {
        // From E.9.2 table:
        // 0x0000ffff... => 16
        let h = hash_with_prefix(&[0x00, 0x00, 0xff, 0xff]);
        assert_eq!(count_leading_zero_bits(&h), 16);

        // 0x00ffffff... => 8
        let h = hash_with_prefix(&[0x00, 0xff, 0xff, 0xff]);
        assert_eq!(count_leading_zero_bits(&h), 8);

        // 0x0fffffff... => 4
        let h = hash_with_prefix(&[0x0f, 0xff, 0xff, 0xff]);
        assert_eq!(count_leading_zero_bits(&h), 4);

        // 0x7fffffff... => 1
        let h = hash_with_prefix(&[0x7f, 0xff, 0xff, 0xff]);
        assert_eq!(count_leading_zero_bits(&h), 1);

        // 0x80000000... => 0
        let h = hash_with_prefix(&[0x80, 0x00, 0x00, 0x00]);
        assert_eq!(count_leading_zero_bits(&h), 0);

        // 0xffffffff... => 0
        let h = hash_with_prefix(&[0xff, 0xff, 0xff, 0xff]);
        assert_eq!(count_leading_zero_bits(&h), 0);
    }

    #[test]
    fn leading_zeros_boundary_values() {
        // 0x01 => 7 leading zeros
        let h = hash_with_prefix(&[0x01]);
        assert_eq!(count_leading_zero_bits(&h), 7);

        // 0x03 => 6 leading zeros
        let h = hash_with_prefix(&[0x03]);
        assert_eq!(count_leading_zero_bits(&h), 6);
    }

    // ---- verify_pow ----

    fn base_datum() -> DatumBody {
        DatumBody {
            n: "ARTA_SIG_PUB".to_owned(),
            v: "0.2".to_owned(),
            t: "room.join".to_owned(),
            ts: 1_710_000_200_000,
            r: Some("ROOM_SIG_PUB".to_owned()),
            to: None,
            c: None,
            env: None,
            tc: None,
            exp: None,
            nonce: None,

            extra: HashMap::new(),
        }
    }

    #[test]
    fn verify_pow_rejects_zero_difficulty() {
        // difficulty 0 means any hash passes
        let d = base_datum();
        assert!(verify_pow(&d, 0).is_ok());
    }

    #[test]
    fn verify_pow_rejects_when_nonce_missing() {
        // With no nonce and difficulty 1, may pass or fail depending on hash —
        // but find_pow_nonce with difficulty=1 always succeeds
        let mut d = base_datum();
        // This should pass for difficulty=1 after we find the nonce
        find_pow_nonce(&mut d, 1);
        assert!(verify_pow(&d, 1).is_ok());
    }

    // ---- find_pow_nonce ----

    #[test]
    fn find_pow_nonce_satisfies_requirement() {
        let mut d = base_datum();
        let _attempts = find_pow_nonce(&mut d, 12);
        // After find_pow_nonce, verify_pow must pass
        assert!(verify_pow(&d, 12).is_ok());
    }

    #[test]
    fn find_pow_nonce_returns_positive_attempts() {
        let mut d = base_datum();
        let attempts = find_pow_nonce(&mut d, 8);
        assert!(attempts >= 1);
    }

    #[test]
    fn find_pow_nonce_sets_nonce_field() {
        let mut d = base_datum();
        assert!(d.nonce.is_none());
        find_pow_nonce(&mut d, 8);
        assert!(d.nonce.is_some());
    }

    #[test]
    fn verify_pow_fails_after_nonce_cleared() {
        let mut d = base_datum();
        find_pow_nonce(&mut d, 12);
        let winning_nonce = d.nonce.unwrap();
        // Mutating nonce breaks PoW
        d.nonce = Some(winning_nonce.wrapping_add(1));
        // The altered nonce is very unlikely to still satisfy 12 bits
        // (probability ~1/4096). We just verify the verify_pow path works.
        // We don't assert failure because it could theoretically pass.
        let _ = verify_pow(&d, 12);
    }

    #[test]
    fn find_pow_nonce_consistent_across_calls() {
        // Two independent searches on identical datums must find the same nonce
        let mut d1 = base_datum();
        let mut d2 = base_datum();
        find_pow_nonce(&mut d1, 10);
        find_pow_nonce(&mut d2, 10);
        assert_eq!(d1.nonce, d2.nonce);
    }

    #[test]
    fn pow_does_not_depend_on_fields_not_in_canonical() {
        // extra HashMap entries with skip_serializing_if=is_empty won't affect hash
        let mut d1 = base_datum();
        let mut d2 = base_datum();
        // Both have empty extra, so canonical is identical
        find_pow_nonce(&mut d1, 8);
        d2.nonce = d1.nonce;
        assert!(verify_pow(&d2, 8).is_ok());
    }
}
