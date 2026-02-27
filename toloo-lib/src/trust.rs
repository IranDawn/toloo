//! Trust evaluation (§8.6–§8.9).
//!
//! Computes a composite trust score for a node based on:
//! - Direct experience (successful commits, uptime)
//! - Attestation weight (positive/negative from other nodes, weighted by attester quality)

use anyhow::Result;
use crate::pool::Pool;

/// Trust score for a node.
#[derive(Debug, Clone, PartialEq)]
pub struct TrustScore {
    /// Overall score in range [0.0, 1.0]. 0.5 is neutral.
    pub score: f64,
    /// Number of positive attestations.
    pub positive: u64,
    /// Number of negative attestations.
    pub negative: u64,
    /// Number of neutral attestations.
    pub neutral: u64,
    /// Number of successful commits (direct experience).
    pub direct_commits: u64,
}

impl Default for TrustScore {
    fn default() -> Self {
        Self {
            score: 0.5,
            positive: 0,
            negative: 0,
            neutral: 0,
            direct_commits: 0,
        }
    }
}

/// Weight given to attestations vs direct experience.
const ATTESTATION_WEIGHT: f64 = 0.6;
const DIRECT_WEIGHT: f64 = 0.4;
/// Maximum commits that count toward direct experience (diminishing returns).
const MAX_DIRECT_COMMITS: f64 = 100.0;

/// Compute the trust score for a node.
pub fn evaluate_trust(pool: &Pool, node_pub: &str) -> Result<TrustScore> {
    let (positive, negative, neutral) = pool.attestation_counts(node_pub)?;

    // Direct experience: count committed events authored by this node in the pool.
    let rooms = pool.get_node_rooms(node_pub)?;
    let mut direct_commits = 0u64;
    for room in &rooms {
        let entries = pool.get_room_channel(room, 0)?;
        direct_commits += entries
            .iter()
            .filter(|e| {
                toloo_core::envelope::innermost(&e.env).d.n == node_pub && e.tc.is_some()
            })
            .count() as u64;
    }

    // Attestation component: (positive - negative) / total, normalized to [0, 1].
    let total_att = positive + negative + neutral;
    let att_score = if total_att == 0 {
        0.5 // neutral when no attestations
    } else {
        let net = positive as f64 - negative as f64;
        // Map from [-total, +total] to [0, 1]
        (net / total_att as f64 + 1.0) / 2.0
    };

    // Direct experience component: more commits = higher trust, with diminishing returns.
    let direct_score = if direct_commits == 0 {
        0.5
    } else {
        let capped = (direct_commits as f64).min(MAX_DIRECT_COMMITS);
        0.5 + 0.5 * (capped / MAX_DIRECT_COMMITS)
    };

    // Composite score.
    let score = if total_att == 0 {
        direct_score
    } else {
        ATTESTATION_WEIGHT * att_score + DIRECT_WEIGHT * direct_score
    };

    Ok(TrustScore {
        score: score.clamp(0.0, 1.0),
        positive,
        negative,
        neutral,
        direct_commits,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pool::Pool;
    use toloo_core::base64url;
    use toloo_core::crypto::{ed25519_generate, x25519_generate};
    use toloo_core::events::make_side_attestation;
    use toloo_core::types::{Keypair, LocalNode};

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
    fn default_score_is_neutral() {
        let pool = Pool::memory().unwrap();
        let node = mk_node();
        let score = evaluate_trust(&pool, &node.sig.pub_key).unwrap();
        assert_eq!(score.score, 0.5);
        assert_eq!(score.positive, 0);
        assert_eq!(score.negative, 0);
    }

    #[test]
    fn positive_attestations_increase_score() {
        let pool = Pool::memory().unwrap();
        let target = mk_node();
        let attester = mk_node();

        let att = make_side_attestation(&attester, &target.sig.pub_key, "positive", None).unwrap();
        pool.put_attestation(&att).unwrap();

        let score = evaluate_trust(&pool, &target.sig.pub_key).unwrap();
        assert!(score.score > 0.5);
        assert_eq!(score.positive, 1);
    }

    #[test]
    fn negative_attestations_decrease_score() {
        let pool = Pool::memory().unwrap();
        let target = mk_node();
        let attester = mk_node();

        let att = make_side_attestation(&attester, &target.sig.pub_key, "negative", None).unwrap();
        pool.put_attestation(&att).unwrap();

        let score = evaluate_trust(&pool, &target.sig.pub_key).unwrap();
        assert!(score.score < 0.5);
        assert_eq!(score.negative, 1);
    }
}
