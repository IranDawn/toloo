use serde_json::Value;

/// A single room rule parsed from the `rules` array in channel -1 metadata.
///
/// Unknown rule types are represented as `Unknown` and skipped during evaluation
/// (spec §5.7.4 — implementations MUST skip unknown rule types, not error).
#[derive(Debug, Clone, PartialEq)]
pub enum Rule {
    /// `{"t": "join", "allow": "*"}` | `{"t": "join", "allow": [...]}` | `{"t": "join", "deny": [...]}`
    Join { who: RuleTarget, allow: bool },
    /// `{"t": "post", "allow": "*"}` | `"members"` | `[...]` | `{"t": "post", "deny": [...]}`
    Post { who: RuleTarget, allow: bool },
    /// `{"t": "invite_only", "inviters": [...]}`
    InviteOnly { inviters: Vec<String> },
    /// `{"t": "join_pow", "difficulty": N}`
    JoinPow { bits: u32 },
    /// `{"t": "post_pow", "difficulty": N}`
    PostPow { bits: u32 },
    /// `{"t": "rate_limit", "max": N, "per": N, "for": [...]?}`
    RateLimit { max: u32, per_ms: u64, for_nodes: Option<Vec<String>> },
    /// `{"t": "retention", "days": N}`
    Retention { days: u64 },
    /// `{"t": "uncommitted_ttl", "ms": N}`
    UncommittedTtl { ttl_ms: u64 },
    /// Any rule type not recognized by this implementation (skipped).
    Unknown,
}

/// Who a rule applies to.
#[derive(Debug, Clone, PartialEq)]
pub enum RuleTarget {
    /// `"*"` — applies to everyone.
    Anyone,
    /// `"members"` — applies to current room members only.
    Members,
    /// Specific list of node public keys.
    List(Vec<String>),
}

impl RuleTarget {
    /// Returns true if `node` is matched by this target.
    /// `members` is the current membership set for `Members` evaluation.
    pub fn matches(&self, node: &str, members: &[&str]) -> bool {
        match self {
            RuleTarget::Anyone => true,
            RuleTarget::Members => members.contains(&node),
            RuleTarget::List(list) => list.iter().any(|s| s == node),
        }
    }
}

/// The full set of rules for a room. Evaluated last-matching-rule-wins (spec §5.7.3).
#[derive(Debug, Clone, Default)]
pub struct RuleSet(Vec<Rule>);

impl RuleSet {
    /// Parse rules from a JSON array (the `rules` field of a room.create / room.update content).
    /// Unknown rule types are silently skipped (§5.7.4).
    pub fn from_json(rules_value: &Value) -> Self {
        let rules = rules_value
            .as_array()
            .map(|arr| arr.iter().map(parse_rule).collect())
            .unwrap_or_default();
        RuleSet(rules)
    }

    /// Whether joining is currently allowed (for any node — use `can_join_node` for per-node).
    /// Default: DENY if no matching rule.
    pub fn can_join(&self) -> bool {
        self.can_join_node("*", &[])
    }

    /// Whether `node` may join, given `members` for membership-based rules.
    /// Last matching `join` or `invite_only` rule wins. Default: DENY.
    pub fn can_join_node(&self, node: &str, members: &[&str]) -> bool {
        let mut result = false; // default DENY
        for rule in &self.0 {
            match rule {
                Rule::Join { who, allow } if who.matches(node, members) => {
                    result = *allow;
                }
                Rule::InviteOnly { .. } => {
                    // invite_only doesn't directly set allow/deny for join evaluation here —
                    // it's a prerequisite check handled at the relay level.
                    // But treat its presence as a restrict signal for the default path.
                }
                _ => {}
            }
        }
        result
    }

    /// Whether posting is currently allowed (for any node).
    /// Default: DENY if no matching rule.
    pub fn can_post(&self) -> bool {
        self.can_post_node("*", &[])
    }

    /// Whether `node` may post, given `members` for membership-based rules.
    /// Last matching `post` rule wins. Default: DENY.
    pub fn can_post_node(&self, node: &str, members: &[&str]) -> bool {
        let mut result = false; // default DENY
        for rule in &self.0 {
            if let Rule::Post { who, allow } = rule {
                if who.matches(node, members) {
                    result = *allow;
                }
            }
        }
        result
    }

    /// Returns the PoW difficulty required for joining, if any `join_pow` rule is present.
    /// If multiple `join_pow` rules exist, the last one wins.
    pub fn required_join_pow(&self) -> Option<u32> {
        let mut bits = None;
        for rule in &self.0 {
            if let Rule::JoinPow { bits: b } = rule {
                bits = Some(*b);
            }
        }
        bits
    }

    /// Returns the PoW difficulty required for posting, if any `post_pow` rule is present.
    pub fn required_post_pow(&self) -> Option<u32> {
        let mut bits = None;
        for rule in &self.0 {
            if let Rule::PostPow { bits: b } = rule {
                bits = Some(*b);
            }
        }
        bits
    }

    /// Returns the rate limit as (max_events, per_ms), if any `rate_limit` rule is present.
    /// The last matching rule wins (or the last rule if `for_nodes` is `None`).
    /// Caller passes `node` to check node-specific limits.
    pub fn max_events_per_hour(&self) -> Option<u32> {
        // Simplified: return the last rate_limit that applies to everyone (no `for_nodes`).
        let mut result = None;
        for rule in &self.0 {
            if let Rule::RateLimit { max, per_ms: _, for_nodes: None } = rule {
                result = Some(*max);
            }
        }
        result
    }

    /// Check if a node is within rate limits given its recent event count in the window.
    /// Returns true (allowed) if within limits, false if exceeded.
    pub fn check_rate_limit(&self, node: &str, events_in_window: u32) -> bool {
        let mut result = true; // no rate limit = allow
        for rule in &self.0 {
            if let Rule::RateLimit { max, per_ms: _, for_nodes } = rule {
                let applies = match for_nodes {
                    None => true,
                    Some(list) => list.iter().any(|s| s == node),
                };
                if applies {
                    result = events_in_window <= *max;
                }
            }
        }
        result
    }

    /// Whether this room requires an invitation to join.
    pub fn is_invite_only(&self) -> bool {
        self.0.iter().any(|r| matches!(r, Rule::InviteOnly { .. }))
    }

    /// Returns the inviters list if an `invite_only` rule is present.
    pub fn invite_only_inviters(&self) -> Option<&Vec<String>> {
        self.0.iter().rev().find_map(|r| {
            if let Rule::InviteOnly { inviters } = r {
                Some(inviters)
            } else {
                None
            }
        })
    }

    /// Returns the retention period in days, if a `retention` rule is present.
    pub fn retention_days(&self) -> Option<u64> {
        let mut days = None;
        for rule in &self.0 {
            if let Rule::Retention { days: d } = rule {
                days = Some(*d);
            }
        }
        days
    }

    /// Returns the uncommitted TTL in milliseconds, if an `uncommitted_ttl` rule is present.
    pub fn uncommitted_ttl_ms(&self) -> Option<u64> {
        let mut ttl = None;
        for rule in &self.0 {
            if let Rule::UncommittedTtl { ttl_ms } = rule {
                ttl = Some(*ttl_ms);
            }
        }
        ttl
    }

    /// Returns all rules (for inspection / testing).
    pub fn rules(&self) -> &[Rule] {
        &self.0
    }
}

fn parse_rule(v: &Value) -> Rule {
    let t = match v.get("t").and_then(Value::as_str) {
        Some(t) => t,
        None => return Rule::Unknown,
    };

    match t {
        "join" => parse_access_rule(v, true),
        "post" => parse_access_rule(v, false),
        "invite_only" => {
            let inviters = string_array(v.get("inviters"));
            Rule::InviteOnly { inviters }
        }
        "join_pow" => {
            let bits = v.get("difficulty").and_then(Value::as_u64).unwrap_or(0) as u32;
            Rule::JoinPow { bits }
        }
        "post_pow" => {
            let bits = v.get("difficulty").and_then(Value::as_u64).unwrap_or(0) as u32;
            Rule::PostPow { bits }
        }
        "rate_limit" => {
            let max = v.get("max").and_then(Value::as_u64).unwrap_or(0) as u32;
            let per_ms = v.get("per").and_then(Value::as_u64).unwrap_or(0);
            let for_nodes = v.get("for").map(|f| string_array(Some(f)));
            Rule::RateLimit { max, per_ms, for_nodes }
        }
        "retention" => {
            let days = v.get("days").and_then(Value::as_u64).unwrap_or(0);
            Rule::Retention { days }
        }
        "uncommitted_ttl" => {
            let ttl_ms = v.get("ms").and_then(Value::as_u64).unwrap_or(0);
            Rule::UncommittedTtl { ttl_ms }
        }
        _ => Rule::Unknown,
    }
}

/// Parse a `join` or `post` access rule.
fn parse_access_rule(v: &Value, is_join: bool) -> Rule {
    // allow can be "*", "members", or an array of node keys
    if let Some(allow_val) = v.get("allow") {
        let (who, allow) = parse_target(allow_val);
        return if is_join {
            Rule::Join { who, allow }
        } else {
            Rule::Post { who, allow }
        };
    }
    // deny field — list of denied nodes
    if let Some(deny_val) = v.get("deny") {
        let who = RuleTarget::List(string_array(Some(deny_val)));
        return if is_join {
            Rule::Join { who, allow: false }
        } else {
            Rule::Post { who, allow: false }
        };
    }
    Rule::Unknown
}

fn parse_target(v: &Value) -> (RuleTarget, bool) {
    match v {
        Value::String(s) if s == "*" => (RuleTarget::Anyone, true),
        Value::String(s) if s == "members" => (RuleTarget::Members, true),
        Value::Array(_) => (RuleTarget::List(string_array(Some(v))), true),
        _ => (RuleTarget::Anyone, false),
    }
}

fn string_array(v: Option<&Value>) -> Vec<String> {
    v.and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(|item| item.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::{Rule, RuleSet, RuleTarget};
    use serde_json::json;

    // ---- parse_rule ----

    #[test]
    fn parse_join_allow_star() {
        let rs = RuleSet::from_json(&json!([{"t": "join", "allow": "*"}]));
        assert_eq!(rs.rules(), &[Rule::Join { who: RuleTarget::Anyone, allow: true }]);
    }

    #[test]
    fn parse_post_allow_members() {
        let rs = RuleSet::from_json(&json!([{"t": "post", "allow": "members"}]));
        assert_eq!(rs.rules(), &[Rule::Post { who: RuleTarget::Members, allow: true }]);
    }

    #[test]
    fn parse_join_deny_list() {
        let rs = RuleSet::from_json(&json!([{"t": "join", "deny": ["SIG_A"]}]));
        assert_eq!(
            rs.rules(),
            &[Rule::Join { who: RuleTarget::List(vec!["SIG_A".to_owned()]), allow: false }]
        );
    }

    #[test]
    fn parse_invite_only() {
        let rs = RuleSet::from_json(&json!([{"t": "invite_only", "inviters": ["SIG_CREATOR"]}]));
        assert_eq!(
            rs.rules(),
            &[Rule::InviteOnly { inviters: vec!["SIG_CREATOR".to_owned()] }]
        );
    }

    #[test]
    fn parse_join_pow_and_post_pow() {
        let rs = RuleSet::from_json(&json!([
            {"t": "join_pow", "difficulty": 20},
            {"t": "post_pow", "difficulty": 16}
        ]));
        assert_eq!(rs.rules()[0], Rule::JoinPow { bits: 20 });
        assert_eq!(rs.rules()[1], Rule::PostPow { bits: 16 });
    }

    #[test]
    fn parse_rate_limit() {
        let rs = RuleSet::from_json(&json!([{"t": "rate_limit", "max": 10, "per": 60000}]));
        assert_eq!(
            rs.rules(),
            &[Rule::RateLimit { max: 10, per_ms: 60000, for_nodes: None }]
        );
    }

    #[test]
    fn parse_rate_limit_with_for() {
        let rs = RuleSet::from_json(
            &json!([{"t": "rate_limit", "max": 100, "per": 60000, "for": ["SIG_ADMIN"]}]),
        );
        assert_eq!(
            rs.rules(),
            &[Rule::RateLimit {
                max: 100, per_ms: 60000,
                for_nodes: Some(vec!["SIG_ADMIN".to_owned()])
            }]
        );
    }

    #[test]
    fn parse_retention_and_uncommitted_ttl() {
        let rs = RuleSet::from_json(&json!([
            {"t": "retention", "days": 90},
            {"t": "uncommitted_ttl", "ms": 86400000}
        ]));
        assert_eq!(rs.rules()[0], Rule::Retention { days: 90 });
        assert_eq!(rs.rules()[1], Rule::UncommittedTtl { ttl_ms: 86400000 });
    }

    #[test]
    fn unknown_rule_type_is_skipped() {
        let rs = RuleSet::from_json(&json!([
            {"t": "future_rule", "foo": "bar"},
            {"t": "join", "allow": "*"}
        ]));
        // Unknown rules are kept as Unknown variant — they don't affect evaluation.
        assert_eq!(rs.rules().len(), 2);
        assert_eq!(rs.rules()[0], Rule::Unknown);
        assert_eq!(rs.rules()[1], Rule::Join { who: RuleTarget::Anyone, allow: true });
    }

    #[test]
    fn empty_rules_array_denies_all() {
        let rs = RuleSet::from_json(&json!([]));
        assert!(!rs.can_join(), "empty rules default to DENY join");
        assert!(!rs.can_post(), "empty rules default to DENY post");
    }

    // ---- Rule evaluation: last-matching-rule-wins (§5.7.3) ----

    #[test]
    fn last_matching_rule_wins_for_join() {
        // Rule 1: allow all. Rule 2: deny specific node. Rule 3: allow specific node.
        let arta = "ARTA_SIG";
        let rs = RuleSet::from_json(&json!([
            {"t": "join", "allow": "*"},
            {"t": "join", "deny": [arta]},
            {"t": "join", "allow": [arta]}
        ]));
        // Last match for Arta is rule 3 (allow) → ALLOW
        assert!(rs.can_join_node(arta, &[]));
    }

    #[test]
    fn test_vector_e11_last_matching_rule_wins() {
        // §E.11.1: post rules — last matching rule for Arta is deny, for Babak is allow.
        let arta = "ARTA_SIG";
        let babak = "BABAK_SIG";
        let rs = RuleSet::from_json(&json!([
            {"t": "post", "allow": "*"},
            {"t": "post", "deny": [arta]}
        ]));
        // Evaluation for Arta: rule1 matches (allow), rule2 matches (deny) → last = DENY
        assert!(!rs.can_post_node(arta, &[]));
        // Evaluation for Babak: rule1 matches (allow), rule2 doesn't → last = ALLOW
        assert!(rs.can_post_node(babak, &[]));
    }

    #[test]
    fn post_allow_members_only() {
        let arta = "ARTA_SIG";
        let babak = "BABAK_SIG";
        let rs = RuleSet::from_json(&json!([{"t": "post", "allow": "members"}]));
        assert!(rs.can_post_node(arta, &[arta, babak]));
        assert!(!rs.can_post_node("STRANGER", &[arta, babak]));
    }

    #[test]
    fn required_pow_accessors() {
        let rs = RuleSet::from_json(&json!([
            {"t": "join_pow", "difficulty": 20},
            {"t": "post_pow", "difficulty": 16}
        ]));
        assert_eq!(rs.required_join_pow(), Some(20));
        assert_eq!(rs.required_post_pow(), Some(16));
    }

    #[test]
    fn rate_limit_check() {
        let rs = RuleSet::from_json(&json!([{"t": "rate_limit", "max": 10, "per": 60000}]));
        assert_eq!(rs.max_events_per_hour(), Some(10));
        assert!(rs.check_rate_limit("any_node", 10));  // at limit = allow
        assert!(!rs.check_rate_limit("any_node", 11)); // over limit = deny
    }

    #[test]
    fn invite_only_detection() {
        let rs = RuleSet::from_json(&json!([{"t": "invite_only", "inviters": ["SIG_CREATOR"]}]));
        assert!(rs.is_invite_only());
        assert_eq!(
            rs.invite_only_inviters().map(|v| v.as_slice()),
            Some(&["SIG_CREATOR".to_owned()][..])
        );
    }

}
