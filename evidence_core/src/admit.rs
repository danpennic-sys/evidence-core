//! admit — pure admission predicate.
//!
//! Decides whether an EvidencePack may enter the chain.
//! No I/O. No clocks. No network. Deterministic.
//!
//! This is the constitution in executable form for the current substrate layer.

use crate::EvidencePack;
use crate::verify::{verify_pack, Replayable, VerificationResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Outcome of the admission predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdmitDecision {
    /// Pack is admitted. Ready for SignedAtom envelope + chain-head link.
    Accept {
        pack_id: String,
        reason: String,
    },
    /// Pack is refused. Must not enter the chain.
    Reject {
        pack_id: String,
        reasons: Vec<String>,
    },
}

impl AdmitDecision {
    pub fn is_accepted(&self) -> bool {
        matches!(self, AdmitDecision::Accept { .. })
    }
}

/// Policy controls that the caller may tighten.
/// Defaults are deliberately strict for the current substrate.
#[derive(Debug, Clone)]
pub struct AdmitPolicy {
    /// Allowed service names. Empty = any non-empty service is allowed.
    pub allowed_services: HashSet<String>,
    /// Required invariants that must appear in the pack.
    /// Keyed by service name → list of required invariant codes.
    pub required_invariants: std::collections::HashMap<String, Vec<String>>,
    /// If true, signature must not be empty or the placeholder.
    pub require_real_signature: bool,
    /// If true, runtime_context fields must be non-empty.
    pub require_runtime_context: bool,
    /// If true, hash_chain.current_hash must equal the recomputed hash.
    pub require_hash_integrity: bool,
}

impl Default for AdmitPolicy {
    fn default() -> Self {
        let mut required = std::collections::HashMap::new();
        required.insert(
            "stripe".into(),
            vec![
                "STRIPE-001".into(),
                "STRIPE-002".into(),
                "STRIPE-003".into(),
                "STRIPE-004".into(),
            ],
        );
        required.insert(
            "time".into(),
            vec!["TZ-001".into(), "TZ-002".into(), "TZ-003".into()],
        );
        required.insert(
            "geo".into(),
            vec!["GEO-001".into(), "GEO-002".into(), "GEO-003".into()],
        );

        AdmitPolicy {
            allowed_services: HashSet::from([
                "time".into(),
                "geo".into(),
                "date".into(),
                "ipdiag".into(),
                "media".into(),
                "stripe".into(),
            ]),
            required_invariants: required,
            require_real_signature: false, // soft until keys land
            require_runtime_context: true,
            require_hash_integrity: true,
        }
    }
}

/// Pure admission predicate.
///
/// Steps (in order):
/// 1. Structural completeness (pack_id, service, versions, hash_chain)
/// 2. Service allow-list
/// 3. Required invariants for that service
/// 4. Hash integrity (recompute == stored)
/// 5. Runtime context presence
/// 6. Signature presence (policy-controlled)
/// 7. Optional live replay (if a Replayable is supplied)
///
/// Returns Accept only when every enforced check passes.
pub fn admit(
    pack: &EvidencePack,
    policy: &AdmitPolicy,
    replayer: Option<&dyn Replayable>,
) -> AdmitDecision {
    let mut reasons: Vec<String> = Vec::new();

    // ------------------------------------------------------------------
    // 1. Structural completeness
    // ------------------------------------------------------------------
    if pack.pack_id.is_empty() {
        reasons.push("pack_id empty".into());
    }
    if pack.service.is_empty() {
        reasons.push("service empty".into());
    }
    if pack.service_version.is_empty() {
        reasons.push("service_version empty".into());
    }
    if pack.gateway_version.is_empty() {
        reasons.push("gateway_version empty".into());
    }
    if pack.hash_chain.current_hash.is_empty() {
        reasons.push("hash_chain.current_hash empty".into());
    }
    if pack.pack_id != pack.hash_chain.current_hash {
        reasons.push("pack_id != hash_chain.current_hash".into());
    }

    // ------------------------------------------------------------------
    // 2. Service allow-list
    // ------------------------------------------------------------------
    if !policy.allowed_services.is_empty()
        && !policy.allowed_services.contains(&pack.service)
    {
        reasons.push(format!("service '{}' not in allow-list", pack.service));
    }

    // ------------------------------------------------------------------
    // 3. Required invariants
    // ------------------------------------------------------------------
    if let Some(required) = policy.required_invariants.get(&pack.service) {
        for code in required {
            if !pack.invariants.contains(code) {
                reasons.push(format!("missing required invariant: {}", code));
            }
        }
    }

    // ------------------------------------------------------------------
    // 4. Hash integrity (via the existing pure verifier)
    // ------------------------------------------------------------------
    if policy.require_hash_integrity {
        // We call verify_pack without a replayer first so we only pay for hash + structure.
        let v: VerificationResult = verify_pack(pack, None::<&NullReplayer>, None);
        if !v.checks.iter().any(|c| c.name == "hash_chain" && c.passed) {
            reasons.push(format!(
                "hash integrity failed: stored={} recomputed={}",
                v.original_hash, v.recomputed_hash
            ));
        }
    }

    // ------------------------------------------------------------------
    // 5. Runtime context
    // ------------------------------------------------------------------
    if policy.require_runtime_context {
        if pack.runtime_context.node_id.is_empty()
            || pack.runtime_context.pod_id.is_empty()
            || pack.runtime_context.region.is_empty()
        {
            reasons.push("runtime_context incomplete".into());
        }
    }

    // ------------------------------------------------------------------
    // 6. Signature
    // ------------------------------------------------------------------
    if policy.require_real_signature {
        if pack.signature.is_empty() || pack.signature == "signature_placeholder" {
            reasons.push("signature missing or still placeholder".into());
        }
    }

    // ------------------------------------------------------------------
    // 7. Optional live replay
    // ------------------------------------------------------------------
    if let Some(r) = replayer {
        let v = verify_pack(pack, Some(r), None);
        if let Some(check) = v.checks.iter().find(|c| c.name == "response_replay") {
            if !check.passed {
                reasons.push(format!("replay failed: {}", check.detail));
            }
        }
    }

    // ------------------------------------------------------------------
    // Decision
    // ------------------------------------------------------------------
    if reasons.is_empty() {
        AdmitDecision::Accept {
            pack_id: pack.pack_id.clone(),
            reason: "all admission checks passed".into(),
        }
    } else {
        AdmitDecision::Reject {
            pack_id: pack.pack_id.clone(),
            reasons,
        }
    }
}

/// Null replayer used when we only need the hash check inside admit.
struct NullReplayer;
impl Replayable for NullReplayer {
    fn replay(&self, _request: &serde_json::Value) -> Result<serde_json::Value, String> {
        Err("null replayer".into())
    }
}

/// Convenience: admit with the default policy and no replayer.
pub fn admit_default(pack: &EvidencePack) -> AdmitDecision {
    admit(pack, &AdmitPolicy::default(), None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{HashChain, RuntimeContext};
    use serde_json::json;

    fn minimal_valid_pack() -> EvidencePack {
        // Build a pack the same way the library does so the hash matches.
        EvidencePack::new(
            "stripe",
            "v20261008-A",
            "v20261008-G",
            json!({"path": "/stripe/webhook/checkout.session.completed", "body": {}}),
            json!({"session_id": "cs_test_1", "amount": 1000}),
            vec![
                "STRIPE-001".into(),
                "STRIPE-002".into(),
                "STRIPE-003".into(),
                "STRIPE-004".into(),
            ],
            "GENESIS".into(),
            RuntimeContext {
                node_id: "node-1".into(),
                pod_id: "pod-1".into(),
                region: "us-central-1".into(),
            },
            "signature_placeholder".into(),
        )
    }

    #[test]
    fn admit_accepts_well_formed_stripe_pack() {
        let pack = minimal_valid_pack();
        let decision = admit_default(&pack);
        assert!(decision.is_accepted(), "{:?}", decision);
    }

    #[test]
    fn admit_rejects_unknown_service() {
        let mut pack = minimal_valid_pack();
        pack.service = "unknown-svc".into();
        // recompute hash so structural check still passes hash, but allow-list fails
        let decision = admit_default(&pack);
        assert!(!decision.is_accepted());
        if let AdmitDecision::Reject { reasons, .. } = decision {
            assert!(reasons.iter().any(|r| r.contains("allow-list")));
        }
    }

    #[test]
    fn admit_rejects_missing_invariant() {
        let mut pack = minimal_valid_pack();
        pack.invariants.retain(|i| i != "STRIPE-002");
        let decision = admit_default(&pack);
        assert!(!decision.is_accepted());
        if let AdmitDecision::Reject { reasons, .. } = decision {
            assert!(reasons.iter().any(|r| r.contains("STRIPE-002")));
        }
    }
}
