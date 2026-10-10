//! admit — pure admission predicate.
//!
//! Decides whether an EvidencePack or SignedAtom may enter the chain.
//! No I/O. No clocks. No network. Deterministic.
//!
//! This is the constitution in executable form for the current substrate layer.

use crate::atom::SignedAtom;
use crate::EvidencePack;
use crate::verify::{verify_pack, Replayable, VerificationResult};
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

/// Outcome of the admission predicate.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum AdmitDecision {
    /// Admitted. Ready for chain-head link (or already enveloped).
    Accept {
        pack_id: String,
        /// Present when the subject was a SignedAtom.
        atom_id: Option<String>,
        reason: String,
    },
    /// Refused. Must not enter the chain.
    Reject {
        pack_id: String,
        atom_id: Option<String>,
        reasons: Vec<String>,
    },
}

impl AdmitDecision {
    pub fn is_accepted(&self) -> bool {
        matches!(self, AdmitDecision::Accept { .. })
    }
}

/// Policy controls that the caller may tighten or relax.
#[derive(Debug, Clone)]
pub struct AdmitPolicy {
    /// Allowed service names. Empty = any non-empty service is allowed.
    pub allowed_services: HashSet<String>,
    /// Required invariants keyed by service name.
    pub required_invariants: std::collections::HashMap<String, Vec<String>>,
    /// If true, body signature must not be empty or the placeholder.
    pub require_real_signature: bool,
    /// If true, runtime_context fields must be non-empty.
    pub require_runtime_context: bool,
    /// If true, hash_chain.current_hash must equal the recomputed hash.
    pub require_hash_integrity: bool,
    /// If true, SignedAtom.signature must not be empty or the placeholder.
    pub require_atom_signature: bool,
}

/// Default = pure admission boundary:
/// hash-checked, signatures required, no runtime-context requirement, no replay.
/// Service allow-list and invariant sets are prefilled for known services.
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
            require_real_signature: true,
            require_runtime_context: false,
            require_hash_integrity: true,
            require_atom_signature: true,
        }
    }
}

/// Soft policy for tests / pre-key era: signatures not required.
pub fn policy_soft_signatures() -> AdmitPolicy {
    let mut p = AdmitPolicy::default();
    p.require_real_signature = false;
    p.require_atom_signature = false;
    p
}

/// Pure admission predicate for an EvidencePack (body only).
///
/// Steps (in order):
/// 1. Structural completeness
/// 2. Service allow-list
/// 3. Required invariants
/// 4. Hash integrity
/// 5. Runtime context (policy)
/// 6. Body signature (policy)
/// 7. Optional live replay
pub fn admit(
    pack: &EvidencePack,
    policy: &AdmitPolicy,
    replayer: Option<&dyn Replayable>,
) -> AdmitDecision {
    let mut reasons: Vec<String> = Vec::new();

    // 1. Structural completeness
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

    // 2. Service allow-list
    if !policy.allowed_services.is_empty()
        && !policy.allowed_services.contains(&pack.service)
    {
        reasons.push(format!("service '{}' not in allow-list", pack.service));
    }

    // 3. Required invariants
    if let Some(required) = policy.required_invariants.get(&pack.service) {
        for code in required {
            if !pack.invariants.contains(code) {
                reasons.push(format!("missing required invariant: {}", code));
            }
        }
    }

    // 4. Hash integrity
    if policy.require_hash_integrity {
        let v: VerificationResult = verify_pack(pack, None::<&NullReplayer>, None);
        if !v.checks.iter().any(|c| c.name == "hash_chain" && c.passed) {
            reasons.push(format!(
                "hash integrity failed: stored={} recomputed={}",
                v.original_hash, v.recomputed_hash
            ));
        }
    }

    // 5. Runtime context
    if policy.require_runtime_context {
        if pack.runtime_context.node_id.is_empty()
            || pack.runtime_context.pod_id.is_empty()
            || pack.runtime_context.region.is_empty()
        {
            reasons.push("runtime_context incomplete".into());
        }
    }

    // 6. Body signature
    if policy.require_real_signature {
        if pack.signature.is_empty() || pack.signature == "signature_placeholder" {
            reasons.push("body signature missing or still placeholder".into());
        }
    }

    // 7. Optional live replay
    if let Some(r) = replayer {
        let v = verify_pack(pack, Some(r), None);
        if let Some(check) = v.checks.iter().find(|c| c.name == "response_replay") {
            if !check.passed {
                reasons.push(format!("replay failed: {}", check.detail));
            }
        }
    }

    if reasons.is_empty() {
        AdmitDecision::Accept {
            pack_id: pack.pack_id.clone(),
            atom_id: None,
            reason: "all body admission checks passed".into(),
        }
    } else {
        AdmitDecision::Reject {
            pack_id: pack.pack_id.clone(),
            atom_id: None,
            reasons,
        }
    }
}

/// Pure admission predicate for a SignedAtom (envelope + body).
///
/// Steps (in order):
/// 1. Envelope structure
/// 2. atom_id integrity (satom-v3)
/// 3. Optional prev_head continuity
/// 4. Envelope signature (policy)
/// 5. Full body admission via admit()
pub fn admit_atom(
    atom: &SignedAtom,
    policy: &AdmitPolicy,
    expected_prev_head: Option<&str>,
    replayer: Option<&dyn Replayable>,
) -> AdmitDecision {
    let mut reasons: Vec<String> = Vec::new();

    // 1. Envelope structure
    if atom.atom_id.is_empty() {
        reasons.push("atom_id empty".into());
    }
    if atom.prev_head.is_empty() {
        reasons.push("prev_head empty".into());
    }
    if atom.enveloped_at_utc.is_empty() {
        reasons.push("enveloped_at_utc empty".into());
    }

    // 2. atom_id integrity (satom-v3)
    if !atom.verify_id() {
        reasons.push("atom_id integrity failed (verify_id)".into());
    }

    // 3. prev_head continuity
    if let Some(expected) = expected_prev_head {
        if atom.prev_head != expected {
            reasons.push(format!(
                "prev_head mismatch: atom has '{}', expected '{}'",
                atom.prev_head, expected
            ));
        }
    }

    // 4. Envelope signature
    if policy.require_atom_signature {
        if atom.signature.is_empty() || atom.signature == "signature_placeholder" {
            reasons.push("atom signature missing or still placeholder".into());
        }
    }

    // 5. Body admission
    let body_decision = admit(&atom.body, policy, replayer);
    match body_decision {
        AdmitDecision::Reject {
            reasons: body_reasons,
            ..
        } => {
            for r in body_reasons {
                reasons.push(format!("body: {}", r));
            }
        }
        AdmitDecision::Accept { .. } => {}
    }

    if reasons.is_empty() {
        AdmitDecision::Accept {
            pack_id: atom.body.pack_id.clone(),
            atom_id: Some(atom.atom_id.clone()),
            reason: "all envelope + body admission checks passed".into(),
        }
    } else {
        AdmitDecision::Reject {
            pack_id: atom.body.pack_id.clone(),
            atom_id: Some(atom.atom_id.clone()),
            reasons,
        }
    }
}

struct NullReplayer;
impl Replayable for NullReplayer {
    fn replay(&self, _request: &serde_json::Value) -> Result<serde_json::Value, String> {
        Err("null replayer".into())
    }
}

/// Default policy: pure, hash-checked, signatures required, no replay.
pub fn admit_default(pack: &EvidencePack) -> AdmitDecision {
    admit(pack, &AdmitPolicy::default(), None)
}

/// Default policy for atoms: pure, hash-checked, signatures required, no replay.
pub fn admit_atom_default(atom: &SignedAtom) -> AdmitDecision {
    admit_atom(atom, &AdmitPolicy::default(), None, None)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::atom::SignedAtom;
    use crate::RuntimeContext;
    use serde_json::json;

    const TEST_SIG: &str = "test-sig-not-placeholder";

    fn minimal_valid_pack() -> EvidencePack {
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
            TEST_SIG.into(),
        )
    }

    #[test]
    fn admit_accepts_well_formed_stripe_pack() {
        let pack = minimal_valid_pack();
        let decision = admit_default(&pack);
        assert!(decision.is_accepted(), "{:?}", decision);
    }

    #[test]
    fn admit_rejects_placeholder_signature_under_default_policy() {
        let mut pack = minimal_valid_pack();
        pack.signature = "signature_placeholder".into();
        let decision = admit_default(&pack);
        assert!(!decision.is_accepted());
        if let AdmitDecision::Reject { reasons, .. } = decision {
            assert!(reasons.iter().any(|r| r.contains("signature")));
        }
    }

    #[test]
    fn admit_rejects_unknown_service() {
        let mut pack = minimal_valid_pack();
        pack.service = "unknown-svc".into();
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

    #[test]
    fn admit_atom_accepts_well_formed_envelope() {
        let pack = minimal_valid_pack();
        let atom = SignedAtom::new(pack, "GENESIS".into(), 0, TEST_SIG.into());
        let decision = admit_atom_default(&atom);
        assert!(decision.is_accepted(), "{:?}", decision);
        if let AdmitDecision::Accept { atom_id, .. } = decision {
            assert!(atom_id.is_some());
        }
    }

    #[test]
    fn admit_atom_rejects_prev_head_mismatch() {
        let pack = minimal_valid_pack();
        let atom = SignedAtom::new(pack, "GENESIS".into(), 0, TEST_SIG.into());
        let decision = admit_atom(&atom, &AdmitPolicy::default(), Some("not-genesis"), None);
        assert!(!decision.is_accepted());
        if let AdmitDecision::Reject { reasons, .. } = decision {
            assert!(reasons.iter().any(|r| r.contains("prev_head mismatch")));
        }
    }

    #[test]
    fn admit_atom_rejects_tampered_atom_id() {
        let pack = minimal_valid_pack();
        let mut atom = SignedAtom::new(pack, "GENESIS".into(), 0, TEST_SIG.into());
        atom.atom_id = "deadbeef".into();
        let decision = admit_atom_default(&atom);
        assert!(!decision.is_accepted());
        if let AdmitDecision::Reject { reasons, .. } = decision {
            assert!(reasons.iter().any(|r| r.contains("verify_id")));
        }
    }

    #[test]
    fn soft_policy_allows_placeholder_signatures() {
        let mut pack = minimal_valid_pack();
        pack.signature = "signature_placeholder".into();
        let decision = admit(&pack, &policy_soft_signatures(), None);
        assert!(decision.is_accepted(), "{:?}", decision);
    }
}
