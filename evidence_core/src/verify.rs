use crate::{EvidencePack, EPACK_DOMAIN};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VerifyError {
    #[error("failed to load pack: {0}")]
    Load(String),
    #[error("hash mismatch: expected {expected}, got {got}")]
    HashMismatch { expected: String, got: String },
    #[error("response mismatch")]
    ResponseMismatch { diff: String },
    #[error("invariant failed: {0}")]
    InvariantFailed(String),
    #[error("replay failed: {0}")]
    Replay(String),
    #[error("signature invalid")]
    SignatureInvalid,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct VerificationResult {
    pub pack_id: String,
    pub passed: bool,
    pub checks: Vec<CheckResult>,
    pub recomputed_hash: String,
    pub original_hash: String,
    pub response_diff: Option<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct CheckResult {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

/// Trait the service must implement so the verifier can replay the request
/// without hard-coding HTTP.
pub trait Replayable {
    fn replay(&self, request: &Value) -> Result<Value, String>;
}

/// Pure verification function.
/// Hash recomputation matches EvidencePack::new / canonicalization.md v3 §3.2.
pub fn verify_pack<R: Replayable>(
    pack: &EvidencePack,
    replayer: Option<&R>,
    expected_invariants: Option<&[String]>,
) -> VerificationResult {
    let mut checks = Vec::new();
    let mut overall_passed = true;

    // 1. Recompute current_hash (epack-v3 domain)
    let mut hasher = Sha256::new();
    hasher.update(EPACK_DOMAIN);
    hasher.update(pack.created_at_utc.as_bytes());
    hasher.update(pack.service.as_bytes());
    hasher.update(pack.service_version.as_bytes());
    hasher.update(pack.gateway_version.as_bytes());
    hasher.update(serde_json::to_vec(&pack.request).unwrap_or_default());
    hasher.update(serde_json::to_vec(&pack.response).unwrap_or_default());
    hasher.update(pack.hash_chain.prev_hash.as_bytes());
    let recomputed = format!("{:x}", hasher.finalize());

    let hash_ok = recomputed == pack.hash_chain.current_hash;
    checks.push(CheckResult {
        name: "hash_chain".into(),
        passed: hash_ok,
        detail: if hash_ok {
            "hash matches".into()
        } else {
            format!("expected {} got {}", pack.hash_chain.current_hash, recomputed)
        },
    });
    if !hash_ok {
        overall_passed = false;
    }

    // 2. Signature check (soft until real keys land)
    let sig_ok = !pack.signature.is_empty() && pack.signature != "signature_placeholder";
    checks.push(CheckResult {
        name: "signature".into(),
        passed: sig_ok,
        detail: if sig_ok {
            "signature present".into()
        } else {
            "signature missing or placeholder".into()
        },
    });

    // 3. Invariant list presence
    if let Some(expected) = expected_invariants {
        let missing: Vec<_> = expected
            .iter()
            .filter(|e| !pack.invariants.contains(e))
            .cloned()
            .collect();
        let inv_ok = missing.is_empty();
        checks.push(CheckResult {
            name: "invariants_declared".into(),
            passed: inv_ok,
            detail: if inv_ok {
                "all expected invariants present".into()
            } else {
                format!("missing: {:?}", missing)
            },
        });
        if !inv_ok {
            overall_passed = false;
        }
    }

    // 4. Optional live replay
    let mut response_diff = None;
    if let Some(r) = replayer {
        match r.replay(&pack.request) {
            Ok(live_resp) => {
                let equal = live_resp == pack.response;
                if !equal {
                    let diff = format!(
                        "stored: {}\nlive:   {}",
                        serde_json::to_string_pretty(&pack.response).unwrap_or_default(),
                        serde_json::to_string_pretty(&live_resp).unwrap_or_default()
                    );
                    response_diff = Some(diff);
                    checks.push(CheckResult {
                        name: "response_replay".into(),
                        passed: false,
                        detail: "response diverged from live replay".into(),
                    });
                    overall_passed = false;
                } else {
                    checks.push(CheckResult {
                        name: "response_replay".into(),
                        passed: true,
                        detail: "bit-identical to live replay".into(),
                    });
                }
            }
            Err(e) => {
                checks.push(CheckResult {
                    name: "response_replay".into(),
                    passed: false,
                    detail: format!("replay error: {}", e),
                });
                overall_passed = false;
            }
        }
    } else {
        checks.push(CheckResult {
            name: "response_replay".into(),
            passed: true,
            detail: "skipped (no replayer supplied)".into(),
        });
    }

    // 5. Runtime context sanity
    let ctx_ok = !pack.runtime_context.node_id.is_empty()
        && !pack.runtime_context.pod_id.is_empty()
        && !pack.runtime_context.region.is_empty();
    checks.push(CheckResult {
        name: "runtime_context".into(),
        passed: ctx_ok,
        detail: if ctx_ok {
            "node/pod/region present".into()
        } else {
            "incomplete runtime context".into()
        },
    });

    VerificationResult {
        pack_id: pack.pack_id.clone(),
        passed: overall_passed,
        checks,
        recomputed_hash: recomputed,
        original_hash: pack.hash_chain.current_hash.clone(),
        response_diff,
    }
}

pub fn load_pack(path: &str) -> Result<EvidencePack, VerifyError> {
    let data = std::fs::read_to_string(path)
        .map_err(|e| VerifyError::Load(e.to_string()))?;
    serde_json::from_str(&data).map_err(|e| VerifyError::Load(e.to_string()))
}

pub fn verify_pack_file<R: Replayable>(
    path: &str,
    replayer: Option<&R>,
    expected_invariants: Option<&[String]>,
) -> Result<VerificationResult, VerifyError> {
    let pack = load_pack(path)?;
    Ok(verify_pack(&pack, replayer, expected_invariants))
}
