//! SignedAtom + chain-head.
//!
//! After admit() accepts an EvidencePack, wrap it in a SignedAtom and
//! link it to the current chain-head. The head is the only mutable
//! pointer; every atom is immutable once written.

use crate::admit::{admit, AdmitDecision, AdmitPolicy};
use crate::EvidencePack;
use crate::verify::Replayable;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

/// Domain prefix for SignedAtom ids (canonicalization.md v3 §2 / §4).
pub const SATOM_DOMAIN: &[u8] = b"satom-v3:";

/// Immutable signed envelope around an admitted EvidencePack.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAtom {
    /// Content-addressed id = SHA-256 of the canonical atom bytes (excluding this field).
    pub atom_id: String,
    /// Previous chain-head. "GENESIS" for the first atom.
    pub prev_head: String,
    /// Monotonic sequence number (0-based).
    pub sequence: u64,
    /// The admitted EvidencePack (body).
    pub body: EvidencePack,
    /// Signature over (prev_head || sequence || body.pack_id).
    /// Placeholder until real Ed25519 / PQC keys land.
    pub signature: String,
    /// UTC timestamp of envelope creation (RFC3339).
    pub enveloped_at_utc: String,
}

impl SignedAtom {
    /// Compute the deterministic atom_id from the other fields.
    /// canonicalization.md v3 §4.2
    fn compute_id(
        prev_head: &str,
        sequence: u64,
        body_pack_id: &str,
        signature: &str,
        enveloped_at_utc: &str,
    ) -> String {
        let mut hasher = Sha256::new();
        hasher.update(SATOM_DOMAIN);
        hasher.update(prev_head.as_bytes());
        hasher.update(sequence.to_string().as_bytes());
        hasher.update(body_pack_id.as_bytes());
        hasher.update(signature.as_bytes());
        hasher.update(enveloped_at_utc.as_bytes());
        format!("{:x}", hasher.finalize())
    }

    /// Create a new SignedAtom linked to `prev_head`.
    /// Caller is responsible for having already run admit().
    pub fn new(
        body: EvidencePack,
        prev_head: String,
        sequence: u64,
        signature: String,
    ) -> Self {
        let enveloped_at_utc = chrono::Utc::now().to_rfc3339();
        let atom_id = Self::compute_id(
            &prev_head,
            sequence,
            &body.pack_id,
            &signature,
            &enveloped_at_utc,
        );

        SignedAtom {
            atom_id,
            prev_head,
            sequence,
            body,
            signature,
            enveloped_at_utc,
        }
    }

    /// Recompute atom_id and verify it matches the stored value.
    pub fn verify_id(&self) -> bool {
        let recomputed = Self::compute_id(
            &self.prev_head,
            self.sequence,
            &self.body.pack_id,
            &self.signature,
            &self.enveloped_at_utc,
        );
        recomputed == self.atom_id
    }

    /// Persist atom under atoms/<atom_id>.json
    pub fn write_to_disk(&self, root: &Path) -> std::io::Result<()> {
        let dir = root.join("atoms");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", self.atom_id));
        let data = serde_json::to_string_pretty(self).expect("atom serialize");
        fs::write(path, data)
    }
}

/// The single mutable pointer into the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainHead {
    pub head_atom_id: String,
    pub sequence: u64,
    pub updated_at_utc: String,
}

impl ChainHead {
    pub fn genesis() -> Self {
        ChainHead {
            head_atom_id: "GENESIS".into(),
            sequence: 0,
            updated_at_utc: chrono::Utc::now().to_rfc3339(),
        }
    }

    pub fn load(path: &Path) -> std::io::Result<Self> {
        if !path.exists() {
            return Ok(Self::genesis());
        }
        let data = fs::read_to_string(path)?;
        Ok(serde_json::from_str(&data).unwrap_or_else(|_| Self::genesis()))
    }

    pub fn save(&self, path: &Path) -> std::io::Result<()> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let data = serde_json::to_string_pretty(self).expect("head serialize");
        fs::write(path, data)
    }
}

/// Result of attempting to append an atom to the chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AppendResult {
    Appended {
        atom_id: String,
        sequence: u64,
        new_head: String,
    },
    Refused {
        pack_id: String,
        reasons: Vec<String>,
    },
}

/// The only write path into the chain.
///
/// 1. Run admit() on the body
/// 2. On Accept → wrap in SignedAtom, link to current head, persist atom, advance head
/// 3. On Reject → return reasons, head unchanged
pub fn append_atom(
    pack: EvidencePack,
    policy: &AdmitPolicy,
    replayer: Option<&dyn Replayable>,
    chain_root: &Path,
    atom_signature: String,
) -> AppendResult {
    // 1. Admission gate (body)
    let decision = admit(&pack, policy, replayer);
    match decision {
        AdmitDecision::Reject { pack_id, reasons, .. } => {
            return AppendResult::Refused { pack_id, reasons };
        }
        AdmitDecision::Accept { .. } => {}
    }

    // 2. Load current head
    let head_path = chain_root.join("chain-head.json");
    let mut head = ChainHead::load(&head_path).unwrap_or_else(|_| ChainHead::genesis());

    // 3. Build SignedAtom linked to current head
    let sequence = if head.head_atom_id == "GENESIS" {
        0
    } else {
        head.sequence + 1
    };

    let atom = SignedAtom::new(
        pack,
        head.head_atom_id.clone(),
        sequence,
        atom_signature,
    );

    // 4. Persist atom
    if let Err(e) = atom.write_to_disk(chain_root) {
        return AppendResult::Refused {
            pack_id: atom.body.pack_id,
            reasons: vec![format!("atom write failed: {}", e)],
        };
    }

    // 5. Advance head
    head.head_atom_id = atom.atom_id.clone();
    head.sequence = sequence;
    head.updated_at_utc = chrono::Utc::now().to_rfc3339();
    if let Err(e) = head.save(&head_path) {
        return AppendResult::Refused {
            pack_id: atom.body.pack_id,
            reasons: vec![format!("head write failed: {}", e)],
        };
    }

    AppendResult::Appended {
        atom_id: atom.atom_id,
        sequence,
        new_head: head.head_atom_id,
    }
}

/// Convenience: append with default policy, no replayer, placeholder signature.
pub fn append_atom_default(pack: EvidencePack, chain_root: &Path) -> AppendResult {
    append_atom(
        pack,
        &AdmitPolicy::default(),
        None,
        chain_root,
        "signature_placeholder".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::RuntimeContext;
    use serde_json::json;
    use std::env::temp_dir;

    fn stripe_pack() -> EvidencePack {
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
    fn append_first_atom_from_genesis() {
        let root = temp_dir().join(format!("chain_test_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let result = append_atom_default(stripe_pack(), &root);
        match result {
            AppendResult::Appended { atom_id, sequence, new_head } => {
                assert_eq!(sequence, 0);
                assert_eq!(atom_id, new_head);
                assert!(root.join("atoms").join(format!("{}.json", atom_id)).exists());
                assert!(root.join("chain-head.json").exists());
            }
            AppendResult::Refused { reasons, .. } => panic!("unexpected refuse: {:?}", reasons),
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn refuse_unknown_service() {
        let root = temp_dir().join(format!("chain_refuse_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let mut pack = stripe_pack();
        pack.service = "unknown".into();

        let result = append_atom_default(pack, &root);
        assert!(matches!(result, AppendResult::Refused { .. }));

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn atom_id_includes_satom_domain() {
        let pack = stripe_pack();
        let atom = SignedAtom::new(pack, "GENESIS".into(), 0, "signature_placeholder".into());
        assert!(atom.verify_id());
    }
}
