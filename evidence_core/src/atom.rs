//! SignedAtom + chain-head.

use crate::admit::{admit, policy_soft_signatures, AdmitDecision, AdmitPolicy};
use crate::keys;
use crate::EvidencePack;
use crate::verify::Replayable;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::Path;

pub const SATOM_DOMAIN: &[u8] = b"satom-v3:";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignedAtom {
    pub atom_id: String,
    pub prev_head: String,
    pub sequence: u64,
    pub body: EvidencePack,
    pub signature: String,
    pub enveloped_at_utc: String,
}

impl SignedAtom {
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

    /// Create atom with a pre-supplied envelope signature string.
    pub fn new(
        body: EvidencePack,
        prev_head: String,
        sequence: u64,
        signature: String,
    ) -> Self {
        let enveloped_at_utc = chrono::Utc::now().to_rfc3339();
        // Provisional id uses the provided signature bytes in the material.
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

    /// Create atom and sign the envelope with the founding key.
    ///
    /// Note: atom_id includes the signature in its hash material (v3 §4).
    /// We therefore:
    /// 1. Build with a temporary empty signature to get enveloped_at_utc + provisional fields
    /// 2. Actually we must sign over atom_id, but atom_id depends on signature.
    ///
    /// Resolution used here (documented):
    /// - Compute a *pre-sig* material hash over (prev_head || sequence || body.pack_id || enveloped_at_utc)
    ///   is NOT the v3 atom_id.
    /// - v3 atom_id includes signature. So the operational sequence is:
    ///   a) fix enveloped_at_utc
    ///   b) choose signature = sign("sig-v3:" || provisional_id) where provisional_id is
    ///      SHA-256(satom-v3: || prev_head || sequence || pack_id || "" || enveloped_at_utc)
    ///   c) final atom_id = SHA-256(satom-v3: || prev_head || sequence || pack_id || signature || enveloped_at_utc)
    ///   d) The signed message remains "sig-v3:" || provisional_id (stable, independent of final atom_id)
    ///
    /// For strict v3 message = "sig-v3:" || atom_id, a fixed-point would be required.
    /// We use provisional_id as the signed content and store final atom_id as the content address.
    /// verify_atom_sig checks the provisional form via `sign_target()`.
    pub fn new_signed(
        body: EvidencePack,
        prev_head: String,
        sequence: u64,
        signing: &SigningKey,
    ) -> Self {
        let enveloped_at_utc = chrono::Utc::now().to_rfc3339();
        let provisional_id = Self::compute_id(
            &prev_head,
            sequence,
            &body.pack_id,
            "",
            &enveloped_at_utc,
        );
        let signature = keys::sign_atom(&provisional_id, signing);
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

    /// The id that was actually signed (provisional, empty-sig material).
    pub fn sign_target(&self) -> String {
        Self::compute_id(
            &self.prev_head,
            self.sequence,
            &self.body.pack_id,
            "",
            &self.enveloped_at_utc,
        )
    }

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

    pub fn write_to_disk(&self, root: &Path) -> std::io::Result<()> {
        let dir = root.join("atoms");
        fs::create_dir_all(&dir)?;
        let path = dir.join(format!("{}.json", self.atom_id));
        let data = serde_json::to_string_pretty(self).expect("atom serialize");
        fs::write(path, data)
    }
}

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

pub fn append_atom(
    pack: EvidencePack,
    policy: &AdmitPolicy,
    replayer: Option<&dyn Replayable>,
    chain_root: &Path,
    atom_signature: String,
) -> AppendResult {
    let decision = admit(&pack, policy, replayer);
    match decision {
        AdmitDecision::Reject { pack_id, reasons, .. } => {
            return AppendResult::Refused { pack_id, reasons };
        }
        AdmitDecision::Accept { .. } => {}
    }

    let head_path = chain_root.join("chain-head.json");
    let mut head = ChainHead::load(&head_path).unwrap_or_else(|_| ChainHead::genesis());

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

    if let Err(e) = atom.write_to_disk(chain_root) {
        return AppendResult::Refused {
            pack_id: atom.body.pack_id,
            reasons: vec![format!("atom write failed: {}", e)],
        };
    }

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

/// Constitutional path: real signatures + AdmitPolicy::default().
pub fn append_atom_signed(
    pack: EvidencePack,
    signing: &SigningKey,
    chain_root: &Path,
) -> AppendResult {
    let decision = admit(&pack, &AdmitPolicy::default(), None);
    match decision {
        AdmitDecision::Reject { pack_id, reasons, .. } => {
            return AppendResult::Refused { pack_id, reasons };
        }
        AdmitDecision::Accept { .. } => {}
    }

    let head_path = chain_root.join("chain-head.json");
    let mut head = ChainHead::load(&head_path).unwrap_or_else(|_| ChainHead::genesis());

    let sequence = if head.head_atom_id == "GENESIS" {
        0
    } else {
        head.sequence + 1
    };

    let atom = SignedAtom::new_signed(
        pack,
        head.head_atom_id.clone(),
        sequence,
        signing,
    );

    if let Err(e) = atom.write_to_disk(chain_root) {
        return AppendResult::Refused {
            pack_id: atom.body.pack_id,
            reasons: vec![format!("atom write failed: {}", e)],
        };
    }

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

/// Pre-key operational path.
pub fn append_atom_default(pack: EvidencePack, chain_root: &Path) -> AppendResult {
    append_atom(
        pack,
        &policy_soft_signatures(),
        None,
        chain_root,
        "signature_placeholder".into(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::{generate_founding_keypair, sign_pack};
    use crate::RuntimeContext;
    use serde_json::json;
    use std::env::temp_dir;

    fn stripe_pack_unsigned() -> EvidencePack {
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
            String::new(),
        )
    }

    #[test]
    fn append_first_real_atom_under_strict_policy() {
        let root = temp_dir().join(format!("chain_real_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let (sk, _vk) = generate_founding_keypair();
        let mut pack = stripe_pack_unsigned();
        pack.signature = sign_pack(&pack.pack_id, &sk);

        let result = append_atom_signed(pack, &sk, &root);
        match result {
            AppendResult::Appended { atom_id, sequence, new_head } => {
                assert_eq!(sequence, 0);
                assert_eq!(atom_id, new_head);
                assert!(root.join("atoms").join(format!("{}.json", atom_id)).exists());
            }
            AppendResult::Refused { reasons, .. } => panic!("refused: {:?}", reasons),
        }

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn soft_path_still_works() {
        let root = temp_dir().join(format!("chain_soft_{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let mut pack = stripe_pack_unsigned();
        pack.signature = "signature_placeholder".into();
        let result = append_atom_default(pack, &root);
        assert!(matches!(result, AppendResult::Appended { .. }));

        let _ = fs::remove_dir_all(&root);
    }
}
