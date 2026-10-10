//! Founding Ed25519 keys + sig-v3 sign/verify helpers.
//!
//! Signature payload (canonicalization.md v3 §6):
//!   EvidencePack body:  "sig-v3:" || pack_id
//!   SignedAtom envelope: "sig-v3:" || atom_id
//!
//! No ambient authority. Keys are generated and persisted only when the
//! operator explicitly calls generate_founding_keypair / load helpers.

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};
use thiserror::Error;

/// Domain prefix for signature messages (canonicalization.md v3 §6).
pub const SIG_DOMAIN: &[u8] = b"sig-v3:";

#[derive(Debug, Error)]
pub enum KeyError {
    #[error("io: {0}")]
    Io(#[from] std::io::Error),
    #[error("invalid key bytes: {0}")]
    InvalidKey(String),
    #[error("invalid signature: {0}")]
    InvalidSignature(String),
    #[error("hex decode: {0}")]
    Hex(#[from] hex::FromHexError),
}

/// Generate a new founding Ed25519 keypair.
/// Returns (signing_key, verifying_key).
pub fn generate_founding_keypair() -> (SigningKey, VerifyingKey) {
    let mut csprng = OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying = signing.verifying_key();
    (signing, verifying)
}

/// Persist founding keypair under `dir` as hex files:
///   founding.sk  (32-byte secret, hex)
///   founding.pk  (32-byte public, hex)
pub fn save_founding_keypair(
    dir: &Path,
    signing: &SigningKey,
    verifying: &VerifyingKey,
) -> Result<(), KeyError> {
    fs::create_dir_all(dir)?;
    let sk_hex = hex::encode(signing.to_bytes());
    let pk_hex = hex::encode(verifying.to_bytes());
    fs::write(dir.join("founding.sk"), sk_hex)?;
    fs::write(dir.join("founding.pk"), pk_hex)?;
    // Restrictive perms on secret where the OS allows it
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(dir.join("founding.sk"), fs::Permissions::from_mode(0o600));
    }
    Ok(())
}

/// Load founding signing key from `dir/founding.sk`.
pub fn load_signing_key(dir: &Path) -> Result<SigningKey, KeyError> {
    let hex_str = fs::read_to_string(dir.join("founding.sk"))?;
    let bytes = hex::decode(hex_str.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KeyError::InvalidKey("signing key must be 32 bytes".into()))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// Load founding verifying key from `dir/founding.pk`.
pub fn load_verifying_key(dir: &Path) -> Result<VerifyingKey, KeyError> {
    let hex_str = fs::read_to_string(dir.join("founding.pk"))?;
    let bytes = hex::decode(hex_str.trim())?;
    let arr: [u8; 32] = bytes
        .try_into()
        .map_err(|_| KeyError::InvalidKey("verifying key must be 32 bytes".into()))?;
    VerifyingKey::from_bytes(&arr).map_err(|e| KeyError::InvalidKey(e.to_string()))
}

/// Build the exact message bytes that are signed for a pack_id or atom_id.
fn sig_message(id: &str) -> Vec<u8> {
    let mut m = Vec::with_capacity(SIG_DOMAIN.len() + id.len());
    m.extend_from_slice(SIG_DOMAIN);
    m.extend_from_slice(id.as_bytes());
    m
}

/// Sign an EvidencePack body: message = "sig-v3:" || pack_id.
/// Returns lowercase hex of the 64-byte signature.
pub fn sign_pack(pack_id: &str, signing: &SigningKey) -> String {
    let msg = sig_message(pack_id);
    let sig = signing.sign(&msg);
    hex::encode(sig.to_bytes())
}

/// Sign a SignedAtom envelope: message = "sig-v3:" || atom_id.
/// Returns lowercase hex of the 64-byte signature.
pub fn sign_atom(atom_id: &str, signing: &SigningKey) -> String {
    let msg = sig_message(atom_id);
    let sig = signing.sign(&msg);
    hex::encode(sig.to_bytes())
}

/// Verify a pack body signature.
pub fn verify_pack_sig(
    pack_id: &str,
    signature_hex: &str,
    verifying: &VerifyingKey,
) -> Result<(), KeyError> {
    let msg = sig_message(pack_id);
    let sig_bytes = hex::decode(signature_hex)?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| KeyError::InvalidSignature(e.to_string()))?;
    verifying
        .verify(&msg, &sig)
        .map_err(|e| KeyError::InvalidSignature(e.to_string()))
}

/// Verify an atom envelope signature.
pub fn verify_atom_sig(
    atom_id: &str,
    signature_hex: &str,
    verifying: &VerifyingKey,
) -> Result<(), KeyError> {
    let msg = sig_message(atom_id);
    let sig_bytes = hex::decode(signature_hex)?;
    let sig = Signature::from_slice(&sig_bytes)
        .map_err(|e| KeyError::InvalidSignature(e.to_string()))?;
    verifying
        .verify(&msg, &sig)
        .map_err(|e| KeyError::InvalidSignature(e.to_string()))
}

/// Fingerprint of the verifying key (SHA-256 of raw 32 bytes, hex) for display / allow-lists.
pub fn verifying_key_fingerprint(verifying: &VerifyingKey) -> String {
    let mut h = Sha256::new();
    h.update(verifying.as_bytes());
    format!("{:x}", h.finalize())
}

/// Default path for founding keys relative to a chain root.
pub fn default_keys_dir(chain_root: &Path) -> PathBuf {
    chain_root.join("keys")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_sign_verify_pack() {
        let (sk, vk) = generate_founding_keypair();
        let pack_id = "abc123deadbeef";
        let sig = sign_pack(pack_id, &sk);
        assert!(verify_pack_sig(pack_id, &sig, &vk).is_ok());
        assert!(verify_pack_sig("tampered", &sig, &vk).is_err());
    }

    #[test]
    fn roundtrip_sign_verify_atom() {
        let (sk, vk) = generate_founding_keypair();
        let atom_id = "satomdeadbeef00";
        let sig = sign_atom(atom_id, &sk);
        assert!(verify_atom_sig(atom_id, &sig, &vk).is_ok());
    }

    #[test]
    fn message_includes_sig_domain() {
        let msg = sig_message("id1");
        assert!(msg.starts_with(SIG_DOMAIN));
    }
}
