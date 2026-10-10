//! Generate founding keypair and append the first real atom under strict policy.
//!
//! Usage (from workspace root):
//!   cargo run --example founding_atom --manifest-path evidence_core/Cargo.toml
//!
//! Or add to workspace examples and:
//!   cargo run -p evidence_core --example founding_atom

use evidence_core::atom::{append_atom_signed, AppendResult};
use evidence_core::keys::{
    default_keys_dir, generate_founding_keypair, save_founding_keypair, sign_pack,
    verifying_key_fingerprint,
};
use evidence_core::{EvidencePack, RuntimeContext};
use serde_json::json;
use std::path::Path;

fn main() {
    let chain_root = Path::new("./chain");
    let keys_dir = default_keys_dir(chain_root);

    // 1. Founding keypair
    let (sk, vk) = generate_founding_keypair();
    save_founding_keypair(&keys_dir, &sk, &vk).expect("save keys");
    println!("founding key fingerprint: {}", verifying_key_fingerprint(&vk));
    println!("keys written under {}", keys_dir.display());

    // 2. First real EvidencePack (body signed)
    let mut pack = EvidencePack::new(
        "stripe",
        "v20261008-A",
        "v20261008-G",
        json!({
            "path": "/stripe/webhook/checkout.session.completed",
            "body": { "session_id": "cs_founding_1" }
        }),
        json!({
            "session_id": "cs_founding_1",
            "amount": 1000,
            "currency": "usd",
            "note": "first real atom under strict AdmitPolicy"
        }),
        vec![
            "STRIPE-001".into(),
            "STRIPE-002".into(),
            "STRIPE-003".into(),
            "STRIPE-004".into(),
        ],
        "GENESIS".into(),
        RuntimeContext {
            node_id: "node-founding".into(),
            pod_id: "pod-founding".into(),
            region: "us-central-1".into(),
        },
        String::new(),
    );
    pack.signature = sign_pack(&pack.pack_id, &sk);
    let _ = pack.write_to_disk("stripe");

    // 3. Append under constitutional path (strict policy + envelope signed)
    match append_atom_signed(pack, &sk, chain_root) {
        AppendResult::Appended {
            atom_id,
            sequence,
            new_head,
        } => {
            println!("FIRST REAL ATOM");
            println!("  sequence : {}", sequence);
            println!("  atom_id  : {}", atom_id);
            println!("  new_head : {}", new_head);
            println!("  path     : {}/atoms/{}.json", chain_root.display(), atom_id);
        }
        AppendResult::Refused { pack_id, reasons } => {
            eprintln!("REFUSED pack_id={}", pack_id);
            for r in reasons {
                eprintln!("  - {}", r);
            }
            std::process::exit(1);
        }
    }
}
