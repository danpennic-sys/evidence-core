# evidence-core

Minimal, deterministic **EvidencePack** emission + verification + **admission** + **SignedAtom chain-head** for Operator microservices.

## Workspace

```
evidence-core/
├── evidence_core/       shared library
│   ├── emit / verify / admit / atom
├── stripe-service/      Stripe Checkout + webhook + EvidencePack
└── examples/            drop-in wiring patterns
```

## Chain flow (the only write path)

```
EvidencePack
    │
    ▼
admit()                    ← pure predicate
    │
    ├─ Reject → stop
    │
    └─ Accept
         │
         ▼
    SignedAtom             ← envelope (prev_head, sequence, body, signature)
         │
         ▼
    atoms/<atom_id>.json   ← immutable
         │
         ▼
    chain-head.json        ← single mutable pointer advanced
```

### Usage

```rust
use evidence_core::atom::{append_atom_default, AppendResult};
use std::path::Path;

let result = append_atom_default(pack, Path::new("./chain"));
match result {
    AppendResult::Appended { atom_id, sequence, new_head } => {
        // atom is now the chain tip
    }
    AppendResult::Refused { pack_id, reasons } => {
        // admission failed; head unchanged
    }
}
```

### SignedAtom fields

| Field | Meaning |
|-------|--------|
| `atom_id` | Content-addressed SHA-256 of the envelope |
| `prev_head` | Previous chain-head (`GENESIS` for first) |
| `sequence` | Monotonic 0-based counter |
| `body` | The admitted EvidencePack |
| `signature` | Placeholder until real keys |
| `enveloped_at_utc` | Envelope creation time |

## Admission (`admit.rs`)

Pure. No I/O. No clocks. No network.

Checks: structure → allow-list → required invariants → hash integrity → runtime context → signature → optional replay.

## Stripe service

```bash
cp stripe-service/.env.example stripe-service/.env
cargo run -p stripe-service
# second terminal: stripe listen --forward-to localhost:4242/webhook
```

After a paid webhook the EvidencePack is written. Call `append_atom_default` on it to admit + link.

## Design constraints

- `admit` is pure.
- Atoms are immutable once written.
- Only `chain-head.json` is mutable.
- Signature remains placeholder until Ed25519 / PQC keys land.
