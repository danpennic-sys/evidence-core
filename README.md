# evidence-core

Minimal, deterministic **EvidencePack** emission + verification + **admission** for Operator microservices.

## Workspace

```
evidence-core/
├── evidence_core/       shared library (emit + verify + admit)
├── stripe-service/      full Stripe Checkout + verified webhook + EvidencePack
└── examples/            drop-in wiring patterns
```

## Admission predicate (`admit.rs`)

Pure function. No I/O. No clocks. No network.

```rust
use evidence_core::admit::{admit, admit_default, AdmitPolicy, AdmitDecision};

let decision = admit_default(&pack);
match decision {
    AdmitDecision::Accept { pack_id, reason } => { /* link to chain-head */ }
    AdmitDecision::Reject { pack_id, reasons } => { /* refuse */ }
}
```

Checks performed (in order):

1. Structural completeness (pack_id, service, versions, hash_chain)
2. Service allow-list
3. Required invariants per service
4. Hash integrity (recomputed == stored)
5. Runtime context presence
6. Signature presence (policy flag)
7. Optional live replay

Default policy already encodes the STRIPE-001..004 and TZ/GEO invariant sets.

## Services covered

| Service | Endpoints |
|---------|-----------|
| Time | `/v1/time/now`, `/v1/time/convert` |
| Geo | `/v1/geo/ip` |
| Date | `/v1/date/today`, `/v1/date/holiday` |
| IPDiag | `/v1/ip/diag` |
| Media | `/v1/media/suggest` |
| Stripe | `checkout.session.completed` (sole payment confirmation boundary) |

## Quick start — Stripe service

```bash
cp stripe-service/.env.example stripe-service/.env
# set STRIPE_SECRET_KEY=sk_test_...

cargo run -p stripe-service
```

Second terminal:

```bash
stripe listen --forward-to localhost:4242/webhook
```

Open http://localhost:4242, pay $10 with test card `4242 4242 4242 4242`.
EvidencePack is written under `evidence/`. Run `admit_default` on it before any chain link.

## Design constraints

- Hash is a pure function of the fields written into the pack.
- `admit` is pure; it never writes, never reads the clock, never talks to the network.
- Signature field remains a placeholder until real Ed25519 / PQC keys land.
