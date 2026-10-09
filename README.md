# evidence-core

Minimal, deterministic **EvidencePack** emission + verification for Operator microservices.

## Workspace

```
evidence-core/           (this repo)
├── evidence_core/       shared library crate
├── stripe-service/      full Stripe Checkout + verified webhook + EvidencePack
└── examples/            drop-in wiring patterns for Time / Geo / Date / IPDiag / Media
```

## Services covered by evidence packs

| Service | Endpoints |
|---------|-----------|
| Time | `/v1/time/now`, `/v1/time/convert` |
| Geo | `/v1/geo/ip` |
| Date | `/v1/date/today`, `/v1/date/holiday` |
| IPDiag | `/v1/ip/diag` |
| Media | `/v1/media/suggest` |
| **Stripe** | `checkout.session.completed` (sole payment confirmation boundary) |

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
EvidencePack is written automatically under `evidence/`.

## Library usage (other services)

```toml
evidence_core = { path = "../evidence_core" }
# or
evidence_core = { git = "https://github.com/danpennic-sys/evidence-core" }
```

```rust
use evidence_core::emit_pack;

let _pack = emit_pack(
    "geo",
    "v20261008-A",
    "v20261008-G",
    "/v1/geo/ip",
    serde_json::json!({ "ip": ip }),
    &result,
    vec!["GEO-001".into(), "GEO-002".into()],
    prev_hash,
    signature,
);
```

See `examples/wiring_*.rs` for every endpoint.

## Design constraints

- Hash is a pure function of the fields written into the pack (deterministic).
- No network inside the library; only the stripe-service binary talks to Stripe.
- Signature field is a placeholder until real Ed25519 / PQC keys land (compatible with quantumguard).
