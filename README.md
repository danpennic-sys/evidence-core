# evidence-core

Minimal, deterministic **EvidencePack** emission + verification for Operator microservices.

Services covered:
- Time (`/v1/time/now`, `/v1/time/convert`)
- Geo (`/v1/geo/ip`)
- Date (`/v1/date/today`, `/v1/date/holiday`)
- IPDiag (`/v1/ip/diag`)
- Media (`/v1/media/suggest`)

## Usage

Add to your service `Cargo.toml`:

```toml
evidence_core = { git = "https://github.com/danpennic-sys/evidence-core" }
```

Then after computing a response:

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

See `examples/wiring_*.rs` for the exact drop-in for every endpoint.

## Verification

```rust
use evidence_core::verify::{verify_pack_file, Replayable};

let result = verify_pack_file("evidence/geo_....json", Some(&replayer), Some(&expected_invariants))?;
assert!(result.passed);
```

## Design constraints

- Hash is pure function of the fields written into the pack (deterministic).
- No network, no side-effects beyond writing the JSON file.
- Signature is a placeholder until real Ed25519 / PQC keys land (compatible with quantumguard).
