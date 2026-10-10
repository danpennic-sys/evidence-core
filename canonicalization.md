# Canonicalization — v3 (FROZEN)

**Status:** FROZEN  
**Version:** 3  
**Date:** 2026-10-10  
**Scope:** EvidencePack, SignedAtom, chain-head, admit predicate  
**Compatibility:** quantumguard CanonicalBytes (payload_hash domain), evidence-core hash construction

This document is the single source of truth for deterministic byte sequences used for hashing and signing. No alternate construction is permitted.

---

## 1. Design Rules (non-negotiable)

1. **Determinism** — identical logical inputs MUST produce identical byte sequences on every conforming implementation.
2. **No ambient authority** — canonicalization MUST NOT read the clock, the filesystem, the network, environment variables, or locale.
3. **Domain separation** — every hash domain has an explicit prefix. Cross-domain collisions are forbidden by construction.
4. **Immutability after freeze** — this document may only be superseded by a new major version (v4+). Patches that change byte sequences are prohibited.
5. **UTF-8 only** — all string fields are encoded as UTF-8 without BOM.
6. **No floating point** — numeric values that participate in hashes MUST be integers or decimal strings with a fixed representation.

---

## 2. Domain Prefixes

| Domain              | Prefix (ASCII)     | Used by                          |
|---------------------|--------------------|----------------------------------|
| EvidencePack hash   | `epack-v3:`        | `EvidencePack::new` current_hash |
| SignedAtom id       | `satom-v3:`        | `SignedAtom::compute_id`         |
| Chain-head link     | `chead-v3:`        | future head integrity checks     |
| Admit transcript    | `admit-v3:`        | optional audit log of decisions  |

Prefixes are included in the first bytes of the material that is hashed.

---

## 3. EvidencePack current_hash (epack-v3)

### 3.1 Input fields (in order)

```
created_at_utc      (RFC3339 string, as stored)
service             (string)
service_version     (string)
gateway_version     (string)
request             (canonical JSON bytes — see §5)
response            (canonical JSON bytes — see §5)
prev_hash           (hex string, lowercase)
```

### 3.2 Construction

```
material = "epack-v3:"
         || created_at_utc
         || service
         || service_version
         || gateway_version
         || request_canonical_bytes
         || response_canonical_bytes
         || prev_hash

current_hash = lowercase_hex( SHA-256(material) )
```

`pack_id` MUST equal `current_hash`.

### 3.3 Notes

- Field order is fixed. No key sorting of the outer struct is performed; the concatenation order above is authoritative.
- `invariants`, `runtime_context`, and `signature` are intentionally excluded from the hash so that signature material can be attached after the hash is known.

---

## 4. SignedAtom atom_id (satom-v3)

### 4.1 Input fields (in order)

```
prev_head           (string, "GENESIS" or prior atom_id)
sequence            (decimal string of u64, no leading zeros except for 0 itself)
body.pack_id        (hex string)
signature           (string)
enveloped_at_utc    (RFC3339 string)
```

### 4.2 Construction

```
material = "satom-v3:"
         || prev_head
         || sequence
         || body.pack_id
         || signature
         || enveloped_at_utc

atom_id = lowercase_hex( SHA-256(material) )
```

### 4.3 Chain-head invariant

After a successful `append_atom`:

- `chain-head.json.head_atom_id` MUST equal the new `atom_id`
- `chain-head.json.sequence` MUST equal the new `sequence`
- The atom file `atoms/<atom_id>.json` MUST exist and MUST verify `verify_id() == true`

---

## 5. Canonical JSON (JCS-r1 profile)

For any `serde_json::Value` that participates in a hash:

1. **Objects** — keys sorted lexicographically by UTF-8 code unit order. No duplicate keys.
2. **Arrays** — elements in the order they appear; no reordering.
3. **Strings** — UTF-8, JSON-escaped exactly as produced by a conforming RFC 8259 serializer that uses the shortest escape form for control characters and does not escape solidus (`/`).
4. **Numbers** — integer values in the range of i64 MUST be emitted without decimal point or exponent. Values outside that range or non-integers are forbidden in hash-participating fields for v3.
5. **Booleans / null** — lowercase `true` / `false` / `null`.
6. **Whitespace** — none. No space after `:` or `,`.

Reference algorithm: RFC 8785 (JCS) restricted to the subset above. Implementations MUST produce bit-identical output to `serde_json::to_vec` on a Value that already has sorted object keys and only integer numbers.

In the current Rust codebase the practical rule is:

```rust
// Before hashing, ensure object keys are sorted if the Value was constructed
// from a BTreeMap or via a canonicalizing helper. Map/HashMap insertion
// order is NOT reliable; do not rely on it.
serde_json::to_vec(&value).expect("canonical json")
```

Future implementations in other languages MUST match the byte sequences produced by the Rust reference.

---

## 6. Signature Payload (future, reserved)

When real signatures replace the placeholder, the signed message MUST be:

```
"sig-v3:" || atom_id
```

for SignedAtom, and

```
"sig-v3:" || pack_id
```

for EvidencePack (if independently signed).

Algorithm agility is reserved for v4 (Ed25519 first, PQC track second, matching quantumguard PQC-TRACK).

---

## 7. Admit Transcript (optional, admit-v3)

If an implementation records admission decisions for audit, the transcript line is:

```
material = "admit-v3:"
         || pack_id
         || decision           ("ACCEPT" | "REJECT")
         || reasons_joined     (reasons sorted, joined by 0x1F unit separator, empty if ACCEPT)

transcript_hash = lowercase_hex( SHA-256(material) )
```

This hash is advisory; it does not affect chain validity.

---

## 8. Conformance Vectors (minimal)

Implementations MUST pass the following fixed vectors.

### 8.1 EvidencePack hash (illustrative structure)

Given fixed inputs (clock frozen for the test):

```
created_at_utc   = "2026-10-10T00:00:00Z"
service          = "stripe"
service_version  = "v20261008-A"
gateway_version  = "v20261008-G"
request          = {"body":{},"path":"/stripe/webhook/checkout.session.completed"}  // keys sorted
response         = {"amount":1000,"session_id":"cs_test_1"}
prev_hash        = "GENESIS"
```

`current_hash` MUST equal the SHA-256 of the material defined in §3.2.  
Exact hex digests will be published as machine-readable files under `vectors/canonical/v3/` once the reference implementation freezes the clock in tests.

### 8.2 SignedAtom id

```
prev_head        = "GENESIS"
sequence         = 0
body.pack_id     = <hash from 8.1>
signature        = "signature_placeholder"
enveloped_at_utc = "2026-10-10T00:00:01Z"
```

`atom_id` MUST equal the SHA-256 of the material defined in §4.2.

---

## 9. Change Control

- **v3 is frozen.** Any change that alters a byte sequence requires a new major version.
- Editorial corrections (typos, clarification that do not change bytes) MAY be applied with a note in the document history below.
- The Rust reference implementation in `evidence_core` is authoritative for v3 byte sequences.

### Document History

| Version | Date       | Note                                      |
|---------|------------|-------------------------------------------|
| 3       | 2026-10-10 | Initial freeze. EvidencePack + SignedAtom |

---

**End of canonicalization.md v3**
