// Drop-in pattern for TimeService (already shown previously).
// Keep for completeness.

use evidence_core::emit_pack;
use serde_json::json;

const SERVICE: &str = "time";
const SERVICE_VERSION: &str = "v20261008-A";
const GATEWAY_VERSION: &str = "v20261008-G";

// Inside your handler after you have `result`:
fn emit_time_now(result: &impl serde::Serialize) {
    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/v1/time/now",
        json!({}),
        result,
        vec!["TZ-001".into(), "TZ-002".into(), "TZ-003".into()],
        "GENESIS".into(),                     // replace with real prev_hash store
        "signature_placeholder".into(),       // replace with real signer
    );
}

fn emit_time_convert(body: serde_json::Value, result: &impl serde::Serialize) {
    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/v1/time/convert",
        body,
        result,
        vec!["TZ-001".into(), "TZ-004".into()],
        "GENESIS".into(),
        "signature_placeholder".into(),
    );
}
