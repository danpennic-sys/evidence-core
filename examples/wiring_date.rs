// Drop-in for Date service

use evidence_core::emit_pack;
use serde_json::json;

const SERVICE: &str = "date";
const SERVICE_VERSION: &str = "v20261008-A";
const GATEWAY_VERSION: &str = "v20261008-G";

// GET /v1/date/today
fn emit_date_today(result: &impl serde::Serialize) {
    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/v1/date/today",
        json!({}),
        result,
        vec!["DATE-001".into(), "DATE-002".into()],
        "GENESIS".into(),
        "signature_placeholder".into(),
    );
}

// GET /v1/date/holiday
fn emit_date_holiday(query: serde_json::Value, result: &impl serde::Serialize) {
    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/v1/date/holiday",
        query,
        result,
        vec!["DATE-001".into(), "DATE-003".into(), "DATE-004".into()],
        "GENESIS".into(),
        "signature_placeholder".into(),
    );
}
