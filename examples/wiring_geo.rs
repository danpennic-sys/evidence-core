// Drop-in for Geo service

use evidence_core::emit_pack;
use serde_json::json;

const SERVICE: &str = "geo";
const SERVICE_VERSION: &str = "v20261008-A";
const GATEWAY_VERSION: &str = "v20261008-G";

// GET /v1/geo/ip
fn emit_geo_ip(ip: &str, result: &impl serde::Serialize) {
    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/v1/geo/ip",
        json!({ "ip": ip }),
        result,
        vec!["GEO-001".into(), "GEO-002".into(), "GEO-003".into()],
        "GENESIS".into(),
        "signature_placeholder".into(),
    );
}
