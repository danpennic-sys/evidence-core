// Drop-in for Media service

use evidence_core::emit_pack;
use serde_json::json;

const SERVICE: &str = "media";
const SERVICE_VERSION: &str = "v20261008-A";
const GATEWAY_VERSION: &str = "v20261008-G";

// GET /v1/media/suggest
fn emit_media_suggest(query: serde_json::Value, result: &impl serde::Serialize) {
    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/v1/media/suggest",
        query,
        result,
        vec!["MED-001".into(), "MED-002".into()],
        "GENESIS".into(),
        "signature_placeholder".into(),
    );
}
