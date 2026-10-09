// Drop-in for IPDiag service

use evidence_core::emit_pack;
use serde_json::json;

const SERVICE: &str = "ipdiag";
const SERVICE_VERSION: &str = "v20261008-A";
const GATEWAY_VERSION: &str = "v20261008-G";

// GET /v1/ip/diag
fn emit_ip_diag(ip: &str, result: &impl serde::Serialize) {
    let _pack = emit_pack(
        SERVICE,
        SERVICE_VERSION,
        GATEWAY_VERSION,
        "/v1/ip/diag",
        json!({ "ip": ip }),
        result,
        vec!["IPD-001".into(), "IPD-002".into(), "IPD-003".into()],
        "GENESIS".into(),
        "signature_placeholder".into(),
    );
}
