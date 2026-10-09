//! evidence_core — minimal, deterministic EvidencePack emission + verification.

pub mod verify;

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use chrono::Utc;

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct EvidencePack {
    pub pack_id: String,
    pub created_at_utc: String,
    pub service: String,
    pub service_version: String,
    pub gateway_version: String,
    pub request: serde_json::Value,
    pub response: serde_json::Value,
    pub invariants: Vec<String>,
    pub runtime_context: RuntimeContext,
    pub hash_chain: HashChain,
    pub signature: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct RuntimeContext {
    pub node_id: String,
    pub pod_id: String,
    pub region: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct HashChain {
    pub prev_hash: String,
    pub current_hash: String,
}

impl EvidencePack {
    pub fn new(
        service: &str,
        service_version: &str,
        gateway_version: &str,
        request: serde_json::Value,
        response: serde_json::Value,
        invariants: Vec<String>,
        prev_hash: String,
        runtime: RuntimeContext,
        signature: String,
    ) -> Self {
        let created_at_utc = Utc::now().to_rfc3339();

        let mut hasher = Sha256::new();
        hasher.update(created_at_utc.as_bytes());
        hasher.update(service.as_bytes());
        hasher.update(service_version.as_bytes());
        hasher.update(gateway_version.as_bytes());
        hasher.update(serde_json::to_vec(&request).expect("request serialize"));
        hasher.update(serde_json::to_vec(&response).expect("response serialize"));
        hasher.update(prev_hash.as_bytes());
        let current_hash = format!("{:x}", hasher.finalize());

        EvidencePack {
            pack_id: current_hash.clone(),
            created_at_utc,
            service: service.to_string(),
            service_version: service_version.to_string(),
            gateway_version: gateway_version.to_string(),
            request,
            response,
            invariants,
            runtime_context: runtime,
            hash_chain: HashChain {
                prev_hash,
                current_hash,
            },
            signature,
        }
    }

    /// Persist to a deterministic path under `evidence/`.
    pub fn write_to_disk(&self, prefix: &str) -> std::io::Result<()> {
        std::fs::create_dir_all("evidence")?;
        let path = format!("evidence/{}_{}.json", prefix, self.pack_id);
        let data = serde_json::to_string_pretty(self).expect("pack serialize");
        std::fs::write(path, data)
    }
}

/// Convenience helper used by every service handler.
pub fn emit_pack(
    service: &str,
    service_version: &str,
    gateway_version: &str,
    path: &str,
    body: serde_json::Value,
    response: &impl Serialize,
    invariants: Vec<String>,
    prev_hash: String,
    signature: String,
) -> EvidencePack {
    let runtime = RuntimeContext {
        node_id: std::env::var("NODE_ID").unwrap_or_else(|_| "node-1".into()),
        pod_id: std::env::var("POD_ID").unwrap_or_else(|_| "pod-1".into()),
        region: std::env::var("REGION").unwrap_or_else(|_| "us-central-1".into()),
    };

    let req_json = serde_json::json!({ "path": path, "body": body });
    let resp_json = serde_json::to_value(response).expect("response to value");

    let pack = EvidencePack::new(
        service,
        service_version,
        gateway_version,
        req_json,
        resp_json,
        invariants,
        prev_hash,
        runtime,
        signature,
    );

    let _ = pack.write_to_disk(service);
    pack
}
