use chrono::Utc;
use serde::{Deserialize, Serialize};
use shared_types::{
    CloudResource, ContainerFinding, IacFinding, KubernetesFinding, SecretFinding, WorkloadRecord,
};
use uuid::Uuid;

pub use shared_types::{CnappScanBundle, CnappTelemetryPayload};

/// Controller ingest payload wrapping CNAPP scan batches.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CnappIngestPayload {
    pub tenant_id: Uuid,
    pub agent_id: Uuid,
    pub resources: Vec<CloudResource>,
    pub workloads: Vec<WorkloadRecord>,
    pub kubernetes_findings: Vec<KubernetesFinding>,
    pub container_findings: Vec<ContainerFinding>,
    pub iac_findings: Vec<IacFinding>,
    pub secret_findings: Vec<SecretFinding>,
    pub ingested_at: chrono::DateTime<Utc>,
}

impl CnappIngestPayload {
    pub fn empty(tenant_id: Uuid, agent_id: Uuid) -> Self {
        Self {
            tenant_id,
            agent_id,
            resources: Vec::new(),
            workloads: Vec::new(),
            kubernetes_findings: Vec::new(),
            container_findings: Vec::new(),
            iac_findings: Vec::new(),
            secret_findings: Vec::new(),
            ingested_at: Utc::now(),
        }
    }

    pub fn event_count(&self) -> u32 {
        (self.resources.len()
            + self.workloads.len()
            + self.kubernetes_findings.len()
            + self.container_findings.len()
            + self.iac_findings.len()
            + self.secret_findings.len()) as u32
    }
}

/// Acknowledgement returned to Controller after ingest.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CnappIngestResponse {
    pub accepted: bool,
    pub events_processed: u32,
    pub message: String,
}

pub fn parse_ingest_payload(json: &str) -> Result<CnappIngestPayload, serde_json::Error> {
    serde_json::from_str(json)
}

pub fn build_telemetry_payload(
    agent_id: Uuid,
    tenant_id: Uuid,
    posture: u32,
    workloads: u32,
    kubernetes: u32,
    containers: u32,
    iac: u32,
    secrets: u32,
    vulnerabilities: u32,
    compliance_score_pct: f64,
) -> CnappTelemetryPayload {
    CnappTelemetryPayload {
        agent_id,
        tenant_id,
        reported_at: Utc::now(),
        posture_findings: posture,
        workload_records: workloads,
        kubernetes_findings: kubernetes,
        container_findings: containers,
        iac_findings: iac,
        secret_findings: secrets,
        vulnerabilities,
        compliance_score_pct,
    }
}

pub fn build_scan_bundle(bundle: CnappScanBundle) -> CnappScanBundle {
    bundle
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_payload_has_zero_events() {
        let payload = CnappIngestPayload::empty(Uuid::new_v4(), Uuid::new_v4());
        assert_eq!(payload.event_count(), 0);
    }

    #[test]
    fn roundtrips_json() {
        let payload = CnappIngestPayload::empty(Uuid::new_v4(), Uuid::new_v4());
        let json = serde_json::to_string(&payload).unwrap();
        let parsed = parse_ingest_payload(&json).unwrap();
        assert_eq!(parsed.tenant_id, payload.tenant_id);
    }
}
