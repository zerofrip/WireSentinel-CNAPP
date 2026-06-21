use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{AffectedAsset, CloudProvider, CnappSeverity, ServiceEventInner, Vulnerability};
use uuid::Uuid;

struct VulnState {
    vulnerabilities: Vec<Vulnerability>,
}

impl Default for VulnState {
    fn default() -> Self {
        Self {
            vulnerabilities: Vec::new(),
        }
    }
}

/// Vulnerability scanning and prioritization engine.
pub struct VulnerabilityEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<VulnState>,
}

impl<E: CnappEventEmitter> VulnerabilityEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(VulnState::default()),
        }
    }

    pub fn ingest_vulnerability(
        &self,
        vulnerability: Vulnerability,
        asset: AffectedAsset,
    ) -> CnappResult<()> {
        if vulnerability.severity == CnappSeverity::Critical || vulnerability.cvss_score >= 9.0 {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::CriticalVulnerabilityDetected {
                    vulnerability: vulnerability.clone(),
                    asset,
                },
            ));
        }
        self.state.write().vulnerabilities.push(vulnerability);
        Ok(())
    }

    pub fn vulnerability_count(&self) -> usize {
        self.state.read().vulnerabilities.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    fn sample(severity: CnappSeverity, cvss: f64) -> (Vulnerability, AffectedAsset) {
        (
            Vulnerability {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                cve_id: "CVE-2024-0001".into(),
                severity,
                cvss_score: cvss,
                package_name: "openssl".into(),
                package_version: "1.1.1".into(),
                fixed_version: Some("3.0.0".into()),
                detected_at: Utc::now(),
            },
            AffectedAsset {
                id: Uuid::new_v4(),
                asset_kind: "workload".into(),
                identifier: "vm-1".into(),
                provider: CloudProvider::Aws,
            },
        )
    }

    #[test]
    fn emits_critical_vulnerability() {
        let emitter = CollectingEmitter::new();
        let engine = VulnerabilityEngine::new(&emitter);
        let (vuln, asset) = sample(CnappSeverity::Critical, 9.8);
        engine.ingest_vulnerability(vuln, asset).unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn low_severity_is_quiet() {
        let emitter = CollectingEmitter::new();
        let engine = VulnerabilityEngine::new(&emitter);
        let (vuln, asset) = sample(CnappSeverity::Low, 2.0);
        engine.ingest_vulnerability(vuln, asset).unwrap();
        assert!(emitter.drain().is_empty());
    }
}
