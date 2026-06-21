use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CnappSeverity, KubernetesFinding, ServiceEventInner};
use uuid::Uuid;

struct K8sState {
    findings: Vec<KubernetesFinding>,
}

impl Default for K8sState {
    fn default() -> Self {
        Self { findings: Vec::new() }
    }
}

/// Kubernetes security engine for cluster and workload risk.
pub struct KubernetesSecurityEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<K8sState>,
}

impl<E: CnappEventEmitter> KubernetesSecurityEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(K8sState::default()),
        }
    }

    pub fn ingest_finding(&self, finding: KubernetesFinding) -> CnappResult<()> {
        self.analyze_finding(&finding);
        self.state.write().findings.push(finding);
        Ok(())
    }

    pub fn finding_count(&self) -> usize {
        self.state.read().findings.len()
    }

    fn analyze_finding(&self, finding: &KubernetesFinding) {
        if finding.finding_kind.contains("privileged") || finding.severity >= CnappSeverity::High {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::KubernetesRiskDetected {
                    finding: finding.clone(),
                },
            ));
        }
        if finding.finding_kind.contains("compromise") || finding.resource_name.contains("exfil") {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::ClusterCompromiseSuspected {
                    finding: finding.clone(),
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    fn sample_finding(kind: &str, name: &str, severity: CnappSeverity) -> KubernetesFinding {
        KubernetesFinding {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            cluster_id: "prod".into(),
            namespace: "default".into(),
            resource_kind: "Pod".into(),
            resource_name: name.into(),
            finding_kind: kind.into(),
            severity,
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn detects_privileged_pod() {
        let emitter = CollectingEmitter::new();
        let engine = KubernetesSecurityEngine::new(&emitter);
        engine
            .ingest_finding(sample_finding("privileged_container", "web", CnappSeverity::High))
            .unwrap();
        assert!(!emitter.drain().is_empty());
    }

    #[test]
    fn low_severity_is_quiet() {
        let emitter = CollectingEmitter::new();
        let engine = KubernetesSecurityEngine::new(&emitter);
        engine
            .ingest_finding(sample_finding("info", "web", CnappSeverity::Low))
            .unwrap();
        assert!(emitter.drain().is_empty());
    }
}
