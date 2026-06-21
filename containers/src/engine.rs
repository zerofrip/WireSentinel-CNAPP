use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CnappSeverity, ContainerFinding, ServiceEventInner};
use uuid::Uuid;

struct ContainerState {
    findings: Vec<ContainerFinding>,
}

impl Default for ContainerState {
    fn default() -> Self {
        Self { findings: Vec::new() }
    }
}

/// Container runtime security engine.
pub struct ContainerSecurityEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<ContainerState>,
}

impl<E: CnappEventEmitter> ContainerSecurityEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(ContainerState::default()),
        }
    }

    pub fn ingest_finding(&self, finding: ContainerFinding) -> CnappResult<()> {
        self.analyze_finding(&finding);
        self.state.write().findings.push(finding);
        Ok(())
    }

    pub fn finding_count(&self) -> usize {
        self.state.read().findings.len()
    }

    fn analyze_finding(&self, finding: &ContainerFinding) {
        if finding.severity >= CnappSeverity::Medium {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::ContainerRiskDetected {
                    finding: finding.clone(),
                },
            ));
        }
        if finding.finding_kind.contains("escape") || finding.finding_kind.contains("shell") {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::ContainerThreatDetected {
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

    fn sample(kind: &str, severity: CnappSeverity) -> ContainerFinding {
        ContainerFinding {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            container_id: "ctr-1".into(),
            image: "app:latest".into(),
            finding_kind: kind.into(),
            severity,
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn detects_container_escape() {
        let emitter = CollectingEmitter::new();
        let engine = ContainerSecurityEngine::new(&emitter);
        engine
            .ingest_finding(sample("container_escape", CnappSeverity::Critical))
            .unwrap();
        assert_eq!(emitter.drain().len(), 2);
    }

    #[test]
    fn low_risk_is_quiet() {
        let emitter = CollectingEmitter::new();
        let engine = ContainerSecurityEngine::new(&emitter);
        engine
            .ingest_finding(sample("info", CnappSeverity::Low))
            .unwrap();
        assert!(emitter.drain().is_empty());
    }
}
