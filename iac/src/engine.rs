use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CnappSeverity, IacFinding, ServiceEventInner};
use uuid::Uuid;

struct IacState {
    findings: Vec<IacFinding>,
}

impl Default for IacState {
    fn default() -> Self {
        Self { findings: Vec::new() }
    }
}

/// IaC scanning engine for Terraform, CloudFormation, and Kubernetes manifests.
pub struct IacSecurityEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<IacState>,
}

impl<E: CnappEventEmitter> IacSecurityEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(IacState::default()),
        }
    }

    pub fn scan_finding(&self, finding: IacFinding) -> CnappResult<()> {
        if finding.severity >= CnappSeverity::Low {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::IacFindingDetected {
                    finding: finding.clone(),
                },
            ));
        }
        self.state.write().findings.push(finding);
        Ok(())
    }

    pub fn finding_count(&self) -> usize {
        self.state.read().findings.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    fn sample(severity: CnappSeverity) -> IacFinding {
        IacFinding {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            file_path: "main.tf".into(),
            iac_kind: "terraform".into(),
            rule_id: "TF001".into(),
            severity,
            message: "S3 bucket is public".into(),
            detected_at: Utc::now(),
        }
    }

    #[test]
    fn emits_iac_finding() {
        let emitter = CollectingEmitter::new();
        let engine = IacSecurityEngine::new(&emitter);
        engine.scan_finding(sample(CnappSeverity::High)).unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn stores_findings() {
        let emitter = CollectingEmitter::new();
        let engine = IacSecurityEngine::new(&emitter);
        engine.scan_finding(sample(CnappSeverity::Medium)).unwrap();
        assert_eq!(engine.finding_count(), 1);
    }
}
