use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CnappSeverity, ComplianceControl, ComplianceScore, ServiceEventInner};
use uuid::Uuid;

struct ComplianceState {
    controls: Vec<ComplianceControl>,
    scores: Vec<ComplianceScore>,
}

impl Default for ComplianceState {
    fn default() -> Self {
        Self {
            controls: Vec::new(),
            scores: Vec::new(),
        }
    }
}

/// Compliance engine for CIS, PCI, and SOC2 frameworks.
pub struct ComplianceEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<ComplianceState>,
}

impl<E: CnappEventEmitter> ComplianceEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(ComplianceState::default()),
        }
    }

    pub fn register_control(&self, control: ComplianceControl) -> CnappResult<()> {
        self.state.write().controls.push(control);
        Ok(())
    }

    pub fn record_violation(&self, control: ComplianceControl, severity: CnappSeverity) -> CnappResult<()> {
        self.emitter.emit(shared_types::ServiceEvent::now(
            ServiceEventInner::ComplianceViolation { control, severity },
        ));
        Ok(())
    }

    pub fn update_score(&self, score: ComplianceScore) -> CnappResult<()> {
        self.emitter.emit(shared_types::ServiceEvent::now(
            ServiceEventInner::ComplianceScoreUpdated {
                score: score.clone(),
            },
        ));
        self.state.write().scores.push(score);
        Ok(())
    }

    pub fn control_count(&self) -> usize {
        self.state.read().controls.len()
    }

    pub fn latest_score(&self, tenant_id: Uuid, framework: &str) -> Option<ComplianceScore> {
        self.state
            .read()
            .scores
            .iter()
            .rev()
            .find(|s| s.tenant_id == tenant_id && s.framework == framework)
            .cloned()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    fn sample_control() -> ComplianceControl {
        ComplianceControl {
            id: Uuid::new_v4(),
            framework: "cis".into(),
            control_id: "1.1".into(),
            title: "MFA enabled".into(),
            description: None,
        }
    }

    #[test]
    fn records_violation() {
        let emitter = CollectingEmitter::new();
        let engine = ComplianceEngine::new(&emitter);
        engine
            .record_violation(sample_control(), CnappSeverity::High)
            .unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn updates_score() {
        let emitter = CollectingEmitter::new();
        let engine = ComplianceEngine::new(&emitter);
        let tenant = Uuid::new_v4();
        engine
            .update_score(ComplianceScore {
                tenant_id: tenant,
                framework: "cis".into(),
                score_pct: 92.5,
                passing_controls: 37,
                failing_controls: 3,
                computed_at: Utc::now(),
            })
            .unwrap();
        assert!(engine.latest_score(tenant, "cis").is_some());
    }
}
