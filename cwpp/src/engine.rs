use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CloudProvider, CnappSeverity, ServiceEventInner, WorkloadRecord};
use uuid::Uuid;

const SUSPICIOUS_IMAGES: &[&str] = &["malware", "crypto-miner", "backdoor"];

struct CwppState {
    workloads: Vec<WorkloadRecord>,
}

impl Default for CwppState {
    fn default() -> Self {
        Self { workloads: Vec::new() }
    }
}

/// Cloud workload protection engine for runtime threat detection.
pub struct CloudWorkloadProtectionEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<CwppState>,
}

impl<E: CnappEventEmitter> CloudWorkloadProtectionEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(CwppState::default()),
        }
    }

    pub fn ingest_workload(&self, workload: WorkloadRecord) -> CnappResult<()> {
        self.analyze_workload(&workload);
        self.state.write().workloads.push(workload);
        Ok(())
    }

    pub fn workload_count(&self) -> usize {
        self.state.read().workloads.len()
    }

    fn analyze_workload(&self, workload: &WorkloadRecord) {
        let image = workload.image.as_deref().unwrap_or("").to_lowercase();
        let suspicious = SUSPICIOUS_IMAGES.iter().any(|p| image.contains(p));
        if suspicious {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::WorkloadThreatDetected {
                    workload: workload.clone(),
                    severity: CnappSeverity::High,
                },
            ));
        }
        if image.contains("compromised") || workload.name.contains("exfil") {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::WorkloadCompromised {
                    workload: workload.clone(),
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    fn sample_workload(image: &str, name: &str) -> WorkloadRecord {
        WorkloadRecord {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: CloudProvider::Aws,
            workload_kind: "vm".into(),
            name: name.into(),
            image: Some(image.into()),
            namespace: None,
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn detects_suspicious_image() {
        let emitter = CollectingEmitter::new();
        let engine = CloudWorkloadProtectionEngine::new(&emitter);
        engine
            .ingest_workload(sample_workload("registry/malware:latest", "app"))
            .unwrap();
        assert_eq!(engine.workload_count(), 1);
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn clean_workload_is_silent() {
        let emitter = CollectingEmitter::new();
        let engine = CloudWorkloadProtectionEngine::new(&emitter);
        engine
            .ingest_workload(sample_workload("registry/app:v1", "app"))
            .unwrap();
        assert!(emitter.drain().is_empty());
    }
}
