use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CnappSeverity, DependencyRecord, ServiceEventInner};
use uuid::Uuid;

const MALICIOUS_PACKAGES: &[&str] = &["event-stream", "flatmap-stream", "ua-parser-js"];

struct SupplyChainState {
    dependencies: Vec<DependencyRecord>,
}

impl Default for SupplyChainState {
    fn default() -> Self {
        Self {
            dependencies: Vec::new(),
        }
    }
}

/// Supply-chain risk engine for dependency analysis.
pub struct SupplyChainSecurityEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<SupplyChainState>,
}

impl<E: CnappEventEmitter> SupplyChainSecurityEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(SupplyChainState::default()),
        }
    }

    pub fn ingest_dependency(&self, dependency: DependencyRecord) -> CnappResult<()> {
        self.analyze_dependency(&dependency);
        self.state.write().dependencies.push(dependency);
        Ok(())
    }

    pub fn dependency_count(&self) -> usize {
        self.state.read().dependencies.len()
    }

    fn analyze_dependency(&self, dependency: &DependencyRecord) {
        if MALICIOUS_PACKAGES.contains(&dependency.package_name.as_str()) {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::SupplyChainThreatDetected {
                    dependency: dependency.clone(),
                },
            ));
            return;
        }
        if !dependency.direct && dependency.version.starts_with("0.0.") {
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::DependencyRiskDetected {
                    dependency: dependency.clone(),
                    severity: CnappSeverity::Medium,
                },
            ));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    fn sample(name: &str, version: &str, direct: bool) -> DependencyRecord {
        DependencyRecord {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            package_name: name.into(),
            version: version.into(),
            ecosystem: "npm".into(),
            direct,
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn detects_malicious_package() {
        let emitter = CollectingEmitter::new();
        let engine = SupplyChainSecurityEngine::new(&emitter);
        engine.ingest_dependency(sample("event-stream", "3.3.6", true)).unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn flags_transitive_prerelease() {
        let emitter = CollectingEmitter::new();
        let engine = SupplyChainSecurityEngine::new(&emitter);
        engine
            .ingest_dependency(sample("lodash", "0.0.1", false))
            .unwrap();
        assert_eq!(emitter.drain().len(), 1);
    }
}
