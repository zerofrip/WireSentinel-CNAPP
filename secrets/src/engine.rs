use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CnappSeverity, SecretFinding, ServiceEventInner};
use uuid::Uuid;

const SECRET_PREFIXES: &[&str] = &["AKIA", "ghp_", "sk_live_", "-----BEGIN"];

struct SecretsState {
    findings: Vec<SecretFinding>,
}

impl Default for SecretsState {
    fn default() -> Self {
        Self { findings: Vec::new() }
    }
}

/// Secret scanning engine for repos, images, and cloud storage.
pub struct SecretsDetectionEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<SecretsState>,
}

impl<E: CnappEventEmitter> SecretsDetectionEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(SecretsState::default()),
        }
    }

    pub fn scan_content(&self, tenant_id: Uuid, location: &str, content: &str) -> CnappResult<()> {
        for prefix in SECRET_PREFIXES {
            if content.contains(prefix) {
                let finding = SecretFinding {
                    id: Uuid::new_v4(),
                    tenant_id,
                    location: location.into(),
                    secret_kind: prefix.trim_end_matches('_').into(),
                    severity: CnappSeverity::Critical,
                    redacted_preview: format!("{}***", prefix),
                    detected_at: Utc::now(),
                };
                self.emitter.emit(shared_types::ServiceEvent::now(
                    ServiceEventInner::SecretExposed {
                        finding: finding.clone(),
                    },
                ));
                self.state.write().findings.push(finding);
            }
        }
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

    #[test]
    fn detects_aws_key() {
        let emitter = CollectingEmitter::new();
        let engine = SecretsDetectionEngine::new(&emitter);
        engine
            .scan_content(Uuid::new_v4(), "config.env", "AKIAIOSFODNN7EXAMPLE")
            .unwrap();
        assert_eq!(engine.finding_count(), 1);
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn clean_content_is_silent() {
        let emitter = CollectingEmitter::new();
        let engine = SecretsDetectionEngine::new(&emitter);
        engine
            .scan_content(Uuid::new_v4(), "readme.md", "no secrets here")
            .unwrap();
        assert!(emitter.drain().is_empty());
    }
}
