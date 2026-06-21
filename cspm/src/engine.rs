use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{CloudProvider, CloudResource, CnappSeverity, PostureFinding, ServiceEventInner};
use uuid::Uuid;

struct CspmState {
    resources: Vec<CloudResource>,
    findings: Vec<PostureFinding>,
    risk_score: f64,
}

impl Default for CspmState {
    fn default() -> Self {
        Self {
            resources: Vec::new(),
            findings: Vec::new(),
            risk_score: 0.0,
        }
    }
}

/// Cloud posture engine for misconfiguration and policy drift detection.
pub struct CloudPostureEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<CspmState>,
}

impl<E: CnappEventEmitter> CloudPostureEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(CspmState::default()),
        }
    }

    pub fn ingest_resource(&self, resource: CloudResource) -> CnappResult<()> {
        self.analyze_resource(&resource);
        self.state.write().resources.push(resource);
        Ok(())
    }

    pub fn resource_count(&self) -> usize {
        self.state.read().resources.len()
    }

    pub fn finding_count(&self) -> usize {
        self.state.read().findings.len()
    }

    pub fn risk_score(&self) -> f64 {
        self.state.read().risk_score
    }

    fn analyze_resource(&self, resource: &CloudResource) {
        let tags = resource.tags.to_string().to_lowercase();
        if tags.contains("public=true") || tags.contains("\"public\":true") {
            let finding = PostureFinding {
                id: Uuid::new_v4(),
                tenant_id: resource.tenant_id,
                provider: resource.provider,
                resource_id: resource.resource_id.clone(),
                control_id: "cspm.public_exposure".into(),
                title: "Public cloud resource".into(),
                severity: CnappSeverity::High,
                description: Some("Resource tagged or configured as public".into()),
                detected_at: Utc::now(),
            };
            self.record_finding(finding.clone(), true);
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::CloudMisconfigurationDetected { finding },
            ));
        }

        if resource.resource_type.contains("iam") && tags.contains("admin") {
            let finding = PostureFinding {
                id: Uuid::new_v4(),
                tenant_id: resource.tenant_id,
                provider: resource.provider,
                resource_id: resource.resource_id.clone(),
                control_id: "cspm.overprivileged".into(),
                title: "Overprivileged IAM binding".into(),
                severity: CnappSeverity::Critical,
                description: None,
                detected_at: Utc::now(),
            };
            self.record_finding(finding.clone(), false);
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::CloudPolicyViolation { finding },
            ));
        }
    }

    fn record_finding(&self, finding: PostureFinding, increase_risk: bool) {
        let mut state = self.state.write();
        if increase_risk {
            let previous = state.risk_score;
            state.risk_score = (state.risk_score + 10.0).min(100.0);
            if state.risk_score > previous {
                self.emitter.emit(shared_types::ServiceEvent::now(
                    ServiceEventInner::CloudRiskIncreased {
                        tenant_id: finding.tenant_id,
                        previous_score: previous,
                        current_score: state.risk_score,
                    },
                ));
            }
        }
        state.findings.push(finding);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    fn sample_resource(public: bool) -> CloudResource {
        CloudResource {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            provider: CloudProvider::Aws,
            resource_type: "s3.bucket".into(),
            resource_id: "bucket-1".into(),
            region: "us-east-1".into(),
            tags: serde_json::json!({"public": public}),
            observed_at: Utc::now(),
        }
    }

    #[test]
    fn detects_public_resource() {
        let emitter = CollectingEmitter::new();
        let engine = CloudPostureEngine::new(&emitter);
        engine.ingest_resource(sample_resource(true)).unwrap();
        assert_eq!(engine.resource_count(), 1);
        assert_eq!(engine.finding_count(), 1);
        assert!(!emitter.drain().is_empty());
    }

    #[test]
    fn clean_resource_has_no_findings() {
        let emitter = CollectingEmitter::new();
        let engine = CloudPostureEngine::new(&emitter);
        engine.ingest_resource(sample_resource(false)).unwrap();
        assert_eq!(engine.finding_count(), 0);
        assert!(emitter.drain().is_empty());
    }
}
