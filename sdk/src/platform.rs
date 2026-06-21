use std::sync::Arc;

use analytics::MultiCloudAnalyticsService;
use attack_path::CloudAttackPathEngine;
use compliance::ComplianceEngine;
use containers::ContainerSecurityEngine;
use cspm::CloudPostureEngine;
use cwpp::CloudWorkloadProtectionEngine;
use iac::IacSecurityEngine;
use kubernetes::KubernetesSecurityEngine;
use sbom::SbomEngine;
use secrets::SecretsDetectionEngine;
use supply_chain::SupplyChainSecurityEngine;
use vulnerabilities::VulnerabilityEngine;
use cnapp_core::CollectingEmitter;

/// Facade bundling all CNAPP engines behind a shared event emitter.
pub struct CnappPlatform {
    pub emitter: Arc<CollectingEmitter>,
    pub cspm: CloudPostureEngine<Arc<CollectingEmitter>>,
    pub cwpp: CloudWorkloadProtectionEngine<Arc<CollectingEmitter>>,
    pub kubernetes: KubernetesSecurityEngine<Arc<CollectingEmitter>>,
    pub containers: ContainerSecurityEngine<Arc<CollectingEmitter>>,
    pub iac: IacSecurityEngine<Arc<CollectingEmitter>>,
    pub secrets: SecretsDetectionEngine<Arc<CollectingEmitter>>,
    pub supply_chain: SupplyChainSecurityEngine<Arc<CollectingEmitter>>,
    pub sbom: SbomEngine<Arc<CollectingEmitter>>,
    pub vulnerabilities: VulnerabilityEngine<Arc<CollectingEmitter>>,
    pub attack_path: CloudAttackPathEngine<Arc<CollectingEmitter>>,
    pub compliance: ComplianceEngine<Arc<CollectingEmitter>>,
    pub analytics: MultiCloudAnalyticsService,
}

impl CnappPlatform {
    pub fn new() -> Self {
        let emitter = Arc::new(CollectingEmitter::new());

        Self {
            cspm: CloudPostureEngine::new(emitter.clone()),
            cwpp: CloudWorkloadProtectionEngine::new(emitter.clone()),
            kubernetes: KubernetesSecurityEngine::new(emitter.clone()),
            containers: ContainerSecurityEngine::new(emitter.clone()),
            iac: IacSecurityEngine::new(emitter.clone()),
            secrets: SecretsDetectionEngine::new(emitter.clone()),
            supply_chain: SupplyChainSecurityEngine::new(emitter.clone()),
            sbom: SbomEngine::new(emitter.clone()),
            vulnerabilities: VulnerabilityEngine::new(emitter.clone()),
            attack_path: CloudAttackPathEngine::new(emitter.clone()),
            compliance: ComplianceEngine::new(emitter.clone()),
            analytics: MultiCloudAnalyticsService::new(),
            emitter,
        }
    }

    pub fn drain_events(&self) -> Vec<shared_types::ServiceEvent> {
        self.emitter.drain()
    }
}

impl Default for CnappPlatform {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::{CloudProvider, CloudResource};
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn platform_bundles_engines() {
        let platform = CnappPlatform::new();
        assert_eq!(platform.cspm.resource_count(), 0);
        assert_eq!(platform.compliance.control_count(), 0);
    }

    #[test]
    fn shared_emitter_collects_events() {
        let platform = CnappPlatform::new();
        platform
            .cspm
            .ingest_resource(CloudResource {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                provider: CloudProvider::Aws,
                resource_type: "s3.bucket".into(),
                resource_id: "bucket".into(),
                region: "us-east-1".into(),
                tags: serde_json::json!({"public": true}),
                observed_at: Utc::now(),
            })
            .unwrap();
        assert!(!platform.drain_events().is_empty());
    }
}
