use chrono::Utc;
use parking_lot::RwLock;
use shared_types::{
    CnappAnalyticsSummary, CnappSeverity, CloudAttackPath, ComplianceScore, PostureFinding,
    SecretFinding, Vulnerability,
};
use uuid::Uuid;

struct AnalyticsState {
    posture_findings: Vec<PostureFinding>,
    vulnerabilities: Vec<Vulnerability>,
    secrets: Vec<SecretFinding>,
    attack_paths: Vec<CloudAttackPath>,
    compliance_scores: Vec<ComplianceScore>,
}

impl Default for AnalyticsState {
    fn default() -> Self {
        Self {
            posture_findings: Vec::new(),
            vulnerabilities: Vec::new(),
            secrets: Vec::new(),
            attack_paths: Vec::new(),
            compliance_scores: Vec::new(),
        }
    }
}

/// Aggregates CNAPP signals into multi-cloud fleet analytics.
pub struct MultiCloudAnalyticsService {
    state: RwLock<AnalyticsState>,
}

impl MultiCloudAnalyticsService {
    pub fn new() -> Self {
        Self {
            state: RwLock::new(AnalyticsState::default()),
        }
    }

    pub fn record_posture_finding(&self, finding: PostureFinding) {
        self.state.write().posture_findings.push(finding);
    }

    pub fn record_vulnerability(&self, vulnerability: Vulnerability) {
        self.state.write().vulnerabilities.push(vulnerability);
    }

    pub fn record_secret(&self, finding: SecretFinding) {
        self.state.write().secrets.push(finding);
    }

    pub fn record_attack_path(&self, path: CloudAttackPath) {
        self.state.write().attack_paths.push(path);
    }

    pub fn record_compliance_score(&self, score: ComplianceScore) {
        self.state.write().compliance_scores.push(score);
    }

    pub fn summarize(&self, tenant_id: Uuid) -> CnappAnalyticsSummary {
        let state = self.state.read();
        let posture: Vec<_> = state
            .posture_findings
            .iter()
            .filter(|f| f.tenant_id == tenant_id)
            .collect();
        let critical = posture
            .iter()
            .filter(|f| f.severity == CnappSeverity::Critical)
            .count() as u64;
        let vulns = state
            .vulnerabilities
            .iter()
            .filter(|v| v.tenant_id == tenant_id)
            .count() as u64;
        let secrets = state
            .secrets
            .iter()
            .filter(|s| s.tenant_id == tenant_id)
            .count() as u64;
        let attack_paths = state
            .attack_paths
            .iter()
            .filter(|p| p.tenant_id == tenant_id)
            .count() as u64;
        let compliance_score_pct = state
            .compliance_scores
            .iter()
            .rev()
            .find(|s| s.tenant_id == tenant_id)
            .map(|s| s.score_pct)
            .unwrap_or(100.0);

        let cloud_risk_score = compute_risk_score(
            posture.len() as u64,
            critical,
            vulns,
            secrets,
            attack_paths,
        );

        CnappAnalyticsSummary {
            tenant_id,
            total_posture_findings: posture.len() as u64,
            critical_findings: critical,
            open_vulnerabilities: vulns,
            exposed_secrets: secrets,
            compliance_score_pct,
            attack_paths_discovered: attack_paths,
            cloud_risk_score,
            computed_at: Utc::now(),
        }
    }
}

impl Default for MultiCloudAnalyticsService {
    fn default() -> Self {
        Self::new()
    }
}

fn compute_risk_score(
    posture: u64,
    critical: u64,
    vulns: u64,
    secrets: u64,
    attack_paths: u64,
) -> f64 {
    (posture as f64 * 1.5
        + critical as f64 * 4.0
        + vulns as f64 * 2.0
        + secrets as f64 * 5.0
        + attack_paths as f64 * 3.0)
        .min(100.0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_types::CloudProvider;

    #[test]
    fn summarizes_tenant_metrics() {
        let svc = MultiCloudAnalyticsService::new();
        let tenant = Uuid::new_v4();
        svc.record_posture_finding(PostureFinding {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            provider: CloudProvider::Aws,
            resource_id: "bucket".into(),
            control_id: "1".into(),
            title: "Public bucket".into(),
            severity: CnappSeverity::Critical,
            description: None,
            detected_at: Utc::now(),
        });
        let summary = svc.summarize(tenant);
        assert_eq!(summary.total_posture_findings, 1);
        assert_eq!(summary.critical_findings, 1);
    }

    #[test]
    fn computes_risk_score() {
        let score = compute_risk_score(5, 2, 3, 1, 1);
        assert!(score > 0.0);
        assert!(score <= 100.0);
    }
}
