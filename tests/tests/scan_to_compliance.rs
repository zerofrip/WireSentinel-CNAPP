use chrono::Utc;
use shared_types::{CnappSeverity, ComplianceControl, ComplianceScore};
use uuid::Uuid;
use cnapp_sdk::CnappPlatform;

#[test]
fn scan_updates_compliance_score() {
    let platform = CnappPlatform::new();
    let tenant = Uuid::new_v4();

    platform
        .compliance
        .record_violation(
            ComplianceControl {
                id: Uuid::new_v4(),
                framework: "cis".into(),
                control_id: "1.2".into(),
                title: "Logging enabled".into(),
                description: None,
            },
            CnappSeverity::Medium,
        )
        .unwrap();

    platform
        .compliance
        .update_score(ComplianceScore {
            tenant_id: tenant,
            framework: "cis".into(),
            score_pct: 88.0,
            passing_controls: 44,
            failing_controls: 6,
            computed_at: Utc::now(),
        })
        .unwrap();

    platform.analytics.record_compliance_score(ComplianceScore {
        tenant_id: tenant,
        framework: "cis".into(),
        score_pct: 88.0,
        passing_controls: 44,
        failing_controls: 6,
        computed_at: Utc::now(),
    });

    let summary = platform.analytics.summarize(tenant);
    assert_eq!(summary.compliance_score_pct, 88.0);
    assert!(!platform.drain_events().is_empty());
}

#[test]
fn compliance_engine_tracks_controls() {
    let platform = CnappPlatform::new();
    platform
        .compliance
        .register_control(ComplianceControl {
            id: Uuid::new_v4(),
            framework: "pci".into(),
            control_id: "10.1".into(),
            title: "Audit trails".into(),
            description: None,
        })
        .unwrap();
    assert_eq!(platform.compliance.control_count(), 1);
}
