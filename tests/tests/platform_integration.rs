use chrono::Utc;
use shared_types::{CloudProvider, CloudResource};
use uuid::Uuid;
use cnapp_controller::CnappIngestPayload;
use cnapp_sdk::CnappPlatform;

#[test]
fn end_to_end_ingest_and_posture() {
    let platform = CnappPlatform::new();
    let tenant = Uuid::new_v4();

    let payload = CnappIngestPayload {
        tenant_id: tenant,
        agent_id: Uuid::new_v4(),
        resources: vec![CloudResource {
            id: Uuid::new_v4(),
            tenant_id: tenant,
            provider: CloudProvider::Aws,
            resource_type: "s3.bucket".into(),
            resource_id: "public-data".into(),
            region: "us-west-2".into(),
            tags: serde_json::json!({"public": true}),
            observed_at: Utc::now(),
        }],
        ..CnappIngestPayload::empty(tenant, Uuid::new_v4())
    };

    for resource in payload.resources {
        platform.cspm.ingest_resource(resource).unwrap();
    }

    assert!(platform.cspm.finding_count() > 0 || !platform.drain_events().is_empty());
}

#[test]
fn platform_modules_initialized() {
    let platform = CnappPlatform::new();
    assert_eq!(platform.cspm.resource_count(), 0);
    assert_eq!(platform.sbom.document_count(), 0);
}
