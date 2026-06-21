//! Core CNAPP abstractions for WireSentinel Phase 18.

mod error;
mod emitter;
mod security;

pub use error::{CnappError, CnappResult};
pub use emitter::{CollectingEmitter, CnappEventEmitter, NullEmitter};
pub use security::CnappSecurityPolicyEngine;
pub use shared_types::{
    AffectedAsset, CloudAttackPath, CloudProvider, CloudResource, CnappAnalyticsSummary,
    CnappScanBundle, CnappSecurityPolicy, CnappSeverity, CnappTelemetryPayload,
    ComplianceControl, ComplianceScore, ContainerFinding, DependencyRecord, IacFinding,
    KubernetesFinding, PostureFinding, RemediationPlan, SbomDocument, SecretFinding,
    Vulnerability, WorkloadRecord,
};
