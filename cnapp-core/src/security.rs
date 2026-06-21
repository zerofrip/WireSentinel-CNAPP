use shared_types::{
    CnappSecurityPolicy, CnappSecurityViolationDetail, IacFinding, SbomDocument, SecretFinding,
    ServiceEvent, ServiceEventInner,
};

use crate::{CnappError, CnappEventEmitter, CnappResult};

/// Validates CNAPP mutations against tenant security policy.
pub struct CnappSecurityPolicyEngine<E: CnappEventEmitter> {
    emitter: E,
}

impl<E: CnappEventEmitter> CnappSecurityPolicyEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self { emitter }
    }

    pub fn validate_iac_finding(
        &self,
        policy: &CnappSecurityPolicy,
        findings: &[IacFinding],
        finding: &IacFinding,
    ) -> CnappResult<()> {
        if findings.len() as u32 >= policy.max_iac_findings_per_scan {
            self.violation("iac", "scan finding limit exceeded", &finding.file_path);
            return Err(CnappError::Security("iac finding limit exceeded".into()));
        }
        if finding.message.contains("'; DROP") {
            self.violation("iac", "dangerous pattern", &finding.file_path);
            return Err(CnappError::Security("dangerous iac pattern".into()));
        }
        Ok(())
    }

    pub fn validate_secret_finding(
        &self,
        policy: &CnappSecurityPolicy,
        count: u32,
        finding: &SecretFinding,
    ) -> CnappResult<()> {
        if count > policy.max_secrets_per_repo {
            self.violation("secrets", "secret limit exceeded", &finding.location);
            return Err(CnappError::Security("secret finding limit exceeded".into()));
        }
        Ok(())
    }

    pub fn validate_sbom(&self, policy: &CnappSecurityPolicy, document: &SbomDocument) -> CnappResult<()> {
        if !policy
            .allowed_sbom_formats
            .iter()
            .any(|f| f.eq_ignore_ascii_case(&document.format))
        {
            self.violation("sbom", "format not allowed", &document.artifact_name);
            return Err(CnappError::Security("sbom format not permitted".into()));
        }
        Ok(())
    }

    pub fn validate_compliance_framework(
        &self,
        policy: &CnappSecurityPolicy,
        framework: &str,
    ) -> CnappResult<()> {
        if !policy
            .required_compliance_frameworks
            .iter()
            .any(|f| f.eq_ignore_ascii_case(framework))
        {
            self.violation("compliance", "framework not required", framework);
            return Err(CnappError::Security("compliance framework not tracked".into()));
        }
        Ok(())
    }

    fn violation(&self, violation_type: &str, detail: &str, resource: &str) {
        let _detail = CnappSecurityViolationDetail {
            violation_type: violation_type.to_string(),
            detail: detail.to_string(),
            resource: resource.to_string(),
        };
        self.emitter.emit(ServiceEvent::now(ServiceEventInner::CnappSecurityViolation {
            violation_type: violation_type.to_string(),
            detail: format!("{}: {}", detail, resource),
        }));
    }
}
