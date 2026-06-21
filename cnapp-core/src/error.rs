use thiserror::Error;

#[derive(Debug, Error)]
pub enum CnappError {
    #[error("cspm error: {0}")]
    Cspm(String),
    #[error("cwpp error: {0}")]
    Cwpp(String),
    #[error("kubernetes error: {0}")]
    Kubernetes(String),
    #[error("containers error: {0}")]
    Containers(String),
    #[error("iac error: {0}")]
    Iac(String),
    #[error("secrets error: {0}")]
    Secrets(String),
    #[error("supply chain error: {0}")]
    SupplyChain(String),
    #[error("sbom error: {0}")]
    Sbom(String),
    #[error("vulnerabilities error: {0}")]
    Vulnerabilities(String),
    #[error("attack path error: {0}")]
    AttackPath(String),
    #[error("compliance error: {0}")]
    Compliance(String),
    #[error("security error: {0}")]
    Security(String),
    #[error("{0}")]
    Other(String),
}

pub type CnappResult<T> = std::result::Result<T, CnappError>;
