use chrono::Utc;
use cnapp_core::{CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{SbomDocument, ServiceEventInner};
use uuid::Uuid;

struct SbomState {
    documents: Vec<SbomDocument>,
}

impl Default for SbomState {
    fn default() -> Self {
        Self { documents: Vec::new() }
    }
}

/// SBOM engine for CycloneDX and SPDX documents.
pub struct SbomEngine<E: CnappEventEmitter> {
    emitter: E,
    state: RwLock<SbomState>,
}

impl<E: CnappEventEmitter> SbomEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            state: RwLock::new(SbomState::default()),
        }
    }

    pub fn generate(
        &self,
        tenant_id: Uuid,
        artifact_name: &str,
        artifact_version: &str,
        component_count: u32,
    ) -> CnappResult<SbomDocument> {
        let document = SbomDocument {
            id: Uuid::new_v4(),
            tenant_id,
            format: "cyclonedx".into(),
            artifact_name: artifact_name.into(),
            artifact_version: artifact_version.into(),
            component_count,
            generated_at: Utc::now(),
        };
        self.emitter.emit(shared_types::ServiceEvent::now(
            ServiceEventInner::SbomGenerated {
                document: document.clone(),
            },
        ));
        self.state.write().documents.push(document.clone());
        Ok(document)
    }

    pub fn import(&self, document: SbomDocument) -> CnappResult<()> {
        self.emitter.emit(shared_types::ServiceEvent::now(
            ServiceEventInner::SbomImported {
                document: document.clone(),
            },
        ));
        self.state.write().documents.push(document);
        Ok(())
    }

    pub fn document_count(&self) -> usize {
        self.state.read().documents.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    #[test]
    fn generates_sbom() {
        let emitter = CollectingEmitter::new();
        let engine = SbomEngine::new(&emitter);
        let doc = engine
            .generate(Uuid::new_v4(), "app", "1.0.0", 42)
            .unwrap();
        assert_eq!(doc.component_count, 42);
        assert_eq!(emitter.drain().len(), 1);
    }

    #[test]
    fn imports_sbom() {
        let emitter = CollectingEmitter::new();
        let engine = SbomEngine::new(&emitter);
        engine
            .import(SbomDocument {
                id: Uuid::new_v4(),
                tenant_id: Uuid::new_v4(),
                format: "spdx".into(),
                artifact_name: "lib".into(),
                artifact_version: "2.0".into(),
                component_count: 10,
                generated_at: Utc::now(),
            })
            .unwrap();
        assert_eq!(engine.document_count(), 1);
    }
}
