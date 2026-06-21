use chrono::Utc;
use cnapp_core::{CnappError, CnappEventEmitter, CnappResult};
use parking_lot::RwLock;
use shared_types::{
    AttackGraphEdge, AttackGraphEdgeKind, AttackGraphNode, AttackGraphNodeKind, CloudAttackPath,
    ServiceEventInner,
};
use uuid::Uuid;

struct AttackPathState {
    paths: Vec<CloudAttackPath>,
}

impl Default for AttackPathState {
    fn default() -> Self {
        Self { paths: Vec::new() }
    }
}

/// Cloud attack path engine using the XDR attack-graph adapter.
pub struct CloudAttackPathEngine<E: CnappEventEmitter> {
    emitter: E,
    graph: attack_graph::AttackGraphEngine,
    state: RwLock<AttackPathState>,
}

impl<E: CnappEventEmitter> CloudAttackPathEngine<E> {
    pub fn new(emitter: E) -> Self {
        Self {
            emitter,
            graph: attack_graph::AttackGraphEngine::new(),
            state: RwLock::new(AttackPathState::default()),
        }
    }

    pub fn graph(&self) -> &attack_graph::AttackGraphEngine {
        &self.graph
    }

    pub fn register_resource(
        &self,
        tenant_id: Uuid,
        label: &str,
        kind: AttackGraphNodeKind,
    ) -> Uuid {
        self.graph.add_node(AttackGraphNode {
            id: Uuid::new_v4(),
            tenant_id,
            node_kind: kind,
            label: label.into(),
            metadata: serde_json::json!({}),
        })
    }

    pub fn connect(
        &self,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        edge_kind: AttackGraphEdgeKind,
        weight: f64,
    ) -> Uuid {
        self.graph.add_edge(AttackGraphEdge {
            id: Uuid::new_v4(),
            tenant_id,
            source_id,
            target_id,
            edge_kind,
            weight,
        })
    }

    pub fn discover_path(
        &self,
        tenant_id: Uuid,
        source_id: Uuid,
        target_id: Uuid,
        source_label: &str,
        target_label: &str,
    ) -> CnappResult<Vec<CloudAttackPath>> {
        let raw_paths = self
            .graph
            .discover_paths(source_id, target_id, 8)
            .map_err(|e| CnappError::AttackPath(e.to_string()))?;

        let mut cloud_paths = Vec::new();
        for raw in raw_paths {
            let path = CloudAttackPath {
                id: Uuid::new_v4(),
                tenant_id,
                source_resource: source_label.into(),
                target_resource: target_label.into(),
                risk_score: raw.risk_score,
                node_ids: raw.nodes,
                edge_ids: raw.edges,
                discovered_at: Utc::now(),
            };
            self.emitter.emit(shared_types::ServiceEvent::now(
                ServiceEventInner::AttackPathDiscovered {
                    path: path.clone(),
                },
            ));
            cloud_paths.push(path);
        }

        self.state.write().paths.extend(cloud_paths.clone());
        Ok(cloud_paths)
    }

    pub fn path_count(&self) -> usize {
        self.state.read().paths.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cnapp_core::CollectingEmitter;

    #[test]
    fn discovers_cloud_attack_path() {
        let emitter = CollectingEmitter::new();
        let engine = CloudAttackPathEngine::new(&emitter);
        let tenant = Uuid::new_v4();
        let internet = engine.register_resource(tenant, "internet", AttackGraphNodeKind::Resource);
        let bucket = engine.register_resource(tenant, "public-bucket", AttackGraphNodeKind::Resource);
        let workload = engine.register_resource(tenant, "workload", AttackGraphNodeKind::Device);
        engine.connect(
            tenant,
            internet,
            bucket,
            AttackGraphEdgeKind::NetworkReachability,
            2.0,
        );
        engine.connect(
            tenant,
            bucket,
            workload,
            AttackGraphEdgeKind::Access,
            3.0,
        );

        let paths = engine
            .discover_path(tenant, internet, workload, "internet", "workload")
            .unwrap();
        assert!(!paths.is_empty());
        assert!(!emitter.drain().is_empty());
    }

    #[test]
    fn missing_node_returns_error() {
        let emitter = CollectingEmitter::new();
        let engine = CloudAttackPathEngine::new(&emitter);
        let err = engine
            .discover_path(
                Uuid::new_v4(),
                Uuid::new_v4(),
                Uuid::new_v4(),
                "a",
                "b",
            )
            .unwrap_err();
        assert!(matches!(err, CnappError::AttackPath(_)));
    }
}
