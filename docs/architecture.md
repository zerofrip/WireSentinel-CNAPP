# WireSentinel-CNAPP Architecture

```
Cloud → Controller → CNAPP Platform → XDR → SSE → Core → Guardian
```

## Data Flow

1. Cloud inventory and workload telemetry ingested from WireSentinel-Controller
2. CSPM/CWPP/Kubernetes/Container engines analyze posture and runtime risk
3. IaC, secrets, SBOM, and vulnerability engines enrich the risk graph
4. Attack-path engine correlates cloud exposure using XDR attack-graph adapter
5. Compliance engine tracks framework scores and violations
6. Multi-cloud analytics aggregates fleet risk for Controller dashboards
