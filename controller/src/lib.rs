//! DTO helpers for WireSentinel-Controller CNAPP ingest.

mod dto;

pub use dto::{
    CnappIngestPayload, CnappIngestResponse, CnappScanBundle, CnappTelemetryPayload,
    build_scan_bundle, build_telemetry_payload, parse_ingest_payload,
};
