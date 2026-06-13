//! `ngxora-runtime` is the Pingora-facing execution layer.
//!
//! Module map:
//! - `grpc`: protobuf wire adapter for snapshots
//! - `control`: active snapshot state machine and restart boundary
//! - `server`: listener binding into Pingora services
//! - `upstreams`: compiled routing model and request-time upstream execution
//! - `metrics`: Prometheus metrics and JSON access log
//! - `tracing`: OpenTelemetry distributed tracing

pub mod cache;
pub mod control;
pub mod grpc;
pub mod le;
pub mod metrics;
pub mod server;
pub mod tracing;
pub mod upstreams;
