//! `ngxora-runtime` is the Pingora-facing execution layer.
//!
//! Module map:
//! - `grpc`: protobuf wire adapter for snapshots
//! - `control`: active snapshot state machine and restart boundary
//! - `server`: listener binding into Pingora services
//! - `upstreams`: compiled routing model and request-time upstream execution

pub mod control;
pub mod grpc;
pub mod server;
pub mod upstreams;
