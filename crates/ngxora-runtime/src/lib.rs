#[cfg(all(feature = "openssl", feature = "rustls"))]
compile_error!("features `openssl` and `rustls` are mutually exclusive");

pub mod server;
pub mod upstreams;
