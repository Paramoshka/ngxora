use async_trait::async_trait;
use pingora_proxy::{ProxyHttp, Session};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};

// 1. Shared routing table
struct RouteTable {
    // Map paths to (IP, Port)
    pub backends: HashMap<String, (String, u16)>,
}

pub struct DynamicProxy {
    routing: Arc<RwLock<RouteTable>>,
}

#[async_trait]
impl ProxyHttp for DynamicProxy {}
