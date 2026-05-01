use pingora::prelude::HttpPeer;
use pingora_cache::{MemCache, lock::CacheKeyLockImpl, predictor::Predictor};
use pingora_proxy::{ProxyHttp, Session};
use tonic::async_trait;
use pingora::Result;




pub struct ProxyCache {
    cache_backend: MemCache,
    predictor: Predictor<32>,
    cache_lock: CacheKeyLockImpl,
}

#[async_trait]
impl ProxyHttp for ProxyCache {
    type CTX = ();
    fn new_ctx(&self) -> Self::CTX {}



    async fn upstream_peer(
        &self,
        session: &mut Session,
        ctx: &mut Self::CTX,
    ) -> Result<Box<HttpPeer>> {

           let mut peer = Box::new(HttpPeer::new(
            format!("127.0.0.1:{}", 80),
            false,
            "".to_string(),
        ));

        Ok(peer)
    }
}