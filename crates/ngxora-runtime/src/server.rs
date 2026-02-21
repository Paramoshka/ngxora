use crate::upstreams::CompiledRouter;
use pingora::services::listening::Service;
use pingora_proxy::{HttpProxy, ProxyHttp};

// bind_listeners_from_router function apply all listeners (0.0.0.0:443 ssl) to server entity.
pub fn bind_listeners_from_router<SV>(svc: &mut Service<HttpProxy<SV, ()>>, router: &CompiledRouter)
where
    SV: ProxyHttp,
{
    // svc.add_tcp(...), svc.add_tls_with_settings(...)
}
