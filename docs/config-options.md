# Config Options

`ngxora` supports a focused nginx-style config subset.

This document is the source of truth for currently supported text-config directives, upstream policies, and built-in location plugins.

For `gRPC ApplySnapshot` reload semantics, see [docs/README.md](./README.md).

## HTTP Block

- `client_max_body_size <size>;`
  Sets the downstream request body limit. `0` disables the limit.
- `keepalive_timeout <idle> [header];`
  Sets downstream keepalive timeout. `0` disables keepalive timeout handling.
- `keepalive_requests <count>;`
  Sets the downstream keepalive request limit.
- `allow_connect_method_proxying on|off;`
  Enables or disables proxying of `CONNECT` requests.
- `h2c on|off;`
  Enables or disables cleartext HTTP/2 handling at the service level.
- `tcp_nodelay on|off;`
  Parsed and stored in runtime config, but not yet enforced on downstream sockets.

## Upstream Blocks

Supported shape:

```nginx
upstream app_pool {
    policy random;
    server 127.0.0.1:8080;
    server 127.0.0.1:8081;
}
```

Supported directives:

- `server <host>:<port>;`
  Adds a static backend to the upstream group.
- `policy round_robin|random;`
  Selects backend balancing policy. Default is `round_robin`.

Supported policies:

- `round_robin` - default policy
- `random`

## Server And Listener Options

- `listen <addr>:<port>;`
  Basic listener binding.
- `listen <port>;`
  Shorthand bind on wildcard address.
- `listen ... default_server;`
  Marks the server block as the listener default.
- `listen ... ssl;`
  Enables downstream TLS on the listener.
- `listen ... http2;`
  Enables HTTP/2 on TLS listeners.
- `listen ... http2_only;`
  Restricts TLS listener ALPN to HTTP/2 only.
- `server_name <name> ...;`
  Declares hostnames for virtual host routing.

## Downstream TLS Options

- `ssl_certificate <path>;`
  Server certificate for the listener.
- `ssl_certificate_key <path>;`
  Private key for the listener certificate.
- `ssl_protocols TLSv1 TLSv1.2 TLSv1.3;`
  Sets downstream TLS protocol bounds.
- `ssl_verify_client off|optional|required;`
  Configures downstream client certificate verification.
- `ssl_client_certificate <path>;`
  Client CA bundle used with `ssl_verify_client`.

## Location Proxy Options

Supported proxy targets:

- direct upstream URL:
  `proxy_pass http://127.0.0.1:8080;`
- direct TLS upstream URL:
  `proxy_pass https://api.internal:8443;`
- named upstream group:
  `proxy_pass http://app_pool;`

Supported location directives:

- `proxy_connect_timeout <duration>;`
- `proxy_read_timeout <duration>;`
- `proxy_write_timeout <duration>;`
- `proxy_ssl_verify on|off;`
  `off` disables both upstream certificate and hostname verification.
- `proxy_ssl_trusted_certificate <path>;`
  Sets a custom CA bundle for upstream TLS verification.

Notes:

- `proxy_ssl_trusted_certificate` currently requires an `openssl` build.
- There is no separate `send_timeout` directive today; upstream timeouts are modeled as `connect`, `read`, and `write`.

Example:

```nginx
location /api/ {
    proxy_connect_timeout 3s;
    proxy_read_timeout 15s;
    proxy_write_timeout 20s;
    proxy_ssl_verify on;
    proxy_ssl_trusted_certificate /etc/ngxora/tls/upstream-ca.pem;
    proxy_pass https://app_pool;
}
```

Disable upstream verification only for local or disposable environments:

```nginx
location /lab/ {
    proxy_ssl_verify off;
    proxy_pass https://127.0.0.1:9443;
}
```

## Built-In Location Plugins

### `headers`

Supported inside `location {}`:

```nginx
location /api/ {
    headers {
        request_add X-Env dev;
        request_set X-Route api;
        request_remove X-Debug;

        upstream_request_add X-From-Proxy ngxora;
        upstream_request_set X-Upstream-Route api;
        upstream_request_remove X-Legacy;

        response_add X-Proxy ngxora;
        response_set Cache-Control no-store;
        response_remove X-Powered-By;
    }

    proxy_pass http://127.0.0.1:8080;
}
```

### `basic_auth` / `basic-auth`

Supported inside `location {}` when the binary is built with `plugin-basic-auth`:

```nginx
location /admin/ {
    basic_auth {
        username demo;
        password s3cret;
        realm Admin Area;
    }

    proxy_pass http://127.0.0.1:8080;
}
```

Supported directives:

- `username <value>;`
- `password <value>;`
- `realm <value>;`
