# Gateway API Policies & Plugins

`ngxora` supports both native Gateway API filters and custom extensions via `ExtensionRef`. This document lists all supported policies and their configuration schemas.

## Native Filters

These filters are part of the standard Kubernetes Gateway API and are implemented natively by the `ngxora` control-plane.

### RequestHeaderModifier

Modifies headers before they are sent to the upstream backend.

```yaml
filters:
  - type: RequestHeaderModifier
    requestHeaderModifier:
      add:
        - name: X-Added-By
          value: ngxora
      set:
        - name: X-Environment
          value: production
      remove: ["X-Debug-Token"]
```

### ResponseHeaderModifier

Modifies headers before they are sent back to the client.

```yaml
filters:
  - type: ResponseHeaderModifier
    responseHeaderModifier:
      add:
        - name: X-Processed-By
          value: ngxora-proxy
```

---

## Custom Policies (ExtensionRef)

Custom policies are configured via standalone CRDs and referenced in the `HTTPRoute` rules using the `ExtensionRef` filter type.

**Important:** The `group` must always be `plugins.ngxora.io`.

### BasicAuthPolicy

Protects the route with HTTP Basic Authentication.

**Resource:**
```yaml
apiVersion: plugins.ngxora.io/v1alpha1
kind: BasicAuthPolicy
metadata:
  name: my-auth
spec:
  username: "admin"
  password: "password123"
  realm: "Restricted Area"
```

**Usage:**
```yaml
filters:
  - type: ExtensionRef
    extensionRef:
      group: plugins.ngxora.io
      kind: BasicAuthPolicy
      name: my-auth
```

### RateLimitPolicy

Limits the number of requests per second for a route.

**Resource:**
```yaml
apiVersion: plugins.ngxora.io/v1alpha1
kind: RateLimitPolicy
metadata:
  name: my-limit
spec:
  max_requests_per_second: 100
```

**Usage:**
```yaml
filters:
  - type: ExtensionRef
    extensionRef:
      group: plugins.ngxora.io
      kind: RateLimitPolicy
      name: my-limit
```

### CorsPolicy

Configures Cross-Origin Resource Sharing (CORS) headers.

**Resource:**
```yaml
apiVersion: plugins.ngxora.io/v1alpha1
kind: CorsPolicy
metadata:
  name: my-cors
spec:
  allow_origin: "*"
  allow_methods: "GET,POST,OPTIONS"
  allow_headers: "Content-Type,Authorization"
  expose_headers: "X-Custom-Header"
  allow_credentials: true
  max_age: 3600
```

**Usage:**
```yaml
filters:
  - type: ExtensionRef
    extensionRef:
      group: plugins.ngxora.io
      kind: CorsPolicy
      name: my-cors
```

### ExtAuthzPolicy

Delegates authentication decisions to an external HTTP service.

**Resource:**
```yaml
apiVersion: plugins.ngxora.io/v1alpha1
kind: ExtAuthzPolicy
metadata:
  name: my-ext-auth
spec:
  uri: "http://auth-svc.default.svc.cluster.local/v1/check"
  timeout_ms: 1000
  pass_request_headers: ["Authorization", "Cookie"]
  pass_response_headers: ["X-User-ID", "X-Role"]
```

**Usage:**
```yaml
filters:
  - type: ExtensionRef
    extensionRef:
      group: plugins.ngxora.io
      kind: ExtAuthzPolicy
      name: my-ext-auth
```

### JwtAuthPolicy

Validates JSON Web Tokens in the `Authorization` header.

**Resource:**
```yaml
apiVersion: plugins.ngxora.io/v1alpha1
kind: JwtAuthPolicy
metadata:
  name: my-jwt
spec:
  algorithm: "RS256"
  # Use 'secret' for HMAC algorithms or 'secret_file' (path on the proxy pod) for RSA/EC
  secret_file: "/etc/ngxora/certs/pubkey.pem"
```

**Usage:**
```yaml
filters:
  - type: ExtensionRef
    extensionRef:
      group: plugins.ngxora.io
      kind: JwtAuthPolicy
      name: my-jwt
```
