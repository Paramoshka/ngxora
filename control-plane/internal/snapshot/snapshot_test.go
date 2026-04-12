package snapshot

import (
	"testing"

	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestBuilder_Build_NilState(t *testing.T) {
	builder := NewBuilder()
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
	}

	result, err := builder.Build(nil, gateway, nil, nil, nil)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "desired state is nil")
}

func TestBuilder_Build_NilGateway(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{Routes: []translator.DesiredRoute{}}

	result, err := builder.Build(state, nil, nil, nil, nil)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "gateway is nil")
}

func TestBuilder_Build_NoSupportedListeners(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "tcp", Protocol: gatewayv1.TCPProtocolType, Port: 9000},
			},
		},
	}

	result, err := builder.Build(state, gateway, nil, nil, nil)
	assert.Nil(t, result)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no supported HTTP or HTTPS listeners")
}

func TestBuilder_Build_SingleRoute_SingleListener(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:      "demo-route",
				Namespace: "default",
				Hostnames: []string{"example.com"},
				ParentRefs: []gatewayv1.ParentReference{
					{SectionName: ptrSectionName("http")},
				},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "PathPrefix", Value: "/api"},
						Backends: []translator.DesiredBackend{
							{
								Name:      "backend",
								Namespace: "default",
								Port:      8080,
								Endpoints: []translator.DesiredBackendEndpoint{
									{IP: "10.0.0.1", Port: 8080},
								},
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}

	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		nil,
		map[string]bool{"http": true},
	)
	require.NoError(t, err)

	// Verify listeners
	require.Len(t, result.Snapshot.Listeners, 1)
	assert.Equal(t, "http-default-ngxora-http", result.Snapshot.Listeners[0].Name)
	assert.Equal(t, uint32(8080), result.Snapshot.Listeners[0].Port)
	assert.Equal(t, "0.0.0.0", result.Snapshot.Listeners[0].Address)
	assert.False(t, result.Snapshot.Listeners[0].Tls)

	// Verify virtual hosts
	require.Len(t, result.Snapshot.VirtualHosts, 1)
	vhost := result.Snapshot.VirtualHosts[0]
	assert.Equal(t, "http-default-ngxora-http", vhost.Listener)
	assert.Equal(t, []string{"example.com"}, vhost.ServerNames)
	assert.False(t, vhost.DefaultServer)

	// Verify routes
	require.Len(t, vhost.Routes, 1)
	route := vhost.Routes[0]
	prefix, ok := route.Match.GetKind().(*controlv1.Match_Prefix)
	require.True(t, ok, "expected Prefix match kind")
	assert.Equal(t, "/api", prefix.Prefix)

	// Verify upstreams
	require.Len(t, result.Snapshot.Upstreams, 1)
	ug := result.Snapshot.Upstreams[0]
	assert.Contains(t, ug.Name, "default")
	assert.Contains(t, ug.Name, "demo-route")
	assert.Equal(t, controlv1.UpstreamSelectionPolicy_UPSTREAM_SELECTION_POLICY_ROUND_ROBIN, ug.Policy)
	require.Len(t, ug.Backends, 1)
	assert.Equal(t, "10.0.0.1", ug.Backends[0].Host)
	assert.Equal(t, uint32(8080), ug.Backends[0].Port)

	// Verify route attachments
	assert.Equal(t, 1, result.RouteAttachments["default/demo-route"])
}

func TestBuilder_Build_HTTPSListener_WithTLS(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:      "secure-route",
				Namespace: "default",
				Hostnames: []string{"secure.example.com"},
				ParentRefs: []gatewayv1.ParentReference{
					{SectionName: ptrSectionName("https")},
				},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "Exact", Value: "/"},
						Backends: []translator.DesiredBackend{
							{
								Name:      "backend",
								Namespace: "default",
								Port:      8080,
								Endpoints: []translator.DesiredBackendEndpoint{
									{IP: "10.0.0.1", Port: 8080},
								},
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 8443},
			},
		},
	}

	tlsBinding := &controlv1.TlsBinding{
		Cert: &controlv1.PemSource{Source: &controlv1.PemSource_InlinePem{InlinePem: "cert"}},
		Key:  &controlv1.PemSource{Source: &controlv1.PemSource_InlinePem{InlinePem: "key"}},
	}

	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		map[string]*controlv1.TlsBinding{"https": tlsBinding},
		map[string]bool{"https": true},
	)
	require.NoError(t, err)

	require.Len(t, result.Snapshot.Listeners, 1)
	assert.True(t, result.Snapshot.Listeners[0].Tls)

	require.Len(t, result.Snapshot.VirtualHosts, 1)
	assert.Equal(t, "cert", result.Snapshot.VirtualHosts[0].Tls.Cert.GetInlinePem())
}

func TestBuilder_Build_HTTPSListener_WithoutTLS_Skipped(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:      "route",
				Namespace: "default",
				Hostnames: []string{"example.com"},
				ParentRefs: []gatewayv1.ParentReference{
					{SectionName: ptrSectionName("https")},
				},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "PathPrefix", Value: "/"},
						Backends: []translator.DesiredBackend{
							{
								Name:      "backend",
								Namespace: "default",
								Port:      8080,
								Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 8080}},
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "https", Protocol: gatewayv1.HTTPSProtocolType, Port: 8443},
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}

	// Only HTTP listener is usable (HTTPS has no TLS binding)
	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		nil, // no TLS bindings
		map[string]bool{"https": false, "http": true},
	)
	require.NoError(t, err)

	// Only HTTP listener should be created
	require.Len(t, result.Snapshot.Listeners, 1)
	assert.Equal(t, "http-default-ngxora-http", result.Snapshot.Listeners[0].Name)
}

func TestBuilder_Build_MultipleRoutes(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:       "route-a",
				Namespace:  "default",
				Hostnames:  []string{"a.example.com"},
				ParentRefs: []gatewayv1.ParentReference{{}},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "PathPrefix", Value: "/a"},
						Backends: []translator.DesiredBackend{
							{
								Name: "backend-a", Namespace: "default", Port: 80,
								Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 80}},
							},
						},
					},
				},
			},
			{
				Name:       "route-b",
				Namespace:  "default",
				Hostnames:  []string{"b.example.com"},
				ParentRefs: []gatewayv1.ParentReference{{}},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "Exact", Value: "/b"},
						Backends: []translator.DesiredBackend{
							{
								Name: "backend-b", Namespace: "default", Port: 80,
								Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.2", Port: 80}},
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80},
			},
		},
	}

	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		nil,
		map[string]bool{"http": true},
	)
	require.NoError(t, err)

	assert.Len(t, result.Snapshot.VirtualHosts, 2)
	assert.Len(t, result.Snapshot.Upstreams, 2)
	assert.Equal(t, 1, result.RouteAttachments["default/route-a"])
	assert.Equal(t, 1, result.RouteAttachments["default/route-b"])
}

func TestBuilder_Build_RouteNotAttached(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:      "orphan-route",
				Namespace: "default",
				Hostnames: []string{"other.com"},
				ParentRefs: []gatewayv1.ParentReference{
					{SectionName: ptrSectionName("http")},
				},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "PathPrefix", Value: "/"},
						Backends: []translator.DesiredBackend{
							{
								Name: "backend", Namespace: "default", Port: 80,
								Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 80}},
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Protocol: gatewayv1.HTTPProtocolType,
					Port:     80,
					Hostname: (*gatewayv1.Hostname)(ptrStr("example.com")),
				},
			},
		},
	}

	// Route hostname "other.com" doesn't match listener "example.com"
	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		nil,
		map[string]bool{"http": true},
	)
	require.NoError(t, err)

	// Route should not be attached
	assert.Equal(t, 0, result.RouteAttachments["default/orphan-route"])
	assert.Len(t, result.Snapshot.VirtualHosts, 0)
}

func TestBuilder_Build_HTTPSBackendScheme(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:       "https-route",
				Namespace:  "default",
				ParentRefs: []gatewayv1.ParentReference{{}},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "PathPrefix", Value: "/"},
						Backends: []translator.DesiredBackend{
							{
								Name:            "backend",
								Namespace:       "default",
								Port:            443,
								BackendProtocol: gatewayv1.HTTPSProtocolType,
								Endpoints:       []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 443}},
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80},
			},
		},
	}

	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		nil,
		map[string]bool{"http": true},
	)
	require.NoError(t, err)

	require.Len(t, result.Snapshot.VirtualHosts, 1)
	require.Len(t, result.Snapshot.VirtualHosts[0].Routes, 1)
	assert.Equal(t, "https", result.Snapshot.VirtualHosts[0].Routes[0].Upstream.Scheme)
}

func TestBuilder_Build_PluginFilters(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:       "plugin-route",
				Namespace:  "default",
				ParentRefs: []gatewayv1.ParentReference{{}},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "PathPrefix", Value: "/"},
						Backends: []translator.DesiredBackend{
							{
								Name: "backend", Namespace: "default", Port: 80,
								Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 80}},
							},
						},
						Filters: []translator.DesiredFilter{
							{
								Type:         string(gatewayv1.HTTPRouteFilterExtensionRef),
								PluginName:   "rate-limit",
								PluginConfig: `{"max_requests_per_second": 100}`,
							},
							{
								Type:         string(gatewayv1.HTTPRouteFilterRequestHeaderModifier),
								PluginName:   "headers",
								PluginConfig: `{"request":{"set":[{"name":"X-Custom","value":"test"}]}}`,
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80},
			},
		},
	}

	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		nil,
		map[string]bool{"http": true},
	)
	require.NoError(t, err)

	require.Len(t, result.Snapshot.VirtualHosts[0].Routes[0].Plugins, 2)
	assert.Equal(t, "rate-limit", result.Snapshot.VirtualHosts[0].Routes[0].Plugins[0].Name)
	assert.Equal(t, "headers", result.Snapshot.VirtualHosts[0].Routes[0].Plugins[1].Name)
}

func TestBuilder_Build_WildcardDefaultServer(t *testing.T) {
	builder := NewBuilder()
	state := &translator.DesiredState{
		Routes: []translator.DesiredRoute{
			{
				Name:       "wildcard-route",
				Namespace:  "default",
				Hostnames:  []string{"*.example.com"},
				ParentRefs: []gatewayv1.ParentReference{{}},
				Rules: []translator.DesiredRule{
					{
						PathMatch: translator.DesiredPathMatch{Kind: "PathPrefix", Value: "/"},
						Backends: []translator.DesiredBackend{
							{
								Name: "backend", Namespace: "default", Port: 80,
								Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 80}},
							},
						},
					},
				},
			},
		},
	}
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: "default"},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 80},
			},
		},
	}

	result, err := builder.Build(state, gateway,
		map[string]map[string]string{"default": {}},
		nil,
		map[string]bool{"http": true},
	)
	require.NoError(t, err)

	assert.True(t, result.Snapshot.VirtualHosts[0].DefaultServer)
}

func TestStableVersion_IdenticalSnapshots_SameHash(t *testing.T) {
	snap1 := &controlv1.ConfigSnapshot{
		Listeners: []*controlv1.Listener{
			{Name: "http", Address: "0.0.0.0", Port: 80, Tls: false},
		},
	}
	snap2 := &controlv1.ConfigSnapshot{
		Listeners: []*controlv1.Listener{
			{Name: "http", Address: "0.0.0.0", Port: 80, Tls: false},
		},
	}

	v1, err := StableVersion(snap1)
	require.NoError(t, err)
	v2, err := StableVersion(snap2)
	require.NoError(t, err)

	assert.Equal(t, v1, v2)
}

func TestStableVersion_DifferentSnapshots_DifferentHash(t *testing.T) {
	snap1 := &controlv1.ConfigSnapshot{
		Listeners: []*controlv1.Listener{{Name: "http", Port: 80}},
	}
	snap2 := &controlv1.ConfigSnapshot{
		Listeners: []*controlv1.Listener{{Name: "http", Port: 443}},
	}

	v1, err := StableVersion(snap1)
	require.NoError(t, err)
	v2, err := StableVersion(snap2)
	require.NoError(t, err)

	assert.NotEqual(t, v1, v2)
}

func TestStableVersion_VersionField_Ignored(t *testing.T) {
	snap1 := &controlv1.ConfigSnapshot{
		Listeners: []*controlv1.Listener{{Name: "http", Port: 80}},
		Version:   "v1",
	}
	snap2 := &controlv1.ConfigSnapshot{
		Listeners: []*controlv1.Listener{{Name: "http", Port: 80}},
		Version:   "v2-different",
	}

	v1, err := StableVersion(snap1)
	require.NoError(t, err)
	v2, err := StableVersion(snap2)
	require.NoError(t, err)

	// Version field should be stripped before hashing
	assert.Equal(t, v1, v2)
}

func TestStableVersion_NilSnapshot(t *testing.T) {
	_, err := StableVersion(nil)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "nil")
}

func TestGatewayBindAddress_ExplicitAddress(t *testing.T) {
	addr := gatewayv1.IPAddressType
	gateway := &gatewayv1.Gateway{
		Spec: gatewayv1.GatewaySpec{
			Addresses: []gatewayv1.GatewaySpecAddress{
				{Type: &addr, Value: "192.168.1.100"},
			},
		},
	}
	assert.Equal(t, "192.168.1.100", gatewayBindAddress(gateway))
}

func TestGatewayBindAddress_Default(t *testing.T) {
	gateway := &gatewayv1.Gateway{
		Spec: gatewayv1.GatewaySpec{},
	}
	assert.Equal(t, "0.0.0.0", gatewayBindAddress(gateway))
}

func TestSanitizeName(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{name: "lowercase", input: "MyName", want: "myname"},
		{name: "underscore to dash", input: "my_name", want: "my-name"},
		{name: "dot to dash", input: "my.name", want: "my-name"},
		{name: "slash to dash", input: "my/name", want: "my-name"},
		{name: "empty defaults", input: "", want: "default"},
		{name: "complex", input: "My_App.Name/Path", want: "my-app-name-path"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, sanitizeName(tc.input))
		})
	}
}

func TestUpstreamGroupName(t *testing.T) {
	route := translator.DesiredRoute{
		Name:      "Test-Route",
		Namespace: "Default",
	}
	name := upstreamGroupName(route, 3)
	assert.Equal(t, "default-test-route-rule-3", name)
}

func TestContainsWildcard(t *testing.T) {
	assert.True(t, containsWildcard([]string{"*.example.com"}))
	assert.True(t, containsWildcard([]string{"*"}))
	assert.True(t, containsWildcard([]string{"example.com", "*.other.com"}))
	assert.False(t, containsWildcard([]string{"example.com", "api.example.com"}))
	assert.False(t, containsWildcard(nil))
}

func TestRouteKey(t *testing.T) {
	route := translator.DesiredRoute{Name: "my-route", Namespace: "default"}
	assert.Equal(t, "default/my-route", routeKey(route))
}

// Helpers

func ptrSectionName(s string) *gatewayv1.SectionName {
	n := gatewayv1.SectionName(s)
	return &n
}

func ptrStr(s string) *string {
	return &s
}
