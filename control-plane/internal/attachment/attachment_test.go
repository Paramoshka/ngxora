package attachment

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestListenerSelectedByParentRefs(t *testing.T) {
	listener := gatewayv1.Listener{
		Name: gatewayv1.SectionName("http"),
		Port: gatewayv1.PortNumber(8080),
	}

	tests := []struct {
		name string
		refs []gatewayv1.ParentReference
		want bool
	}{
		{
			name: "nil refs",
			refs: nil,
			want: false,
		},
		{
			name: "empty refs",
			refs: []gatewayv1.ParentReference{},
			want: false,
		},
		{
			name: "matching listener name",
			refs: []gatewayv1.ParentReference{
				{SectionName: ptrSectionName("http")},
			},
			want: true,
		},
		{
			name: "matching port",
			refs: []gatewayv1.ParentReference{
				{Port: ptrPort(8080)},
			},
			want: true,
		},
		{
			name: "matching both section name and port",
			refs: []gatewayv1.ParentReference{
				{SectionName: ptrSectionName("http"), Port: ptrPort(8080)},
			},
			want: true,
		},
		{
			name: "wrong section name",
			refs: []gatewayv1.ParentReference{
				{SectionName: ptrSectionName("https")},
			},
			want: false,
		},
		{
			name: "wrong port",
			refs: []gatewayv1.ParentReference{
				{Port: ptrPort(443)},
			},
			want: false,
		},
		{
			name: "nil section name and port matches any",
			refs: []gatewayv1.ParentReference{{}},
			want: true,
		},
		{
			name: "first non-match, second match",
			refs: []gatewayv1.ParentReference{
				{SectionName: ptrSectionName("https")},
				{SectionName: ptrSectionName("http")},
			},
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ListenerSelectedByParentRefs(listener, tc.refs)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestListenerAllowsHTTPRoute(t *testing.T) {
	tests := []struct {
		name           string
		listener       gatewayv1.Listener
		gwNamespace    string
		routeNamespace string
		nsLabels       map[string]string
		want           bool
		wantErr        bool
	}{
		{
			name: "HTTP protocol, same namespace",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
			},
			gwNamespace:    "default",
			routeNamespace: "default",
			want:           true,
		},
		{
			name: "HTTPS protocol, same namespace",
			listener: gatewayv1.Listener{
				Name:     "https",
				Protocol: gatewayv1.HTTPSProtocolType,
			},
			gwNamespace:    "default",
			routeNamespace: "default",
			want:           true,
		},
		{
			name: "TCP protocol not allowed",
			listener: gatewayv1.Listener{
				Name:     "tcp",
				Protocol: gatewayv1.TCPProtocolType,
			},
			gwNamespace:    "default",
			routeNamespace: "default",
			want:           false,
		},
		{
			name: "UDP protocol not allowed",
			listener: gatewayv1.Listener{
				Name:     "udp",
				Protocol: gatewayv1.UDPProtocolType,
			},
			gwNamespace:    "default",
			routeNamespace: "default",
			want:           false,
		},
		{
			name: "NamespacesFromSame, different namespace",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Namespaces: &gatewayv1.RouteNamespaces{
						From: ptrNamespaceFrom(gatewayv1.NamespacesFromSame),
					},
				},
			},
			gwNamespace:    "default",
			routeNamespace: "other",
			want:           false,
		},
		{
			name: "NamespacesFromAll, different namespace",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Namespaces: &gatewayv1.RouteNamespaces{
						From: ptrNamespaceFrom(gatewayv1.NamespacesFromAll),
					},
				},
			},
			gwNamespace:    "default",
			routeNamespace: "other",
			want:           true,
		},
		{
			name: "NamespacesFromSelector matching labels",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Namespaces: &gatewayv1.RouteNamespaces{
						From: ptrNamespaceFrom(gatewayv1.NamespacesFromSelector),
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"env": "prod"},
						},
					},
				},
			},
			gwNamespace:    "default",
			routeNamespace: "prod-ns",
			nsLabels:       map[string]string{"env": "prod"},
			want:           true,
		},
		{
			name: "NamespacesFromSelector not matching labels",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Namespaces: &gatewayv1.RouteNamespaces{
						From: ptrNamespaceFrom(gatewayv1.NamespacesFromSelector),
						Selector: &metav1.LabelSelector{
							MatchLabels: map[string]string{"env": "prod"},
						},
					},
				},
			},
			gwNamespace:    "default",
			routeNamespace: "dev-ns",
			nsLabels:       map[string]string{"env": "dev"},
			want:           false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ListenerAllowsHTTPRoute(tc.listener, tc.gwNamespace, tc.routeNamespace, tc.nsLabels)
			if tc.wantErr {
				require.Error(t, err)
			} else {
				require.NoError(t, err)
			}
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestListenerHasOnlySupportedRouteKinds(t *testing.T) {
	tests := []struct {
		name     string
		listener gatewayv1.Listener
		want     bool
	}{
		{
			name: "no allowed routes means HTTPRoute supported",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
			},
			want: true,
		},
		{
			name: "explicit HTTPRoute",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Kinds: []gatewayv1.RouteGroupKind{
						{Kind: "HTTPRoute"},
					},
				},
			},
			want: true,
		},
		{
			name: "TCPRoute not supported",
			listener: gatewayv1.Listener{
				Name:     "tcp",
				Protocol: gatewayv1.TCPProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Kinds: []gatewayv1.RouteGroupKind{
						{Kind: "TCPRoute"},
					},
				},
			},
			want: false,
		},
		{
			name: "mixed kinds with unsupported",
			listener: gatewayv1.Listener{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Kinds: []gatewayv1.RouteGroupKind{
						{Kind: "HTTPRoute"},
						{Kind: "TLSRoute"},
					},
				},
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := ListenerHasOnlySupportedRouteKinds(tc.listener)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestEffectiveServerNames(t *testing.T) {
	tests := []struct {
		name             string
		routeHostnames   []string
		listenerHostname *gatewayv1.Hostname
		want             []string
	}{
		{
			name:             "no listener hostname, no route hostnames",
			routeHostnames:   nil,
			listenerHostname: nil,
			want:             []string{"*"},
		},
		{
			name:             "no listener hostname, with route hostnames",
			routeHostnames:   []string{"example.com", "api.example.com"},
			listenerHostname: nil,
			want:             []string{"example.com", "api.example.com"},
		},
		{
			name:             "with listener hostname, no route hostnames",
			routeHostnames:   nil,
			listenerHostname: ptrHostname("example.com"),
			want:             []string{"example.com"},
		},
		{
			name:             "matching hostnames",
			routeHostnames:   []string{"example.com"},
			listenerHostname: ptrHostname("example.com"),
			want:             []string{"example.com"},
		},
		{
			name:             "route hostname matches listener wildcard",
			routeHostnames:   []string{"api.example.com"},
			listenerHostname: ptrHostname("*.example.com"),
			want:             []string{"api.example.com"},
		},
		{
			name:             "route hostname does not match listener wildcard",
			routeHostnames:   []string{"other.com"},
			listenerHostname: ptrHostname("*.example.com"),
			want:             nil,
		},
		{
			name:             "duplicate hostnames removed",
			routeHostnames:   []string{"example.com", "example.com"},
			listenerHostname: nil,
			want:             []string{"example.com"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := EffectiveServerNames(tc.routeHostnames, tc.listenerHostname)
			assert.ElementsMatch(t, tc.want, got)
		})
	}
}

func TestHostnamesIntersect(t *testing.T) {
	tests := []struct {
		name  string
		left  string
		right string
		want  bool
	}{
		{name: "exact match", left: "example.com", right: "example.com", want: true},
		{name: "exact mismatch", left: "example.com", right: "other.com", want: false},
		{name: "wildcard matches subdomain", left: "api.example.com", right: "*.example.com", want: true},
		{name: "wildcard does not match base", left: "example.com", right: "*.example.com", want: false},
		{name: "two wildcards same domain", left: "*.example.com", right: "*.example.com", want: true},
		{name: "two wildcards different domains", left: "*.example.com", right: "*.other.com", want: false},
		{name: "wildcard subdomain overlap", left: "*.a.example.com", right: "*.example.com", want: true},
		{name: "case insensitive", left: "Example.COM", right: "example.com", want: true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := hostnamesIntersect(tc.left, tc.right)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestNarrowerHostname(t *testing.T) {
	tests := []struct {
		name  string
		left  string
		right string
		want  string
	}{
		{name: "specific over wildcard", left: "api.example.com", right: "*.example.com", want: "api.example.com"},
		{name: "wildcard over wildcard longer", left: "*.a.example.com", right: "*.example.com", want: "*.a.example.com"},
		{name: "specific over specific", left: "api.example.com", right: "www.example.com", want: "api.example.com"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := narrowerHostname(tc.left, tc.right)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestDedupeStrings(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "nil input", input: nil, want: nil},
		{name: "empty", input: []string{}, want: nil},
		{name: "no duplicates", input: []string{"a", "b"}, want: []string{"a", "b"}},
		{name: "with duplicates", input: []string{"a", "b", "a", "c", "b"}, want: []string{"a", "b", "c"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := dedupeStrings(tc.input)
			assert.Equal(t, tc.want, got)
		})
	}
}

// Helpers

func ptrSectionName(s string) *gatewayv1.SectionName {
	n := gatewayv1.SectionName(s)
	return &n
}

func ptrPort(p int32) *gatewayv1.PortNumber {
	n := gatewayv1.PortNumber(p)
	return &n
}

func ptrHostname(s string) *gatewayv1.Hostname {
	n := gatewayv1.Hostname(s)
	return &n
}

func ptrNamespaceFrom(from gatewayv1.FromNamespaces) *gatewayv1.FromNamespaces {
	return &from
}
