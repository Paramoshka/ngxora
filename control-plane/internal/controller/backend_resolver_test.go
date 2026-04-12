package controller

import (
	"context"
	"testing"

	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestReferenceGrantMatches(t *testing.T) {
	group := gatewayv1.Group(gatewayv1.GroupName)
	tests := []struct {
		name          string
		grant         gatewayv1beta1.ReferenceGrant
		fromNamespace string
		backend       translator.DesiredBackend
		want          bool
	}{
		{
			name: "matches exact",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "HTTPRoute",
							Namespace: "default",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{
							Group: "",
							Kind:  "Service",
						},
					},
				},
			},
			fromNamespace: "default",
			backend: translator.DesiredBackend{
				Group:     "",
				Kind:      "Service",
				Name:      "my-service",
				Namespace: "other",
			},
			want: true,
		},
		{
			name: "matches with explicit backend name",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "HTTPRoute",
							Namespace: "default",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{
							Group: "",
							Kind:  "Service",
							Name:  ptrObjectName("my-service"),
						},
					},
				},
			},
			fromNamespace: "default",
			backend: translator.DesiredBackend{
				Group:     "",
				Kind:      "Service",
				Name:      "my-service",
				Namespace: "other",
			},
			want: true,
		},
		{
			name: "does not match wrong name",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "HTTPRoute",
							Namespace: "default",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{
							Group: "",
							Kind:  "Service",
							Name:  ptrObjectName("other-service"),
						},
					},
				},
			},
			fromNamespace: "default",
			backend: translator.DesiredBackend{
				Group:     "",
				Kind:      "Service",
				Name:      "my-service",
				Namespace: "other",
			},
			want: false,
		},
		{
			name: "does not match wrong from namespace",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "HTTPRoute",
							Namespace: "production",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{
							Group: "",
							Kind:  "Service",
						},
					},
				},
			},
			fromNamespace: "default",
			backend: translator.DesiredBackend{
				Group:     "",
				Kind:      "Service",
				Name:      "my-service",
				Namespace: "other",
			},
			want: false,
		},
		{
			name: "does not match wrong group",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "HTTPRoute",
							Namespace: "default",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{
							Group: "custom.io",
							Kind:  "Service",
						},
					},
				},
			},
			fromNamespace: "default",
			backend: translator.DesiredBackend{
				Group:     "",
				Kind:      "Service",
				Name:      "my-service",
				Namespace: "other",
			},
			want: false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := referenceGrantMatches(tc.grant, tc.fromNamespace, tc.backend)
			assert.Equal(t, tc.want, got)
		})
	}
}

func TestFindServicePort(t *testing.T) {
	service := &corev1.Service{
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 80, Name: "http"},
				{Port: 443, Name: "https"},
			},
		},
	}

	tests := []struct {
		name string
		port int32
		want *corev1.ServicePort
	}{
		{name: "port 80", port: 80, want: &corev1.ServicePort{Port: 80, Name: "http"}},
		{name: "port 443", port: 443, want: &corev1.ServicePort{Port: 443, Name: "https"}},
		{name: "port not found", port: 8080, want: nil},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findServicePort(service, tc.port)
			if tc.want == nil {
				assert.Nil(t, got)
			} else {
				require.NotNil(t, got)
				assert.Equal(t, tc.want.Port, got.Port)
			}
		})
	}
}

func TestBackendResolver_ResolveBackendRefs_SameNamespace(t *testing.T) {
	ctx := context.Background()
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080, Name: "http"},
			},
		},
	}

	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-backend-abc123",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "my-backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{"10.0.0.1", "10.0.0.2"},
				Conditions: discoveryv1.EndpointConditions{
					Ready: &ready,
				},
			},
		},
		Ports: []discoveryv1.EndpointPort{
			{Name: ptrStr("http"), Port: ptrInt32(8080)},
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Backends: []translator.DesiredBackend{
					{
						Group:     "",
						Kind:      "Service",
						Name:      "my-backend",
						Namespace: "default",
						Port:      8080,
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(service, slice).
		Build()

	resolver := NewBackendResolver(fakeClient)
	serviceCache := make(map[types.NamespacedName]*corev1.Service)
	grantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)

	err := resolver.ResolveBackendRefs(ctx, "default", route, serviceCache, grantCache)
	require.NoError(t, err)

	// Verify endpoints were resolved
	require.Len(t, route.Rules[0].Backends[0].Endpoints, 2)
	assert.Equal(t, "10.0.0.1", route.Rules[0].Backends[0].Endpoints[0].IP)
	assert.Equal(t, int32(8080), route.Rules[0].Backends[0].Endpoints[0].Port)
	assert.Equal(t, "10.0.0.2", route.Rules[0].Backends[0].Endpoints[1].IP)
}

func TestBackendResolver_ResolveBackendRefs_MissingPort(t *testing.T) {
	ctx := context.Background()
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Backends: []translator.DesiredBackend{
					{
						Group:     "",
						Kind:      "Service",
						Name:      "my-backend",
						Namespace: "default",
						Port:      9090, // wrong port
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(service).
		Build()

	resolver := NewBackendResolver(fakeClient)
	serviceCache := make(map[types.NamespacedName]*corev1.Service)
	grantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)

	err := resolver.ResolveBackendRefs(ctx, "default", route, serviceCache, grantCache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "does not expose port 9090")
}

func TestBackendResolver_ResolveBackendRefs_NoEndpoints(t *testing.T) {
	ctx := context.Background()
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}

	// EndpointSlice with no ready endpoints
	ready := false
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-backend-abc123",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "my-backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses: []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{
					Ready: &ready,
				},
			},
		},
		Ports: []discoveryv1.EndpointPort{
			{Port: ptrInt32(8080)},
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Backends: []translator.DesiredBackend{
					{
						Group:     "",
						Kind:      "Service",
						Name:      "my-backend",
						Namespace: "default",
						Port:      8080,
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(service, slice).
		Build()

	resolver := NewBackendResolver(fakeClient)
	serviceCache := make(map[types.NamespacedName]*corev1.Service)
	grantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)

	err := resolver.ResolveBackendRefs(ctx, "default", route, serviceCache, grantCache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "has no ready endpoints")
}

func TestBackendResolver_ResolveBackendRefs_UnsupportedKind(t *testing.T) {
	ctx := context.Background()
	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Backends: []translator.DesiredBackend{
					{
						Group:     "custom.io",
						Kind:      "CustomBackend",
						Name:      "my-backend",
						Namespace: "default",
						Port:      8080,
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	resolver := NewBackendResolver(fakeClient)
	serviceCache := make(map[types.NamespacedName]*corev1.Service)
	grantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)

	err := resolver.ResolveBackendRefs(ctx, "default", route, serviceCache, grantCache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "only core Service backends are supported")
}

func TestBackendResolver_ResolveBackendRefs_CrossNamespaceWithGrant(t *testing.T) {
	ctx := context.Background()
	group := gatewayv1.Group(gatewayv1.GroupName)

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-ns-backend",
			Namespace: "backend-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}

	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-ns-backend-abc123",
			Namespace: "backend-ns",
			Labels:    map[string]string{"kubernetes.io/service-name": "cross-ns-backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.0.1.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			},
		},
		Ports: []discoveryv1.EndpointPort{
			{Port: ptrInt32(8080)},
		},
	}

	grant := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-httproute",
			Namespace: "backend-ns",
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.Group(group),
					Kind:      "HTTPRoute",
					Namespace: "default",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{Group: "", Kind: "Service"},
			},
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Backends: []translator.DesiredBackend{
					{
						Group:     "",
						Kind:      "Service",
						Name:      "cross-ns-backend",
						Namespace: "backend-ns",
						Port:      8080,
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(service, slice, grant).
		Build()

	resolver := NewBackendResolver(fakeClient)
	serviceCache := make(map[types.NamespacedName]*corev1.Service)
	grantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)

	err := resolver.ResolveBackendRefs(ctx, "default", route, serviceCache, grantCache)
	require.NoError(t, err)
	assert.Len(t, route.Rules[0].Backends[0].Endpoints, 1)
}

func TestBackendResolver_ResolveBackendRefs_CrossNamespaceWithoutGrant(t *testing.T) {
	ctx := context.Background()
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-ns-backend",
			Namespace: "backend-ns",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{
				{Port: 8080},
			},
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Backends: []translator.DesiredBackend{
					{
						Group:     "",
						Kind:      "Service",
						Name:      "cross-ns-backend",
						Namespace: "backend-ns",
						Port:      8080,
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(service).
		Build()

	resolver := NewBackendResolver(fakeClient)
	serviceCache := make(map[types.NamespacedName]*corev1.Service)
	grantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)

	err := resolver.ResolveBackendRefs(ctx, "default", route, serviceCache, grantCache)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not permitted by any ReferenceGrant")
}

func TestValidateRuleConsistency_MixedProtocols(t *testing.T) {
	rule := &translator.DesiredRule{
		Backends: []translator.DesiredBackend{
			{
				Name:            "backend-a",
				Namespace:       "default",
				BackendProtocol: gatewayv1.HTTPProtocolType,
				Endpoints:       []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 80}},
			},
			{
				Name:            "backend-b",
				Namespace:       "default",
				BackendProtocol: gatewayv1.HTTPSProtocolType,
				Endpoints:       []translator.DesiredBackendEndpoint{{IP: "10.0.0.2", Port: 443}},
			},
		},
	}

	err := validateRuleConsistency(rule)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mixed backend protocols")
}

func TestValidateRuleConsistency_SameProtocol(t *testing.T) {
	rule := &translator.DesiredRule{
		Backends: []translator.DesiredBackend{
			{
				Name:            "backend-a",
				Namespace:       "default",
				BackendProtocol: gatewayv1.HTTPProtocolType,
				Endpoints:       []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 80}},
			},
			{
				Name:            "backend-b",
				Namespace:       "default",
				BackendProtocol: gatewayv1.HTTPProtocolType,
				Endpoints:       []translator.DesiredBackendEndpoint{{IP: "10.0.0.2", Port: 80}},
			},
		},
	}

	err := validateRuleConsistency(rule)
	require.NoError(t, err)
}

func TestValidateRuleConsistency_MixedTLSVerify(t *testing.T) {
	vTrue := true
	vFalse := false
	rule := &translator.DesiredRule{
		Backends: []translator.DesiredBackend{
			{
				Name:      "backend-a",
				Namespace: "default",
				TLSVerify: &vTrue,
				Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.1", Port: 443}},
			},
			{
				Name:      "backend-b",
				Namespace: "default",
				TLSVerify: &vFalse,
				Endpoints: []translator.DesiredBackendEndpoint{{IP: "10.0.0.2", Port: 443}},
			},
		},
	}

	err := validateRuleConsistency(rule)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "mixed TLS verify settings")
}

// Helper functions

func ptrStr(s string) *string {
	return &s
}

func ptrInt32(i int32) *int32 {
	return &i
}

func ptrObjectName(name string) *gatewayv1.ObjectName {
	n := gatewayv1.ObjectName(name)
	return &n
}
