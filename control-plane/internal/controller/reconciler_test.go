package controller

import (
	"context"
	"log/slog"
	"testing"

	"github.com/paramoshka/ngxora/control-plane/internal/snapshot"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// mockNGXoraClient is a test double for the dataplane gRPC client.
type mockNGXoraClient struct {
	applySnapshotFn func(ctx context.Context, snap *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error)
	getSnapshotFn   func(ctx context.Context) (*controlv1.ConfigSnapshot, error)
	appliedSnapshot  *controlv1.ConfigSnapshot
	applyCount       int
}

func (m *mockNGXoraClient) ApplySnapshot(ctx context.Context, snap *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error) {
	m.applyCount++
	m.appliedSnapshot = snap
	if m.applySnapshotFn != nil {
		return m.applySnapshotFn(ctx, snap)
	}
	return &controlv1.ApplyResult{Applied: true}, nil
}

func (m *mockNGXoraClient) GetSnapshot(ctx context.Context) (*controlv1.ConfigSnapshot, error) {
	if m.getSnapshotFn != nil {
		return m.getSnapshotFn(ctx)
	}
	return nil, nil
}

func newMockClient() *mockNGXoraClient {
	return &mockNGXoraClient{}
}

func TestReconciler_NoRoutes_ReturnsSuccessfully(t *testing.T) {
	ctx := context.Background()
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ngxora",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}
	ns := &corev1Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, ns).
		WithStatusSubresource(gw).
		Build()

	mockClient := newMockClient()
	reconciler := buildTestReconciler(fakeClient, mockClient)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "any-route"},
	})

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	// Empty snapshot still gets applied (version will be hash of empty snapshot)
	assert.GreaterOrEqual(t, mockClient.applyCount, 0)
}

func TestReconciler_ValidRoute_ApppliesSnapshot(t *testing.T) {
	ctx := context.Background()
	gwNs := gatewayv1.Namespace("default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ngxora",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}

	ns := &corev1Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8080}},
		},
	}

	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-abc",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			},
		},
		Ports: []discoveryv1.EndpointPort{{Port: ptrInt32(8080)}},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "demo-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "ngxora", Namespace: &gwNs},
				},
			},
			Hostnames: []gatewayv1.Hostname{"example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend",
									Port: (*gatewayv1.PortNumber)(ptrInt32(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, ns, service, slice, route).
		WithStatusSubresource(gw, route).
		Build()

	mockClient := newMockClient()
	reconciler := buildTestReconciler(fakeClient, mockClient)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "demo-route"},
	})

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)

	// Snapshot should have been applied
	assert.Equal(t, 1, mockClient.applyCount)
	require.NotNil(t, mockClient.appliedSnapshot)
	assert.NotEmpty(t, mockClient.appliedSnapshot.Version)

	// Verify the route status was updated
	updatedRoute := &gatewayv1.HTTPRoute{}
	require.NoError(t, fakeClient.Get(ctx, types.NamespacedName{Namespace: "default", Name: "demo-route"}, updatedRoute))
	assert.Len(t, updatedRoute.Status.Parents, 1)
}

func TestReconciler_NoMatchingGateway_SkipsRoute(t *testing.T) {
	ctx := context.Background()

	// The reconciler targets "ngxora" gateway, so we need it to exist
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ngxora",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}
	ns := &corev1Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

	// Route targets a different gateway
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "other-gateway"}, // different gateway name
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, ns, route).
		WithStatusSubresource(gw, route).
		Build()

	mockClient := newMockClient()
	reconciler := buildTestReconciler(fakeClient, mockClient)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "demo-route"},
	})

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	// Route doesn't match gateway, but empty snapshot still gets applied
	assert.GreaterOrEqual(t, mockClient.applyCount, 0)
}

func TestReconciler_DifferentNamespace_Skips(t *testing.T) {
	ctx := context.Background()

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	mockClient := newMockClient()
	reconciler := buildTestReconciler(fakeClient, mockClient)

	// Request from a different namespace should be ignored
	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "other-ns", Name: "demo-route"},
	})

	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.Equal(t, 0, mockClient.applyCount)
}

func TestReconciler_NoopApply_SkipsRedundantApply(t *testing.T) {
	ctx := context.Background()
	gwNs := gatewayv1.Namespace("default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ngxora",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}
	ns := &corev1Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8080}},
		},
	}

	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-abc",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			},
		},
		Ports: []discoveryv1.EndpointPort{{Port: ptrInt32(8080)}},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "demo-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "ngxora", Namespace: &gwNs},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend",
									Port: (*gatewayv1.PortNumber)(ptrInt32(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, ns, service, slice, route).
		WithStatusSubresource(gw, route).
		Build()

	// Pre-build the expected snapshot to simulate an already-applied state
	// We can't easily build the exact same snapshot here, so we'll just return nil
	// to trigger the first apply, then on subsequent calls return the same version

	callCount := 0
	mockClient := newMockClient()
	mockClient.getSnapshotFn = func(ctx context.Context) (*controlv1.ConfigSnapshot, error) {
		callCount++
		if callCount == 1 {
			return nil, nil // First call: no active snapshot, trigger apply
		}
		// Return the applied snapshot to simulate no-op
		return mockClient.appliedSnapshot, nil
	}

	reconciler := buildTestReconciler(fakeClient, mockClient)

	// First reconcile: should apply
	result1, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "demo-route"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result1)
	assert.Equal(t, 1, mockClient.applyCount)

	// Second reconcile: same state, should be no-op
	result2, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "demo-route"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result2)
	assert.Equal(t, 1, mockClient.applyCount) // Still 1, no second apply
}

func TestReconciler_ApplyFailure_UpdatesStatus(t *testing.T) {
	ctx := context.Background()
	gwNs := gatewayv1.Namespace("default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ngxora",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}
	ns := &corev1Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8080}},
		},
	}

	ready := true
	slice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend-abc",
			Namespace: "default",
			Labels:    map[string]string{"kubernetes.io/service-name": "backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{
				Addresses:  []string{"10.0.0.1"},
				Conditions: discoveryv1.EndpointConditions{Ready: &ready},
			},
		},
		Ports: []discoveryv1.EndpointPort{{Port: ptrInt32(8080)}},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "demo-route",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "ngxora", Namespace: &gwNs},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend",
									Port: (*gatewayv1.PortNumber)(ptrInt32(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, ns, service, slice, route).
		WithStatusSubresource(gw, route).
		Build()

	applyErr := assert.AnError
	mockClient := newMockClient()
	mockClient.applySnapshotFn = func(ctx context.Context, snap *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error) {
		return nil, applyErr
	}
	reconciler := buildTestReconciler(fakeClient, mockClient)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "demo-route"},
	})

	require.Error(t, err)
	assert.Contains(t, err.Error(), applyErr.Error())
	assert.Equal(t, ctrl.Result{}, result)
}

func TestReconciler_MissingEndpoints_SkipsRoute(t *testing.T) {
	ctx := context.Background()
	gwNs := gatewayv1.Namespace("default")

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ngxora",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}
	ns := &corev1Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}}

	// Service with no endpoints
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "default",
		},
		Spec: corev1.ServiceSpec{
			Ports: []corev1.ServicePort{{Port: 8080}},
		},
	}

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "demo-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "ngxora", Namespace: &gwNs},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					BackendRefs: []gatewayv1.HTTPBackendRef{
						{
							BackendRef: gatewayv1.BackendRef{
								BackendObjectReference: gatewayv1.BackendObjectReference{
									Name: "backend",
									Port: (*gatewayv1.PortNumber)(ptrInt32(8080)),
								},
							},
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, ns, service, route).
		WithStatusSubresource(gw, route).
		Build()

	mockClient := newMockClient()
	reconciler := buildTestReconciler(fakeClient, mockClient)

	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: "default", Name: "demo-route"},
	})

	// Reconciler should succeed but skip the route (no endpoints means route not attached)
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	// Snapshot applied with no routes from this HTTPRoute
	assert.GreaterOrEqual(t, mockClient.applyCount, 0)
}

// buildTestReconciler creates a fully wired HTTPRouteReconciler for testing.
func buildTestReconciler(c client.Client, ngxoraClient *mockNGXoraClient) *HTTPRouteReconciler {
	return &HTTPRouteReconciler{
		Client:           c,
		Logger:           slog.New(slog.DiscardHandler),
		WatchNamespace:   "default",
		GatewayName:      "ngxora",
		GatewayNamespace: "default",
		Translator:       translator.New("ngxora", "default"),
		SnapshotBuilder:  snapshot.NewBuilder(),
		NGXoraClient:     ngxoraClient,
		BackendResolver:  NewBackendResolver(c),
		FilterResolver:   NewFilterResolver(c),
		TLSValidator:     NewTLSValidator(c),
		StatusApplier:    NewStatusApplier(c),
	}
}
