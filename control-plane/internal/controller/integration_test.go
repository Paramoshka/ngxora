//go:build integration

package controller

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/paramoshka/ngxora/control-plane/internal/snapshot"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/paramoshka/ngxora/control-plane/api/v1alpha1"
)

// TestIntegration_HTTPRouteReconciliation is an end-to-end integration test
// that uses a real kube-apiserver (via envtest) to verify the full
// reconciliation pipeline.
//
// Prerequisites:
//   - Install envtest binaries: go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest
//   - Run: setup-envtest use
//   - Run tests with: go test -tags=integration -run TestIntegration
func TestIntegration_HTTPRouteReconciliation(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.TODO()
	testEnv, k8sClient, cfg := setupEnvTest(t)
	defer func() { _ = testEnv.Stop() }()

	require.NoError(t, gatewayv1.Install(scheme.Scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme.Scheme))

	ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "integration-test-"}}
	require.NoError(t, k8sClient.Create(ctx, ns))
	t.Logf("created namespace: %s", ns.Name)

	gwNs := gatewayv1.Namespace(ns.Name)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: ns.Name},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ngxora",
			Listeners: []gatewayv1.Listener{
				{Name: "http", Protocol: gatewayv1.HTTPProtocolType, Port: 8080},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, gateway))

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "backend", Namespace: ns.Name},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "backend"},
			Ports:    []corev1.ServicePort{{Port: 8080, TargetPort: intstr.FromInt32(8080)}},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, service))

	ready := true
	endpointSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "backend-abc", Namespace: ns.Name,
			Labels: map[string]string{"kubernetes.io/service-name": "backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
		Ports: []discoveryv1.EndpointPort{{Name: ptrStr("http"), Port: ptrInt32(8080)}},
	}
	require.NoError(t, k8sClient.Create(ctx, endpointSlice))

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "demo-route", Namespace: ns.Name},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{{Name: "ngxora", Namespace: &gwNs}},
			},
			Hostnames: []gatewayv1.Hostname{"example.com"},
			Rules: []gatewayv1.HTTPRouteRule{
				{
					Matches: []gatewayv1.HTTPRouteMatch{{
						Path: &gatewayv1.HTTPPathMatch{
							Type:  ptrPathMatchType(gatewayv1.PathMatchPathPrefix),
							Value: ptrPathValue("/api"),
						},
					}},
					BackendRefs: []gatewayv1.HTTPBackendRef{{
						BackendRef: gatewayv1.BackendRef{
							BackendObjectReference: gatewayv1.BackendObjectReference{
								Name: "backend",
								Port: (*gatewayv1.PortNumber)(ptrInt32(8080)),
							},
						},
					}},
				},
			},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, route))

	mockClient := newMockClient()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)

	reconciler := &HTTPRouteReconciler{
		Client:           mgr.GetClient(),
		Logger:           slog.New(slog.DiscardHandler),
		WatchNamespace:   ns.Name,
		GatewayName:      "ngxora",
		GatewayNamespace: ns.Name,
		Translator:       translator.New("ngxora", ns.Name),
		SnapshotBuilder:  snapshot.NewBuilder(),
		NGXoraClient:     mockClient,
		BackendResolver:  NewBackendResolver(mgr.GetClient()),
		FilterResolver:   NewFilterResolver(mgr.GetClient()),
		TLSValidator:     NewTLSValidator(mgr.GetClient()),
		StatusApplier:    NewStatusApplier(mgr.GetClient()),
	}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: ns.Name, Name: "demo-route"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.GreaterOrEqual(t, mockClient.applyCount, 1)
	require.NotNil(t, mockClient.appliedSnapshot)
	assert.NotEmpty(t, mockClient.appliedSnapshot.Listeners)
	assert.NotEmpty(t, mockClient.appliedSnapshot.VirtualHosts)
	assert.NotEmpty(t, mockClient.appliedSnapshot.Upstreams)

	updatedRoute := &gatewayv1.HTTPRoute{}
	require.Eventually(t, func() bool {
		err := k8sClient.Get(ctx, types.NamespacedName{Namespace: ns.Name, Name: "demo-route"}, updatedRoute)
		if err != nil {
			return false
		}
		return len(updatedRoute.Status.Parents) > 0
	}, 10*time.Second, 100*time.Millisecond)

	assert.True(t, hasRouteCondition(updatedRoute, string(gatewayv1.RouteConditionAccepted), metav1.ConditionTrue))
}

func TestIntegration_CrossNamespaceWithReferenceGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test in short mode")
	}

	ctx := context.TODO()
	testEnv, k8sClient, cfg := setupEnvTest(t)
	defer func() { _ = testEnv.Stop() }()

	require.NoError(t, gatewayv1.Install(scheme.Scheme))
	require.NoError(t, v1alpha1.AddToScheme(scheme.Scheme))

	gwNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "gw-"}}
	svcNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{GenerateName: "svc-"}}
	require.NoError(t, k8sClient.Create(ctx, gwNS))
	require.NoError(t, k8sClient.Create(ctx, svcNS))

	group := gatewayv1.Group(gatewayv1.GroupName)
	gateway := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{Name: "ngxora", Namespace: gwNS.Name},
		Spec: gatewayv1.GatewaySpec{
			GatewayClassName: "ngxora",
			Listeners: []gatewayv1.Listener{{
				Name:     "http",
				Protocol: gatewayv1.HTTPProtocolType,
				Port:     8080,
				AllowedRoutes: &gatewayv1.AllowedRoutes{
					Namespaces: &gatewayv1.RouteNamespaces{
						From: ptrNamespaceFrom(gatewayv1.NamespacesFromAll),
					},
				},
			}},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, gateway))

	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-ns-backend", Namespace: svcNS.Name},
		Spec:       corev1.ServiceSpec{Ports: []corev1.ServicePort{{Port: 8080}}},
	}
	require.NoError(t, k8sClient.Create(ctx, service))

	ready := true
	endpointSlice := &discoveryv1.EndpointSlice{
		ObjectMeta: metav1.ObjectMeta{
			Name: "backend-abc", Namespace: svcNS.Name,
			Labels: map[string]string{"kubernetes.io/service-name": "cross-ns-backend"},
		},
		Endpoints: []discoveryv1.Endpoint{
			{Addresses: []string{"10.0.0.1"}, Conditions: discoveryv1.EndpointConditions{Ready: &ready}},
		},
		Ports: []discoveryv1.EndpointPort{{Port: ptrInt32(8080)}},
	}
	require.NoError(t, k8sClient.Create(ctx, endpointSlice))

	grant := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-httproute", Namespace: svcNS.Name},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{Group: gatewayv1.Group(group), Kind: "HTTPRoute", Namespace: gatewayv1.Namespace(gwNS.Name)},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{{Group: "", Kind: "Service"}},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, grant))

	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "cross-ns-route", Namespace: gwNS.Name},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{Name: "ngxora", Namespace: (*gatewayv1.Namespace)(&gwNS.Name)},
				},
			},
			Rules: []gatewayv1.HTTPRouteRule{{
				BackendRefs: []gatewayv1.HTTPBackendRef{{
					BackendRef: gatewayv1.BackendRef{
						BackendObjectReference: gatewayv1.BackendObjectReference{
							Name:      "cross-ns-backend",
							Namespace: (*gatewayv1.Namespace)(&svcNS.Name),
							Port:      (*gatewayv1.PortNumber)(ptrInt32(8080)),
						},
					},
				}},
			}},
		},
	}
	require.NoError(t, k8sClient.Create(ctx, route))

	mockClient := newMockClient()
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)

	reconciler := &HTTPRouteReconciler{
		Client:           mgr.GetClient(),
		Logger:           slog.New(slog.DiscardHandler),
		WatchNamespace:   gwNS.Name,
		GatewayName:      "ngxora",
		GatewayNamespace: gwNS.Name,
		Translator:       translator.New("ngxora", gwNS.Name),
		SnapshotBuilder:  snapshot.NewBuilder(),
		NGXoraClient:     mockClient,
		BackendResolver:  NewBackendResolver(mgr.GetClient()),
		FilterResolver:   NewFilterResolver(mgr.GetClient()),
		TLSValidator:     NewTLSValidator(mgr.GetClient()),
		StatusApplier:    NewStatusApplier(mgr.GetClient()),
	}

	result, err := reconciler.Reconcile(ctx, ctrl.Request{
		NamespacedName: types.NamespacedName{Namespace: gwNS.Name, Name: "cross-ns-route"},
	})
	require.NoError(t, err)
	assert.Equal(t, ctrl.Result{}, result)
	assert.GreaterOrEqual(t, mockClient.applyCount, 1)
	require.NotNil(t, mockClient.appliedSnapshot)
	assert.NotEmpty(t, mockClient.appliedSnapshot.Upstreams)
}

// --- Integration test infrastructure ---

var envTestInstance *envtest.Environment

func setupEnvTest(t *testing.T) (*envtest.Environment, client.Client, *rest.Config) {
	t.Helper()

	if envTestInstance == nil {
		envTestInstance = &envtest.Environment{
			CRDDirectoryPaths:     []string{filepath.Join("..", "..", "examples", "crds")},
			ErrorIfCRDPathMissing: false,
		}
	}

	cfg, err := envTestInstance.Start()
	if err != nil {
		t.Skipf("envtest not available: %v (install: go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest && setup-envtest use)", err)
	}

	k8sClient, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)

	return envTestInstance, k8sClient, cfg
}

func hasRouteCondition(route *gatewayv1.HTTPRoute, condType string, status metav1.ConditionStatus) bool {
	for _, parent := range route.Status.Parents {
		for _, cond := range parent.Conditions {
			if cond.Type == condType && cond.Status == status {
				return true
			}
		}
	}
	return false
}

func ptrPathMatchType(t gatewayv1.PathMatchType) *gatewayv1.PathMatchType { return &t }
func ptrPathValue(v string) *string {
	return &v
}
func ptrNamespaceFrom(f gatewayv1.FromNamespaces) *gatewayv1.FromNamespaces {
	return &f
}

func init() {
	_ = os.Setenv("DISABLE_AUTH", "true")
}
