package controller

import (
	"context"
	"fmt"
	"testing"

	ngxorastatus "github.com/paramoshka/ngxora/control-plane/internal/status"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestStatusApplier_ApplyHTTPRouteStatus_Accepted(t *testing.T) {
	ctx := context.Background()
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route).
		WithStatusSubresource(route).
		Build()

	applier := NewStatusApplier(fakeClient)

	// Fetch the route to get the latest version
	key := types.NamespacedName{Namespace: "default", Name: "test-route"}
	require.NoError(t, fakeClient.Get(ctx, key, route))

	parentRef := gatewayv1.ParentReference{
		Name:      "ngxora",
		Namespace: (*gatewayv1.Namespace)(ptrStr("default")),
	}

	plan := httpRouteStatusPlan{
		route:      route,
		parentRefs: []gatewayv1.ParentReference{parentRef},
		accepted: routeConditionState{
			status:  true,
			reason:  string(gatewayv1.RouteReasonAccepted),
			message: "route attached to target Gateway",
		},
		resolved: routeConditionState{
			status:  true,
			reason:  string(gatewayv1.RouteReasonResolvedRefs),
			message: "all backendRefs were resolved",
		},
		programmed: routeConditionState{
			status:  true,
			reason:  ngxorastatus.ReasonProgrammed,
			message: "snapshot applied",
		},
	}

	require.NoError(t, applier.ApplyHTTPRouteStatus(ctx, route, plan))

	// Verify status was updated
	assert.Len(t, route.Status.Parents, 1)
	assert.Equal(t, gatewayv1.GatewayController(ngxorastatus.ControllerName), route.Status.Parents[0].ControllerName)
	assert.True(t, hasCondition(route.Status.Parents[0].Conditions, string(gatewayv1.RouteConditionAccepted), metav1.ConditionTrue))
}

func TestStatusApplier_ApplyHTTPRouteStatus_ClearStatus(t *testing.T) {
	ctx := context.Background()
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "test-route",
			Namespace:  "default",
			Generation: 1,
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(route).
		WithStatusSubresource(route).
		Build()

	applier := NewStatusApplier(fakeClient)

	// Fetch the route to get the latest version
	key := types.NamespacedName{Namespace: "default", Name: "test-route"}
	require.NoError(t, fakeClient.Get(ctx, key, route))

	plan := httpRouteStatusPlan{
		route: route,
		clear: true,
	}

	require.NoError(t, applier.ApplyHTTPRouteStatus(ctx, route, plan))

	// Clear should result in no parent statuses from our controller
	for _, parent := range route.Status.Parents {
		assert.NotEqual(t, gatewayv1.GatewayController(ngxorastatus.ControllerName), parent.ControllerName)
	}
}

func TestStatusApplier_SyncGatewayStatus_Programmed(t *testing.T) {
	ctx := context.Background()
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ngxora",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Protocol: gatewayv1.HTTPProtocolType,
					Port:     8080,
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw).
		WithStatusSubresource(gw).
		Build()

	applier := NewStatusApplier(fakeClient)

	// Fetch the gateway to get the latest version
	key := types.NamespacedName{Namespace: "default", Name: "ngxora"}
	require.NoError(t, fakeClient.Get(ctx, key, gw))

	evaluations := map[string]gatewayListenerEvaluation{
		"http": {
			accepted: routeConditionState{
				status:  true,
				reason:  string(gatewayv1.ListenerReasonAccepted),
				message: "listener is accepted",
			},
			resolved: routeConditionState{
				status:  true,
				reason:  string(gatewayv1.ListenerReasonResolvedRefs),
				message: "references resolved",
			},
		},
	}

	require.NoError(t, applier.SyncGatewayStatus(
		ctx, gw, map[string]int32{"http": 2},
		evaluations, true, ngxorastatus.ReasonProgrammed, "snapshot applied",
	))

	// Verify listener status
	require.Len(t, gw.Status.Listeners, 1)
	assert.Equal(t, gatewayv1.SectionName("http"), gw.Status.Listeners[0].Name)
	assert.Equal(t, int32(2), gw.Status.Listeners[0].AttachedRoutes)

	// Verify gateway conditions
	assert.True(t, hasCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), metav1.ConditionTrue))
	assert.True(t, hasCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), metav1.ConditionTrue))
}

func TestStatusApplier_SyncGatewayStatus_UnsupportedProtocol(t *testing.T) {
	ctx := context.Background()
	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:       "ngxora",
			Namespace:  "default",
			Generation: 1,
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "tcp",
					Protocol: gatewayv1.TCPProtocolType,
					Port:     9000,
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw).
		WithStatusSubresource(gw).
		Build()

	applier := NewStatusApplier(fakeClient)

	key := types.NamespacedName{Namespace: "default", Name: "ngxora"}
	require.NoError(t, fakeClient.Get(ctx, key, gw))

	require.NoError(t, applier.SyncGatewayStatus(
		ctx, gw, map[string]int32{},
		map[string]gatewayListenerEvaluation{},
		false, ngxorastatus.ReasonTranslationFailed, "no supported listeners",
	))

	// Gateway should not be accepted/programmed without supported listeners
	assert.False(t, hasCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionAccepted), metav1.ConditionTrue))
	assert.False(t, hasCondition(gw.Status.Conditions, string(gatewayv1.GatewayConditionProgrammed), metav1.ConditionTrue))
}

func TestStatusApplier_ComputeListenerAttachedRoutes(t *testing.T) {
	ctx := context.Background()

	gw := &gatewayv1.Gateway{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ngxora",
			Namespace: "default",
		},
		Spec: gatewayv1.GatewaySpec{
			Listeners: []gatewayv1.Listener{
				{
					Name:     "http",
					Protocol: gatewayv1.HTTPProtocolType,
					Port:     8080,
				},
			},
		},
	}

	gwNs := gatewayv1.Namespace("default")
	route := &gatewayv1.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-route",
			Namespace: "default",
		},
		Spec: gatewayv1.HTTPRouteSpec{
			CommonRouteSpec: gatewayv1.CommonRouteSpec{
				ParentRefs: []gatewayv1.ParentReference{
					{
						Name:      "ngxora",
						Namespace: &gwNs,
					},
				},
			},
		},
	}

	ns := &corev1Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name: "default",
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(gw, route, ns).
		Build()

	applier := NewStatusApplier(fakeClient)
	translator := translator.New("ngxora", "default")

	evaluations := map[string]gatewayListenerEvaluation{
		"http": {
			accepted: routeConditionState{status: true, reason: string(gatewayv1.ListenerReasonAccepted), message: "accepted"},
			resolved: routeConditionState{status: true, reason: string(gatewayv1.ListenerReasonResolvedRefs), message: "resolved"},
		},
	}

	attached, err := applier.ComputeListenerAttachedRoutes(
		ctx, gw, []gatewayv1.HTTPRoute{*route},
		map[string]map[string]string{"default": {}},
		evaluations, translator,
	)
	require.NoError(t, err)
	assert.Equal(t, int32(1), attached["http"])
}

func TestStatusApplier_GetNamespaceLabels_Cached(t *testing.T) {
	ctx := context.Background()

	ns := &corev1Namespace{
		ObjectMeta: metav1.ObjectMeta{
			Name:   "default",
			Labels: map[string]string{"env": "test", "app": "ngxora"},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(ns).
		Build()

	applier := NewStatusApplier(fakeClient)
	cache := make(map[string]map[string]string)

	// First call should hit the API
	labels, err := applier.GetNamespaceLabels(ctx, "default", cache)
	require.NoError(t, err)
	assert.Equal(t, "test", labels["env"])
	assert.Equal(t, "ngxora", labels["app"])

	// Second call should use cache
	delete(ns.Labels, "env") // Mutate the real object
	labels2, err := applier.GetNamespaceLabels(ctx, "default", cache)
	require.NoError(t, err)
	assert.Contains(t, labels2, "env") // Still has "env" from cache
}

func TestRouteCondition(t *testing.T) {
	tests := []struct {
		name          string
		status        bool
		wantCondition metav1.ConditionStatus
	}{
		{name: "true status", status: true, wantCondition: metav1.ConditionTrue},
		{name: "false status", status: false, wantCondition: metav1.ConditionFalse},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cond := routeCondition(42, "TestCondition", tc.status, "TestReason", "Test message")
			assert.Equal(t, "TestCondition", cond.Type)
			assert.Equal(t, tc.wantCondition, cond.Status)
			assert.Equal(t, int64(42), cond.ObservedGeneration)
			assert.Equal(t, "TestReason", cond.Reason)
			assert.Equal(t, "Test message", cond.Message)
		})
	}
}

func TestParentStatusKey(t *testing.T) {
	tests := []struct {
		name     string
		ref      gatewayv1.ParentReference
		ns       string
		wantPart string
	}{
		{
			name: "minimal ref",
			ref: gatewayv1.ParentReference{
				Name: "ngxora",
			},
			ns:       "default",
			wantPart: "gateway.networking.k8s.io/Gateway/default/ngxora//0",
		},
		{
			name: "with section name",
			ref: gatewayv1.ParentReference{
				Name:        "ngxora",
				SectionName: (*gatewayv1.SectionName)(ptrStr("http")),
			},
			ns:       "default",
			wantPart: "gateway.networking.k8s.io/Gateway/default/ngxora/http/0",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			key := parentStatusKey(tc.ref, tc.ns)
			assert.Contains(t, key, tc.wantPart)
		})
	}
}

func TestGatewayAcceptedReason(t *testing.T) {
	tests := []struct {
		name     string
		valid    int
		invalid  int
		want     string
	}{
		{name: "no listeners", valid: 0, invalid: 0, want: string(gatewayv1.GatewayReasonListenersNotValid)},
		{name: "some invalid", valid: 1, invalid: 1, want: string(gatewayv1.GatewayReasonListenersNotValid)},
		{name: "all valid", valid: 2, invalid: 0, want: string(gatewayv1.GatewayReasonAccepted)},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, gatewayAcceptedReason(tc.valid, tc.invalid))
		})
	}
}

func TestListenerTLSBindings(t *testing.T) {
	evaluations := map[string]gatewayListenerEvaluation{
		"http": {
			accepted: routeConditionState{status: true, reason: "Accepted", message: ""},
		},
		"https": {
			accepted: routeConditionState{status: true, reason: "Accepted", message: ""},
			tls:      &controlv1.TlsBinding{},
		},
		"rejected": {
			accepted: routeConditionState{status: false, reason: "Rejected", message: ""},
			tls:      &controlv1.TlsBinding{},
		},
	}

	bindings := listenerTLSBindings(evaluations)

	assert.NotContains(t, bindings, "http")    // no TLS
	assert.Contains(t, bindings, "https")      // accepted + TLS
	assert.NotContains(t, bindings, "rejected") // not accepted
}

func TestListenerUsableForRoutes(t *testing.T) {
	evaluations := map[string]gatewayListenerEvaluation{
		"usable": {
			accepted: routeConditionState{status: true},
			resolved: routeConditionState{status: true},
		},
		"not_accepted": {
			accepted: routeConditionState{status: false},
			resolved: routeConditionState{status: true},
		},
		"not_resolved": {
			accepted: routeConditionState{status: true},
			resolved: routeConditionState{status: false},
		},
	}

	usable := listenerUsableForRoutes(evaluations)

	assert.True(t, usable["usable"])
	assert.False(t, usable["not_accepted"])
	assert.False(t, usable["not_resolved"])
}

func TestMarkProgrammed_SkipsClearedPlans(t *testing.T) {
	plans := []httpRouteStatusPlan{
		{clear: true, accepted: routeConditionState{status: true}, resolved: routeConditionState{status: true}},
		{accepted: routeConditionState{status: true}, resolved: routeConditionState{status: true}},
		{accepted: routeConditionState{status: false}, resolved: routeConditionState{status: true}},
	}

	reconciler := &HTTPRouteReconciler{}
	reconciler.markProgrammed(plans, true, ngxorastatus.ReasonProgrammed, "done")

	// Cleared plan should not be updated
	assert.False(t, plans[0].programmed.status)
	// Accepted + resolved plan should be updated
	assert.True(t, plans[1].programmed.status)
	// Not accepted plan should not be updated
	assert.False(t, plans[2].programmed.status)
}

func TestFailedTranslationPlan(t *testing.T) {
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	parentRefs := []gatewayv1.ParentReference{{Name: "ngxora"}}
	err := assert.AnError

	plan := failedTranslationPlan(route, parentRefs, err)

	assert.False(t, plan.accepted.status)
	assert.False(t, plan.resolved.status)
	assert.False(t, plan.programmed.status)
	assert.Equal(t, ngxorastatus.ReasonTranslationFailed, plan.accepted.reason)
	assert.Contains(t, plan.accepted.message, "translation failed")
}

func TestUnresolvedRefsPlan_Forbidden(t *testing.T) {
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	parentRefs := []gatewayv1.ParentReference{{Name: "ngxora"}}

	// Simulate a forbidden error
	forbiddenErr := fmt.Errorf("cross-namespace backendRef is not permitted")
	plan := unresolvedRefsPlan(route, parentRefs, forbiddenErr)

	// Should default to BackendNotFound reason for non-API errors
	assert.True(t, plan.accepted.status)
	assert.False(t, plan.resolved.status)
}

func TestInvalidFilterPlan_WithFilterResolutionError(t *testing.T) {
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	parentRefs := []gatewayv1.ParentReference{{Name: "ngxora"}}
	innerErr := assert.AnError
	err := newFilterResolutionError("ExtensionRefNotFound", innerErr)

	plan := invalidFilterPlan(route, parentRefs, err)

	assert.True(t, plan.accepted.status)
	assert.False(t, plan.resolved.status)
	assert.Equal(t, "ExtensionRefNotFound", plan.resolved.reason)
	assert.Contains(t, plan.resolved.message, "filter resolution failed")
}

func TestAcceptedPendingPlan(t *testing.T) {
	route := &gatewayv1.HTTPRoute{ObjectMeta: metav1.ObjectMeta{Name: "test", Namespace: "default"}}
	parentRefs := []gatewayv1.ParentReference{{Name: "ngxora"}}

	plan := acceptedPendingPlan(route, parentRefs)

	assert.True(t, plan.accepted.status)
	assert.True(t, plan.resolved.status)
	assert.False(t, plan.programmed.status)
	assert.Equal(t, ngxorastatus.ReasonPending, plan.programmed.reason)
}

// Helper: type alias for corev1.Namespace to avoid collision
type corev1Namespace = corev1.Namespace

// Helper: check if a condition list has a condition with the given type and status
func hasCondition(conditions []metav1.Condition, condType string, status metav1.ConditionStatus) bool {
	for _, c := range conditions {
		if c.Type == condType && c.Status == status {
			return true
		}
	}
	return false
}
