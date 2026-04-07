package controller

import (
	"errors"
	"testing"

	ngxorastatus "github.com/paramoshka/ngxora/control-plane/internal/status"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	types "sigs.k8s.io/gateway-api/apis/v1"
)

func TestInvalidFilterPlanUsesInvalidExtensionRefReason(t *testing.T) {
	route := &types.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
	}

	plan := invalidFilterPlan(
		route,
		nil,
		newFilterResolutionError(
			ngxorastatus.ReasonInvalidExtensionRef,
			errors.New("unsupported ExtensionRef kind"),
		),
	)

	if plan.resolved.reason != ngxorastatus.ReasonInvalidExtensionRef {
		t.Fatalf("expected reason %q, got %q", ngxorastatus.ReasonInvalidExtensionRef, plan.resolved.reason)
	}
}

func TestInvalidFilterPlanUsesExtensionRefNotFoundReason(t *testing.T) {
	route := &types.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
	}

	notFound := apierrors.NewNotFound(schema.GroupResource{
		Group:    "plugins.ngxora.io",
		Resource: "ratelimitpolicies",
	}, "missing")

	plan := invalidFilterPlan(
		route,
		nil,
		newFilterResolutionError(ngxorastatus.ReasonExtensionRefNotFound, notFound),
	)

	if plan.resolved.reason != ngxorastatus.ReasonExtensionRefNotFound {
		t.Fatalf("expected reason %q, got %q", ngxorastatus.ReasonExtensionRefNotFound, plan.resolved.reason)
	}
}

func TestInvalidFilterPlanDefaultsToUnsupportedValue(t *testing.T) {
	route := &types.HTTPRoute{
		ObjectMeta: metav1.ObjectMeta{Name: "demo", Namespace: "default"},
	}

	plan := invalidFilterPlan(route, nil, errors.New("filter config marshal failed"))

	if plan.resolved.reason != string(types.RouteReasonUnsupportedValue) {
		t.Fatalf("expected reason %q, got %q", types.RouteReasonUnsupportedValue, plan.resolved.reason)
	}
}
