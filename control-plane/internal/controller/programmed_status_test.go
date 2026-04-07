package controller

import (
	"testing"

	ngxorastatus "github.com/paramoshka/ngxora/control-plane/internal/status"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestMarkProgrammedUsesExplicitReason(t *testing.T) {
	plans := []httpRouteStatusPlan{{
		accepted: routeConditionState{status: true},
		resolved: routeConditionState{status: true},
	}}

	(&HTTPRouteReconciler{}).markProgrammed(
		plans,
		false,
		ngxorastatus.ReasonRestartRequired,
		"snapshot requires restart",
	)

	if plans[0].programmed.status {
		t.Fatalf("expected programmed status to be false")
	}
	if plans[0].programmed.reason != ngxorastatus.ReasonRestartRequired {
		t.Fatalf("expected reason %q, got %q", ngxorastatus.ReasonRestartRequired, plans[0].programmed.reason)
	}
	if plans[0].programmed.message != "snapshot requires restart" {
		t.Fatalf("unexpected programmed message: %q", plans[0].programmed.message)
	}
}

func TestGatewayConditionProgrammedReasonUsesRestartRequired(t *testing.T) {
	reason := gatewayConditionProgrammedReason(true, false, ngxorastatus.ReasonRestartRequired)
	if reason != ngxorastatus.ReasonRestartRequired {
		t.Fatalf("expected restart-required reason, got %q", reason)
	}

	reason = gatewayConditionProgrammedReason(true, true, ngxorastatus.ReasonRestartRequired)
	if reason != string(gatewayv1.GatewayReasonProgrammed) {
		t.Fatalf("expected programmed reason, got %q", reason)
	}

	reason = gatewayConditionProgrammedReason(false, false, ngxorastatus.ReasonRestartRequired)
	if reason != string(gatewayv1.GatewayReasonListenersNotValid) {
		t.Fatalf("expected listeners-not-valid reason, got %q", reason)
	}
}

func TestGatewayListenerProgrammedReasonUsesRestartRequired(t *testing.T) {
	evaluation := gatewayListenerEvaluation{
		accepted: routeConditionState{status: true},
		resolved: routeConditionState{status: true},
	}

	reason := gatewayListenerProgrammedReason(evaluation, false, ngxorastatus.ReasonRestartRequired)
	if reason != ngxorastatus.ReasonRestartRequired {
		t.Fatalf("expected restart-required reason, got %q", reason)
	}

	reason = gatewayListenerProgrammedReason(evaluation, true, ngxorastatus.ReasonRestartRequired)
	if reason != string(gatewayv1.ListenerReasonProgrammed) {
		t.Fatalf("expected programmed reason, got %q", reason)
	}
}
