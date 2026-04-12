package controller

import (
	"context"
	"fmt"
	"reflect"

	"github.com/paramoshka/ngxora/control-plane/internal/attachment"
	ngxorastatus "github.com/paramoshka/ngxora/control-plane/internal/status"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// StatusApplier handles HTTPRoute and Gateway status updates.
type StatusApplier struct {
	client.Client
}

// NewStatusApplier creates a new StatusApplier.
func NewStatusApplier(c client.Client) *StatusApplier {
	return &StatusApplier{Client: c}
}

// ApplyHTTPRouteStatus patches the status of a single HTTPRoute.
func (s *StatusApplier) ApplyHTTPRouteStatus(
	ctx context.Context,
	route *gatewayv1.HTTPRoute,
	plan httpRouteStatusPlan,
) error {
	before := route.DeepCopy()
	s.mergeRouteParentStatuses(route, plan)
	if reflect.DeepEqual(before.Status, route.Status) {
		return nil
	}
	return s.Status().Patch(ctx, route, client.MergeFrom(before))
}

// ApplyStatusPlans patches the status of all HTTPRoutes according to their plans.
func (s *StatusApplier) ApplyStatusPlans(ctx context.Context, plans []httpRouteStatusPlan) error {
	for _, plan := range plans {
		if err := s.ApplyHTTPRouteStatus(ctx, plan.route, plan); err != nil {
			return fmt.Errorf("patch %s/%s status: %w", plan.route.Namespace, plan.route.Name, err)
		}
	}
	return nil
}

// SyncGatewayStatus updates the Gateway status with listener evaluations and
// overall programmed state.
func (s *StatusApplier) SyncGatewayStatus(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	attachedRoutes map[string]int32,
	listenerEvaluations map[string]gatewayListenerEvaluation,
	programmed bool,
	programmedReason string,
	programmedMessage string,
) error {
	before := gateway.DeepCopy()
	gateway.Status.Addresses = s.gatewayStatusAddresses(gateway)

	gateway.Status.Listeners = make([]gatewayv1.ListenerStatus, 0, len(gateway.Spec.Listeners))
	validListeners := 0
	invalidListeners := 0

	for _, listener := range gateway.Spec.Listeners {
		evaluation, ok := listenerEvaluations[string(listener.Name)]
		if !ok {
			evaluation = gatewayListenerEvaluation{
				accepted: routeConditionState{
					status:  false,
					reason:  string(gatewayv1.ListenerReasonUnsupportedProtocol),
					message: fmt.Sprintf("listener protocol %q is not supported by ngxora yet", listener.Protocol),
				},
				resolved: routeConditionState{
					status:  true,
					reason:  string(gatewayv1.ListenerReasonResolvedRefs),
					message: "listener references are resolved",
				},
			}
		}

		listenerStatus := gatewayv1.ListenerStatus{
			Name:           listener.Name,
			AttachedRoutes: attachedRoutes[string(listener.Name)],
		}

		if evaluation.accepted.status {
			validListeners++
			if attachment.ListenerHasSupportedHTTPRouteKind(listener) {
				listenerStatus.SupportedKinds = []gatewayv1.RouteGroupKind{httpRouteGroupKind()}
			}
			s.setListenerConditions(&listenerStatus, gateway.Generation, evaluation, programmed, programmedReason, programmedMessage)
		} else {
			invalidListeners++
			s.setListenerConditions(&listenerStatus, gateway.Generation, evaluation, programmed, programmedReason, programmedMessage)
		}

		gateway.Status.Listeners = append(gateway.Status.Listeners, listenerStatus)
	}

	meta.SetStatusCondition(&gateway.Status.Conditions, routeCondition(
		gateway.Generation,
		string(gatewayv1.GatewayConditionAccepted),
		validListeners > 0,
		gatewayAcceptedReason(validListeners, invalidListeners),
		gatewayAcceptedMessage(validListeners, invalidListeners),
	))
	meta.SetStatusCondition(&gateway.Status.Conditions, routeCondition(
		gateway.Generation,
		string(gatewayv1.GatewayConditionProgrammed),
		validListeners > 0 && programmed,
		gatewayConditionProgrammedReason(validListeners > 0, programmed, programmedReason),
		gatewayConditionProgrammedMessage(validListeners > 0, programmed, programmedMessage),
	))

	if reflect.DeepEqual(before.Status, gateway.Status) {
		return nil
	}
	return s.Status().Patch(ctx, gateway, client.MergeFrom(before))
}

func (s *StatusApplier) setListenerConditions(
	listenerStatus *gatewayv1.ListenerStatus,
	generation int64,
	evaluation gatewayListenerEvaluation,
	programmed bool,
	programmedReason string,
	programmedMessage string,
) {
	meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
		generation,
		string(gatewayv1.ListenerConditionAccepted),
		evaluation.accepted.status,
		evaluation.accepted.reason,
		evaluation.accepted.message,
	))
	meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
		generation,
		string(gatewayv1.ListenerConditionResolvedRefs),
		evaluation.resolved.status,
		evaluation.resolved.reason,
		evaluation.resolved.message,
	))
	meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
		generation,
		string(gatewayv1.ListenerConditionProgrammed),
		evaluation.resolved.status && programmed,
		gatewayListenerProgrammedReason(evaluation, programmed, programmedReason),
		gatewayListenerProgrammedMessage(evaluation, programmed, programmedMessage),
	))
}

func (s *StatusApplier) mergeRouteParentStatuses(
	route *gatewayv1.HTTPRoute,
	plan httpRouteStatusPlan,
) {
	otherParents := make([]gatewayv1.RouteParentStatus, 0, len(route.Status.Parents))
	existingParents := make(map[string]gatewayv1.RouteParentStatus, len(route.Status.Parents))

	for _, parentStatus := range route.Status.Parents {
		if string(parentStatus.ControllerName) != ngxorastatus.ControllerName {
			otherParents = append(otherParents, parentStatus)
			continue
		}
		existingParents[parentStatusKey(parentStatus.ParentRef, route.Namespace)] = parentStatus
	}

	route.Status.Parents = otherParents
	if plan.clear {
		return
	}

	for _, parentRef := range plan.parentRefs {
		key := parentStatusKey(parentRef, route.Namespace)
		parentStatus := gatewayv1.RouteParentStatus{
			ParentRef:      parentRef,
			ControllerName: gatewayv1.GatewayController(ngxorastatus.ControllerName),
		}
		if existing, ok := existingParents[key]; ok {
			parentStatus.Conditions = append(parentStatus.Conditions, existing.Conditions...)
		}

		meta.SetStatusCondition(&parentStatus.Conditions, routeCondition(
			route.Generation,
			string(gatewayv1.RouteConditionAccepted),
			plan.accepted.status,
			plan.accepted.reason,
			plan.accepted.message,
		))
		meta.SetStatusCondition(&parentStatus.Conditions, routeCondition(
			route.Generation,
			string(gatewayv1.RouteConditionResolvedRefs),
			plan.resolved.status,
			plan.resolved.reason,
			plan.resolved.message,
		))
		meta.SetStatusCondition(&parentStatus.Conditions, routeCondition(
			route.Generation,
			ngxorastatus.ConditionProgrammed,
			plan.programmed.status,
			plan.programmed.reason,
			plan.programmed.message,
		))

		route.Status.Parents = append(route.Status.Parents, parentStatus)
	}
}

func (s *StatusApplier) gatewayStatusAddresses(gateway *gatewayv1.Gateway) []gatewayv1.GatewayStatusAddress {
	addresses := make([]gatewayv1.GatewayStatusAddress, 0, len(gateway.Spec.Addresses))
	for _, address := range gateway.Spec.Addresses {
		if address.Value == "" {
			continue
		}

		addressType := gatewayv1.IPAddressType
		if address.Type != nil {
			addressType = *address.Type
		}

		addresses = append(addresses, gatewayv1.GatewayStatusAddress{
			Type:  &addressType,
			Value: address.Value,
		})
	}

	if len(addresses) == 0 {
		addressType := gatewayv1.IPAddressType
		addresses = append(addresses, gatewayv1.GatewayStatusAddress{
			Type:  &addressType,
			Value: "0.0.0.0",
		})
	}

	return addresses
}

// GetTargetGateway fetches the target Gateway object.
func (s *StatusApplier) GetTargetGateway(ctx context.Context, key types.NamespacedName) (*gatewayv1.Gateway, error) {
	gateway := &gatewayv1.Gateway{}
	if err := s.Get(ctx, key, gateway); err != nil {
		return nil, err
	}
	return gateway, nil
}

// GetNamespaceLabels fetches labels for a namespace, with optional caching.
func (s *StatusApplier) GetNamespaceLabels(
	ctx context.Context,
	namespace string,
	cache map[string]map[string]string,
) (map[string]string, error) {
	if cache != nil {
		if labels, ok := cache[namespace]; ok {
			return labels, nil
		}
	}

	ns := &corev1.Namespace{}
	if err := s.Get(ctx, types.NamespacedName{Name: namespace}, ns); err != nil {
		return nil, fmt.Errorf("get namespace %s: %w", namespace, err)
	}

	result := make(map[string]string, len(ns.Labels))
	for key, value := range ns.Labels {
		result[key] = value
	}

	if cache != nil {
		cache[namespace] = result
	}

	return result, nil
}

// ComputeListenerAttachedRoutes calculates how many routes are attached to
// each listener for status reporting.
func (s *StatusApplier) ComputeListenerAttachedRoutes(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	routes []gatewayv1.HTTPRoute,
	namespaceLabelsCache map[string]map[string]string,
	listenerEvaluations map[string]gatewayListenerEvaluation,
	translator *translator.Translator,
) (map[string]int32, error) {
	attached := make(map[string]int32, len(gateway.Spec.Listeners))
	for _, route := range routes {
		parentRefs := translator.MatchingParentRefs(route)
		if len(parentRefs) == 0 {
			continue
		}

		namespaceLabels, err := s.GetNamespaceLabels(ctx, route.Namespace, namespaceLabelsCache)
		if err != nil {
			return nil, err
		}

		routeHostnames := make([]string, 0, len(route.Spec.Hostnames))
		for _, hostname := range route.Spec.Hostnames {
			routeHostnames = append(routeHostnames, string(hostname))
		}

		for _, listener := range gateway.Spec.Listeners {
			evaluation, ok := listenerEvaluations[string(listener.Name)]
			if !ok || !evaluation.accepted.status || !evaluation.resolved.status {
				continue
			}

			allowed, err := attachment.ListenerAllowsHTTPRoute(listener, gateway.Namespace, route.Namespace, namespaceLabels)
			if err != nil {
				return nil, err
			}
			if attachment.ListenerSelectedByParentRefs(listener, parentRefs) &&
				allowed &&
				len(attachment.EffectiveServerNames(routeHostnames, listener.Hostname)) > 0 {
				attached[string(listener.Name)]++
			}
		}
	}

	return attached, nil
}

// Status plan types shared across controller and status applier.
type routeConditionState struct {
	status  bool
	reason  string
	message string
}

type httpRouteStatusPlan struct {
	route      *gatewayv1.HTTPRoute
	parentRefs []gatewayv1.ParentReference
	clear      bool
	accepted   routeConditionState
	resolved   routeConditionState
	programmed routeConditionState
}

type gatewayListenerEvaluation struct {
	accepted routeConditionState
	resolved routeConditionState
	tls      *controlv1.TlsBinding
}

func routeCondition(
	generation int64,
	conditionType string,
	status bool,
	reason string,
	message string,
) metav1.Condition {
	conditionStatus := metav1.ConditionFalse
	if status {
		conditionStatus = metav1.ConditionTrue
	}

	return metav1.Condition{
		Type:               conditionType,
		Status:             conditionStatus,
		ObservedGeneration: generation,
		LastTransitionTime: metav1.Now(),
		Reason:             reason,
		Message:            message,
	}
}

func parentStatusKey(parentRef gatewayv1.ParentReference, routeNamespace string) string {
	group := string(gatewayv1.GroupName)
	if parentRef.Group != nil {
		group = string(*parentRef.Group)
	}

	kind := "Gateway"
	if parentRef.Kind != nil {
		kind = string(*parentRef.Kind)
	}

	namespace := routeNamespace
	if parentRef.Namespace != nil {
		namespace = string(*parentRef.Namespace)
	}

	sectionName := ""
	if parentRef.SectionName != nil {
		sectionName = string(*parentRef.SectionName)
	}

	port := 0
	if parentRef.Port != nil {
		port = int(*parentRef.Port)
	}

	return fmt.Sprintf("%s/%s/%s/%s/%s/%d", group, kind, namespace, parentRef.Name, sectionName, port)
}

func httpRouteGroupKind() gatewayv1.RouteGroupKind {
	group := gatewayv1.Group(gatewayv1.GroupName)
	return gatewayv1.RouteGroupKind{
		Group: &group,
		Kind:  gatewayv1.Kind("HTTPRoute"),
	}
}

func gatewayAcceptedReason(validListeners, invalidListeners int) string {
	switch {
	case validListeners == 0:
		return string(gatewayv1.GatewayReasonListenersNotValid)
	case invalidListeners > 0:
		return string(gatewayv1.GatewayReasonListenersNotValid)
	default:
		return string(gatewayv1.GatewayReasonAccepted)
	}
}

func gatewayAcceptedMessage(validListeners, invalidListeners int) string {
	switch {
	case validListeners == 0:
		return "gateway has no supported HTTP or HTTPS listeners"
	case invalidListeners > 0:
		return "gateway has at least one supported listener and one or more unsupported listeners"
	default:
		return "gateway listeners are accepted by ngxora"
	}
}

func gatewayConditionProgrammedReason(hasAcceptedListeners bool, programmed bool, notProgrammedReason string) string {
	if !hasAcceptedListeners {
		return string(gatewayv1.GatewayReasonListenersNotValid)
	}
	if programmed {
		return string(gatewayv1.GatewayReasonProgrammed)
	}
	if notProgrammedReason != "" {
		return notProgrammedReason
	}
	return ngxorastatus.ReasonApplyFailed
}

func gatewayConditionProgrammedMessage(hasAcceptedListeners bool, programmed bool, message string) string {
	switch {
	case !hasAcceptedListeners:
		return "gateway has no valid listeners to program"
	case programmed:
		return message
	case message != "":
		return message
	default:
		return "gateway configuration is not programmed"
	}
}

func gatewayListenerProgrammedReason(
	evaluation gatewayListenerEvaluation,
	programmed bool,
	notProgrammedReason string,
) string {
	if !evaluation.accepted.status {
		return evaluation.accepted.reason
	}
	if !evaluation.resolved.status {
		return evaluation.resolved.reason
	}
	if programmed {
		return string(gatewayv1.ListenerReasonProgrammed)
	}
	if notProgrammedReason != "" {
		return notProgrammedReason
	}
	return ngxorastatus.ReasonApplyFailed
}

func gatewayListenerProgrammedMessage(
	evaluation gatewayListenerEvaluation,
	programmed bool,
	message string,
) string {
	if !evaluation.accepted.status {
		return "listener is not programmed because it is not accepted"
	}
	if !evaluation.resolved.status {
		return "listener is not programmed because references are not resolved"
	}
	if programmed {
		return message
	}
	if message != "" {
		return message
	}
	return "listener configuration is not programmed"
}
