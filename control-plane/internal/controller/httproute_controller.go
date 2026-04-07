package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"time"

	"github.com/paramoshka/ngxora/control-plane/api/v1alpha1"
	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha3 "sigs.k8s.io/gateway-api/apis/v1alpha3"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/paramoshka/ngxora/control-plane/internal/attachment"
	ngxoraclient "github.com/paramoshka/ngxora/control-plane/internal/client"
	"github.com/paramoshka/ngxora/control-plane/internal/snapshot"
	ngxorastatus "github.com/paramoshka/ngxora/control-plane/internal/status"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type HTTPRouteReconciler struct {
	client.Client
	Logger           *slog.Logger
	WatchNamespace   string
	GatewayName      string
	GatewayNamespace string
	Translator       *translator.Translator
	SnapshotBuilder  *snapshot.Builder
	NGXoraClient     *ngxoraclient.NGXoraClient
}

func (r *HTTPRouteReconciler) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
	if r.WatchNamespace != "" && req.Namespace != r.WatchNamespace {
		return ctrl.Result{}, nil
	}

	r.Logger.Info("reconciling HTTPRoute", "name", req.NamespacedName.String())

	var routeList gatewayv1.HTTPRouteList
	if err := r.List(ctx, &routeList, client.InNamespace(r.WatchNamespace)); err != nil {
		return ctrl.Result{}, fmt.Errorf("list HTTPRoutes: %w", err)
	}

	gateway, err := r.getTargetGateway(ctx)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("get target Gateway: %w", err)
	}

	serviceCache := make(map[types.NamespacedName]*corev1.Service)
	secretCache := make(map[types.NamespacedName]*corev1.Secret)
	referenceGrantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)
	namespaceLabelsCache := make(map[string]map[string]string)
	desiredState := &translator.DesiredState{
		Routes: make([]translator.DesiredRoute, 0, len(routeList.Items)),
	}
	statusPlans := make([]httpRouteStatusPlan, 0, len(routeList.Items))
	pendingRoutes := make([]pendingRoute, 0, len(routeList.Items))

	for i := range routeList.Items {
		route := &routeList.Items[i]
		parentRefs := r.Translator.MatchingParentRefs(*route)
		if len(parentRefs) == 0 {
			statusPlans = append(statusPlans, httpRouteStatusPlan{
				route:      route,
				parentRefs: nil,
				clear:      true,
			})
			continue
		}

		desiredRoute, err := r.Translator.TranslateHTTPRoute(*route)
		if err != nil {
			statusPlans = append(statusPlans, failedTranslationPlan(route, parentRefs, err))
			r.Logger.Warn("skipping invalid HTTPRoute", "name", route.Name, "namespace", route.Namespace, "error", err)
			continue
		}
		desiredRoute.ParentRefs = append([]gatewayv1.ParentReference(nil), parentRefs...)
		if _, err := r.getNamespaceLabels(ctx, route.Namespace, namespaceLabelsCache); err != nil {
			return ctrl.Result{}, fmt.Errorf("get namespace labels for %s: %w", route.Namespace, err)
		}

		if err := r.resolveBackendRefs(ctx, route.Namespace, &desiredRoute, serviceCache, referenceGrantCache); err != nil {
			statusPlans = append(statusPlans, unresolvedRefsPlan(route, parentRefs, err))
			r.Logger.Warn("skipping unresolved HTTPRoute backends", "name", route.Name, "namespace", route.Namespace, "error", err)
			continue
		}

		if err := r.resolveFilters(ctx, route.Namespace, &desiredRoute, referenceGrantCache); err != nil {
			statusPlans = append(statusPlans, invalidFilterPlan(route, parentRefs, err))
			r.Logger.Warn("skipping invalid HTTPRoute filters", "name", route.Name, "namespace", route.Namespace, "error", err)
			continue
		}

		pendingRoutes = append(pendingRoutes, pendingRoute{
			route:      route,
			parentRefs: parentRefs,
			desired:    desiredRoute,
		})
		desiredState.Routes = append(desiredState.Routes, desiredRoute)
	}

	listenerEvaluations, err := r.evaluateGatewayListeners(ctx, gateway, secretCache, referenceGrantCache)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("evaluate Gateway listeners: %w", err)
	}

	listenerAttachedRoutes, err := r.gatewayListenerAttachedRoutes(ctx, gateway, routeList.Items, namespaceLabelsCache, listenerEvaluations)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("compute Gateway attached routes: %w", err)
	}

	buildResult, err := r.SnapshotBuilder.Build(
		desiredState,
		gateway,
		namespaceLabelsCache,
		listenerTLSBindings(listenerEvaluations),
		listenerUsableForRoutes(listenerEvaluations),
	)
	if err != nil {
		for _, pending := range pendingRoutes {
			statusPlans = append(statusPlans, r.unattachedPlan(ctx, gateway, pending.route, pending.parentRefs, namespaceLabelsCache, listenerEvaluations))
		}
		if statusErr := r.applyStatusPlans(ctx, statusPlans); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("build snapshot: %w; update route status: %v", err, statusErr)
		}
		if statusErr := r.syncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, false, ngxorastatus.ReasonTranslationFailed, err.Error()); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("build snapshot: %w; update gateway status: %v", err, statusErr)
		}
		return ctrl.Result{}, fmt.Errorf("build snapshot: %w", err)
	}
	for _, pending := range pendingRoutes {
		if buildResult.RouteAttachments[routeKey(pending.desired)] == 0 {
			statusPlans = append(statusPlans, r.unattachedPlan(ctx, gateway, pending.route, pending.parentRefs, namespaceLabelsCache, listenerEvaluations))
			continue
		}
		statusPlans = append(statusPlans, acceptedPendingPlan(pending.route, pending.parentRefs))
	}

	version, err := snapshot.StableVersion(buildResult.Snapshot)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("hash snapshot: %w", err)
	}
	buildResult.Snapshot.Version = version

	activeSnapshot, err := r.NGXoraClient.GetSnapshot(ctx)
	if err == nil && activeSnapshot != nil && activeSnapshot.Version == version {
		r.markProgrammed(statusPlans, true, ngxorastatus.ReasonProgrammed, "active snapshot already matches desired version")
		if err := r.applyStatusPlans(ctx, statusPlans); err != nil {
			return ctrl.Result{}, fmt.Errorf("update HTTPRoute status after no-op apply: %w", err)
		}
		if err := r.syncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, true, ngxorastatus.ReasonProgrammed, "active snapshot already matches desired version"); err != nil {
			return ctrl.Result{}, fmt.Errorf("update Gateway status after no-op apply: %w", err)
		}
		r.Logger.Info("snapshot unchanged, skipping apply", "version", version)
		return ctrl.Result{}, nil
	}

	result, err := r.NGXoraClient.ApplySnapshot(ctx, buildResult.Snapshot)
	if err != nil {
		r.markProgrammed(statusPlans, false, ngxorastatus.ReasonApplyFailed, err.Error())
		if statusErr := r.applyStatusPlans(ctx, statusPlans); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("apply snapshot: %w; update status: %v", err, statusErr)
		}
		if statusErr := r.syncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, false, ngxorastatus.ReasonApplyFailed, err.Error()); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("apply snapshot: %w; update gateway status: %v", err, statusErr)
		}
		return ctrl.Result{}, fmt.Errorf("apply snapshot: %w", err)
	}

	programmed := true
	programmedReason := ngxorastatus.ReasonProgrammed
	programmedMessage := fmt.Sprintf("snapshot version %s applied", version)
	if result.RestartRequired {
		programmed = false
		programmedReason = ngxorastatus.ReasonRestartRequired
		if result.ActiveVersion != "" {
			programmedMessage = fmt.Sprintf(
				"snapshot version %s requires restart to activate; dataplane is still serving version %s",
				version,
				result.ActiveVersion,
			)
		} else {
			programmedMessage = fmt.Sprintf(
				"snapshot version %s requires restart to activate; dataplane is still serving the previous runtime state",
				version,
			)
		}
	}

	r.markProgrammed(statusPlans, programmed, programmedReason, programmedMessage)
	if err := r.applyStatusPlans(ctx, statusPlans); err != nil {
		return ctrl.Result{}, fmt.Errorf("update HTTPRoute status after apply: %w", err)
	}
	if err := r.syncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, programmed, programmedReason, programmedMessage); err != nil {
		return ctrl.Result{}, fmt.Errorf("update Gateway status after apply: %w", err)
	}

	r.Logger.Info(
		"snapshot applied",
		"applied", result.Applied,
		"restart_required", result.RestartRequired,
		"active_version", result.ActiveVersion,
		"version", version,
	)

	return ctrl.Result{}, nil
}

func (r *HTTPRouteReconciler) SetupWithManager(mgr ctrl.Manager) error {
	return ctrl.NewControllerManagedBy(mgr).
		For(&gatewayv1.HTTPRoute{}).
		Watches(&gatewayv1.Gateway{}, handler.EnqueueRequestsFromMapFunc(enqueueAllHTTPRoutes(r.Client, r.WatchNamespace))).
		Watches(&corev1.Secret{}, handler.EnqueueRequestsFromMapFunc(r.enqueueRoutesForSecret())).
		Watches(&gatewayv1beta1.ReferenceGrant{}, handler.EnqueueRequestsFromMapFunc(enqueueAllHTTPRoutes(r.Client, r.WatchNamespace))).
		Watches(&corev1.Namespace{}, handler.EnqueueRequestsFromMapFunc(r.enqueueRoutesForNamespace()), builder.WithPredicates(predicate.LabelChangedPredicate{})).
		Watches(&discoveryv1.EndpointSlice{}, handler.EnqueueRequestsFromMapFunc(enqueueAllHTTPRoutes(r.Client, r.WatchNamespace))).
		Watches(&gatewayv1alpha3.BackendTLSPolicy{}, handler.EnqueueRequestsFromMapFunc(enqueueAllHTTPRoutes(r.Client, r.WatchNamespace))).
		Complete(r)
}

type pendingRoute struct {
	route      *gatewayv1.HTTPRoute
	parentRefs []gatewayv1.ParentReference
	desired    translator.DesiredRoute
}

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

func (r *HTTPRouteReconciler) syncHTTPRouteStatus(
	ctx context.Context,
	route *gatewayv1.HTTPRoute,
	plan httpRouteStatusPlan,
) error {
	before := route.DeepCopy()
	r.mergeRouteParentStatuses(route, plan)
	if reflect.DeepEqual(before.Status, route.Status) {
		return nil
	}
	return r.Status().Patch(ctx, route, client.MergeFrom(before))
}

func (r *HTTPRouteReconciler) mergeRouteParentStatuses(
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

func failedTranslationPlan(route *gatewayv1.HTTPRoute, parentRefs []gatewayv1.ParentReference, err error) httpRouteStatusPlan {
	message := fmt.Sprintf("translation failed: %v", err)
	return httpRouteStatusPlan{
		route:      route,
		parentRefs: parentRefs,
		accepted: routeConditionState{
			status:  false,
			reason:  ngxorastatus.ReasonTranslationFailed,
			message: message,
		},
		resolved: routeConditionState{
			status:  false,
			reason:  ngxorastatus.ReasonTranslationFailed,
			message: message,
		},
		programmed: routeConditionState{
			status:  false,
			reason:  ngxorastatus.ReasonPending,
			message: "route was not included in the active snapshot",
		},
	}
}

func unresolvedRefsPlan(route *gatewayv1.HTTPRoute, parentRefs []gatewayv1.ParentReference, err error) httpRouteStatusPlan {
	reason := string(gatewayv1.RouteReasonBackendNotFound)
	if apierrors.IsForbidden(err) {
		reason = string(gatewayv1.RouteReasonRefNotPermitted)
	}

	message := fmt.Sprintf("backend resolution failed: %v", err)
	return httpRouteStatusPlan{
		route:      route,
		parentRefs: parentRefs,
		accepted: routeConditionState{
			status:  true,
			reason:  string(gatewayv1.RouteReasonAccepted),
			message: "route attached to target Gateway",
		},
		resolved: routeConditionState{
			status:  false,
			reason:  reason,
			message: message,
		},
		programmed: routeConditionState{
			status:  false,
			reason:  ngxorastatus.ReasonPending,
			message: "route was not included in the active snapshot",
		},
	}
}

func invalidFilterPlan(route *gatewayv1.HTTPRoute, parentRefs []gatewayv1.ParentReference, err error) httpRouteStatusPlan {
	message := fmt.Sprintf("filter resolution failed: %v", err)
	return httpRouteStatusPlan{
		route:      route,
		parentRefs: parentRefs,
		accepted: routeConditionState{
			status:  true,
			reason:  string(gatewayv1.RouteReasonAccepted),
			message: "route attached to target Gateway",
		},
		resolved: routeConditionState{
			status:  false,
			reason:  string(gatewayv1.RouteReasonUnsupportedValue),
			message: message,
		},
		programmed: routeConditionState{
			status:  false,
			reason:  ngxorastatus.ReasonPending,
			message: "route was not included in the active snapshot",
		},
	}
}

func acceptedPendingPlan(route *gatewayv1.HTTPRoute, parentRefs []gatewayv1.ParentReference) httpRouteStatusPlan {
	return httpRouteStatusPlan{
		route:      route,
		parentRefs: parentRefs,
		accepted: routeConditionState{
			status:  true,
			reason:  string(gatewayv1.RouteReasonAccepted),
			message: "route attached to target Gateway",
		},
		resolved: routeConditionState{
			status:  true,
			reason:  string(gatewayv1.RouteReasonResolvedRefs),
			message: "all backendRefs were resolved to Services",
		},
		programmed: routeConditionState{
			status:  false,
			reason:  ngxorastatus.ReasonPending,
			message: "waiting for dataplane snapshot apply",
		},
	}
}

func (r *HTTPRouteReconciler) unattachedPlan(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	route *gatewayv1.HTTPRoute,
	parentRefs []gatewayv1.ParentReference,
	namespaceLabelsCache map[string]map[string]string,
	listenerEvaluations map[string]gatewayListenerEvaluation,
) httpRouteStatusPlan {
	reason := string(gatewayv1.RouteReasonNotAllowedByListeners)
	message := "route was not allowed by any selected Gateway listener"

	classifiedReason, classifiedMessage, err := r.classifyUnattachedRoute(
		ctx,
		gateway,
		route,
		parentRefs,
		namespaceLabelsCache,
		listenerEvaluations,
	)
	if err == nil {
		reason = classifiedReason
		message = classifiedMessage
	}

	return httpRouteStatusPlan{
		route:      route,
		parentRefs: parentRefs,
		accepted: routeConditionState{
			status:  false,
			reason:  reason,
			message: message,
		},
		resolved: routeConditionState{
			status:  true,
			reason:  string(gatewayv1.RouteReasonResolvedRefs),
			message: "all backendRefs were resolved to Services",
		},
		programmed: routeConditionState{
			status:  false,
			reason:  ngxorastatus.ReasonPending,
			message: "route was not included in the active snapshot",
		},
	}
}

func (r *HTTPRouteReconciler) markProgrammed(plans []httpRouteStatusPlan, programmed bool, reason, message string) {
	for i := range plans {
		if plans[i].clear || !plans[i].accepted.status || !plans[i].resolved.status {
			continue
		}

		if reason == "" {
			reason = ngxorastatus.ReasonApplyFailed
			if programmed {
				reason = ngxorastatus.ReasonProgrammed
			}
		}
		plans[i].programmed = routeConditionState{
			status:  programmed,
			reason:  reason,
			message: message,
		}
	}
}

func (r *HTTPRouteReconciler) applyStatusPlans(ctx context.Context, plans []httpRouteStatusPlan) error {
	for _, plan := range plans {
		if err := r.syncHTTPRouteStatus(ctx, plan.route, plan); err != nil {
			return fmt.Errorf("patch %s/%s status: %w", plan.route.Namespace, plan.route.Name, err)
		}
	}
	return nil
}

func (r *HTTPRouteReconciler) classifyUnattachedRoute(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	route *gatewayv1.HTTPRoute,
	parentRefs []gatewayv1.ParentReference,
	namespaceLabelsCache map[string]map[string]string,
	listenerEvaluations map[string]gatewayListenerEvaluation,
) (string, string, error) {
	namespaceLabels, err := r.getNamespaceLabels(ctx, route.Namespace, namespaceLabelsCache)
	if err != nil {
		return "", "", err
	}

	hasSelected := false
	hasAllowed := false
	hasHostnameMatch := false

	routeHostnames := make([]string, 0, len(route.Spec.Hostnames))
	for _, hostname := range route.Spec.Hostnames {
		routeHostnames = append(routeHostnames, string(hostname))
	}

	for _, listener := range gateway.Spec.Listeners {
		if !attachment.ListenerSelectedByParentRefs(listener, parentRefs) {
			continue
		}
		hasSelected = true

		evaluation, ok := listenerEvaluations[string(listener.Name)]
		if !ok || !evaluation.accepted.status || !evaluation.resolved.status {
			continue
		}

		allowed, err := attachment.ListenerAllowsHTTPRoute(listener, gateway.Namespace, route.Namespace, namespaceLabels)
		if err != nil {
			return "", "", err
		}
		if !allowed {
			continue
		}
		hasAllowed = true

		if len(attachment.EffectiveServerNames(routeHostnames, listener.Hostname)) > 0 {
			hasHostnameMatch = true
		}
	}

	if !hasSelected || !hasAllowed {
		return string(gatewayv1.RouteReasonNotAllowedByListeners), "route was not allowed by any selected Gateway listener", nil
	}
	if !hasHostnameMatch {
		return string(gatewayv1.RouteReasonNoMatchingListenerHostname), "route did not match the hostname constraints of any selected Gateway listener", nil
	}

	return string(gatewayv1.RouteReasonNotAllowedByListeners), "route was selected but could not be attached to any listener", nil
}

func (r *HTTPRouteReconciler) resolveBackendRefs(
	ctx context.Context,
	routeNamespace string,
	desiredRoute *translator.DesiredRoute,
	cache map[types.NamespacedName]*corev1.Service,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) error {
	for i := range desiredRoute.Rules {
		rule := &desiredRoute.Rules[i]
		if len(rule.Backends) == 0 {
			return fmt.Errorf("rule has no backendRefs")
		}

		for j := range rule.Backends {
			backend := &rule.Backends[j]
			if backend.Group != "" || backend.Kind != "Service" {
				return fmt.Errorf(
					"unsupported backendRef %s/%s: only core Service backends are supported, got group=%q kind=%q",
					backend.Namespace,
					backend.Name,
					backend.Group,
					backend.Kind,
				)
			}

			if backend.Namespace != routeNamespace {
				allowed, err := r.referenceGrantAllows(ctx, routeNamespace, *backend, referenceGrantCache)
				if err != nil {
					return err
				}
				if !allowed {
					return apierrors.NewForbidden(
						corev1.Resource("services"),
						backend.Name,
						fmt.Errorf("cross-namespace backendRef %s/%s is not permitted by any ReferenceGrant", backend.Namespace, backend.Name),
					)
				}
			}

			key := types.NamespacedName{
				Namespace: backend.Namespace,
				Name:      backend.Name,
			}

			service, ok := cache[key]
			if !ok {
				service = &corev1.Service{}
				if err := r.Get(ctx, key, service); err != nil {
					return fmt.Errorf("resolve backend service %s/%s: %w", key.Namespace, key.Name, err)
				}
				cache[key] = service
			}

			svcPort := findServicePort(service, backend.Port)
			if svcPort == nil {
				return fmt.Errorf("service %s/%s does not expose port %d", key.Namespace, key.Name, backend.Port)
			}

			backend.BackendProtocol = gatewayv1.HTTPProtocolType
			if svcPort.AppProtocol != nil && *svcPort.AppProtocol != "" {
				backend.BackendProtocol = gatewayv1.ProtocolType(*svcPort.AppProtocol)
			}

			var backendTlsPolicies gatewayv1alpha3.BackendTLSPolicyList
			if err := r.List(ctx, &backendTlsPolicies, client.InNamespace(backend.Namespace)); err != nil {
				return fmt.Errorf("list BackendTLSPolicy for service %s/%s: %w", backend.Namespace, backend.Name, err)
			}

			var activePolicy *gatewayv1alpha3.BackendTLSPolicy
			for i := range backendTlsPolicies.Items {
				policy := &backendTlsPolicies.Items[i]
				for _, ref := range policy.Spec.TargetRefs {
					if string(ref.Kind) == "Service" && (string(ref.Group) == "core" || string(ref.Group) == "") && string(ref.Name) == backend.Name {
						activePolicy = policy
						break
					}
				}
				if activePolicy != nil {
					break
				}
			}

			if activePolicy != nil {
				v := true
				backend.TLSVerify = &v
				if len(activePolicy.Spec.Validation.CACertificateRefs) > 0 {
					cmRef := activePolicy.Spec.Validation.CACertificateRefs[0]
					if string(cmRef.Kind) == "" || string(cmRef.Kind) == "ConfigMap" {
						cmKey := client.ObjectKey{Namespace: backend.Namespace, Name: string(cmRef.Name)}
						var caMap corev1.ConfigMap
						if err := r.Get(ctx, cmKey, &caMap); err != nil {
							return fmt.Errorf("failed to get ConfigMap %s for BackendTLSPolicy %s: %w", cmRef.Name, activePolicy.Name, err)
						}
						if certDetails, ok := caMap.Data["ca.crt"]; ok {
							backend.TLSTrustedCertPEM = certDetails
						} else {
							return fmt.Errorf("ConfigMap %s does not contain 'ca.crt' key required by BackendTLSPolicy %s", cmRef.Name, activePolicy.Name)
						}
					}
				}
			}

			if service.Spec.Type != corev1.ServiceTypeExternalName {
				var slices discoveryv1.EndpointSliceList
				if err := r.List(ctx, &slices, client.InNamespace(backend.Namespace), client.MatchingLabels{
					"kubernetes.io/service-name": backend.Name,
				}); err != nil {
					return fmt.Errorf("list EndpointSlices for %s/%s: %w", backend.Namespace, backend.Name, err)
				}

				for _, slice := range slices.Items {
					var targetPort int32 = backend.Port
					var targetProtocol gatewayv1.ProtocolType = gatewayv1.HTTPProtocolType
					for _, p := range slice.Ports {
						nameMatches := (p.Name == nil && svcPort.Name == "") || (p.Name != nil && *p.Name == svcPort.Name)
						if nameMatches && p.Port != nil {
							targetPort = *p.Port
							if p.AppProtocol != nil && *p.AppProtocol != "" {
								targetProtocol = gatewayv1.ProtocolType(*p.AppProtocol)
							}
							break
						}
					}

					for _, ep := range slice.Endpoints {
						if ep.Conditions.Ready != nil && !*ep.Conditions.Ready {
							continue
						}
						for _, ip := range ep.Addresses {
							backend.Endpoints = append(backend.Endpoints, translator.DesiredBackendEndpoint{
								IP:              ip,
								Port:            targetPort,
								BackendProtocol: targetProtocol,
							})
						}
					}
				}

				if len(backend.Endpoints) == 0 {
					return fmt.Errorf("service %s/%s has no ready endpoints for port %d", backend.Namespace, backend.Name, backend.Port)
				}
			}
		}

		var ruleProtocol string
		var ruleTLSVerify *bool
		var ruleTLSCertPEM *string

		for j := range rule.Backends {
			backend := &rule.Backends[j]
			p := "http"
			if backend.BackendProtocol == gatewayv1.HTTPSProtocolType || backend.BackendProtocol == gatewayv1.TLSProtocolType {
				p = "https"
			}
			for _, endp := range backend.Endpoints {
				if endp.BackendProtocol == gatewayv1.HTTPSProtocolType || endp.BackendProtocol == gatewayv1.TLSProtocolType {
					p = "https"
					break
				}
			}

			if ruleProtocol == "" {
				ruleProtocol = p
			} else if ruleProtocol != p {
				return fmt.Errorf("HTTPRouteRule contains mixed backend protocols (e.g. %s and %s) which is not supported for a single rule", ruleProtocol, p)
			}

			if ruleTLSVerify == nil {
				if backend.TLSVerify != nil {
					v := *backend.TLSVerify
					ruleTLSVerify = &v
				}
			} else if backend.TLSVerify != nil && *ruleTLSVerify != *backend.TLSVerify {
				return fmt.Errorf("HTTPRouteRule contains mixed TLS verify settings which is not supported for a single rule")
			}

			if ruleTLSCertPEM == nil {
				if backend.TLSTrustedCertPEM != "" {
					certPEM := backend.TLSTrustedCertPEM
					ruleTLSCertPEM = &certPEM
				}
			} else if backend.TLSTrustedCertPEM != "" && *ruleTLSCertPEM != backend.TLSTrustedCertPEM {
				return fmt.Errorf("HTTPRouteRule contains mixed TLS trusted certificate config which is not supported for a single rule")
			}
		}
	}

	return nil
}

func (r *HTTPRouteReconciler) resolveFilters(
	ctx context.Context,
	routeNamespace string,
	desiredRoute *translator.DesiredRoute,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) error {
	for i := range desiredRoute.Rules {
		rule := &desiredRoute.Rules[i]
		for j := range rule.Filters {
			filter := &rule.Filters[j]
			if filter.Type == string(gatewayv1.HTTPRouteFilterExtensionRef) && filter.ExtensionRef != nil {
				if err := r.resolveExtensionRef(ctx, routeNamespace, filter, referenceGrantCache); err != nil {
					return fmt.Errorf("resolve filter ExtensionRef: %w", err)
				}
			}
		}
	}
	return nil
}

func (r *HTTPRouteReconciler) resolveExtensionRef(
	ctx context.Context,
	routeNamespace string,
	filter *translator.DesiredFilter,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) error {
	extRef := filter.ExtensionRef
	group := string(extRef.Group)
	kind := string(extRef.Kind)
	name := string(extRef.Name)

	if group != "plugins.ngxora.io" {
		return fmt.Errorf("unsupported ExtensionRef group %q", group)
	}

	targetNamespace := routeNamespace

	key := client.ObjectKey{Namespace: targetNamespace, Name: name}
	var pluginName string
	var jsonConfig []byte
	var err error

	switch kind {
	case "RateLimitPolicy":
		var policy v1alpha1.RateLimitPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			return err
		}
		pluginName = "rate-limit"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "JwtAuthPolicy":
		var policy v1alpha1.JwtAuthPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			return err
		}
		pluginName = "jwt_auth"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "BasicAuthPolicy":
		var policy v1alpha1.BasicAuthPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			return err
		}
		pluginName = "basic-auth"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "CorsPolicy":
		var policy v1alpha1.CorsPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			return err
		}
		pluginName = "cors"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "ExtAuthzPolicy":
		var policy v1alpha1.ExtAuthzPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			return err
		}
		pluginName = "ext_authz"
		jsonConfig, err = json.Marshal(policy.Spec)
	default:
		return fmt.Errorf("unsupported ExtensionRef kind %q", kind)
	}

	if err != nil {
		return fmt.Errorf("marshal %s spec: %w", kind, err)
	}

	filter.PluginName = pluginName
	filter.PluginConfig = string(jsonConfig)
	return nil
}

func (r *HTTPRouteReconciler) referenceGrantAllows(
	ctx context.Context,
	fromNamespace string,
	backend translator.DesiredBackend,
	cache map[string][]gatewayv1beta1.ReferenceGrant,
) (bool, error) {
	grants, ok := cache[backend.Namespace]
	if !ok {
		var grantList gatewayv1beta1.ReferenceGrantList
		if err := r.List(ctx, &grantList, client.InNamespace(backend.Namespace)); err != nil {
			return false, fmt.Errorf("list ReferenceGrants in namespace %s: %w", backend.Namespace, err)
		}
		grants = grantList.Items
		cache[backend.Namespace] = grants
	}

	for _, grant := range grants {
		if referenceGrantMatches(grant, fromNamespace, backend) {
			return true, nil
		}
	}

	return false, nil
}

func referenceGrantMatches(grant gatewayv1beta1.ReferenceGrant, fromNamespace string, backend translator.DesiredBackend) bool {
	matchedFrom := false
	for _, from := range grant.Spec.From {
		if string(from.Group) != string(gatewayv1.GroupName) {
			continue
		}
		if string(from.Kind) != "HTTPRoute" {
			continue
		}
		if string(from.Namespace) != fromNamespace {
			continue
		}
		matchedFrom = true
		break
	}
	if !matchedFrom {
		return false
	}

	for _, to := range grant.Spec.To {
		if string(to.Group) != backend.Group {
			continue
		}
		if string(to.Kind) != backend.Kind {
			continue
		}
		if to.Name != nil && string(*to.Name) != backend.Name {
			continue
		}
		return true
	}

	return false
}

func (r *HTTPRouteReconciler) evaluateGatewayListeners(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	secretCache map[types.NamespacedName]*corev1.Secret,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) (map[string]gatewayListenerEvaluation, error) {
	evaluations := make(map[string]gatewayListenerEvaluation, len(gateway.Spec.Listeners))

	for _, listener := range gateway.Spec.Listeners {
		evaluation := gatewayListenerEvaluation{
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

		switch listener.Protocol {
		case gatewayv1.HTTPProtocolType:
			evaluation.accepted = routeConditionState{
				status:  true,
				reason:  string(gatewayv1.ListenerReasonAccepted),
				message: "listener is accepted by ngxora",
			}
		case gatewayv1.HTTPSProtocolType:
			evaluation.accepted = routeConditionState{
				status:  true,
				reason:  string(gatewayv1.ListenerReasonAccepted),
				message: "listener is accepted by ngxora",
			}

			mode := gatewayv1.TLSModeTerminate
			if listener.TLS != nil && listener.TLS.Mode != nil {
				mode = *listener.TLS.Mode
			}
			if mode != gatewayv1.TLSModeTerminate {
				evaluation.accepted = routeConditionState{
					status:  false,
					reason:  string(gatewayv1.ListenerReasonUnsupportedProtocol),
					message: fmt.Sprintf("listener TLS mode %q is not supported by ngxora; only Terminate is supported", mode),
				}
			} else {
				binding, resolved := r.resolveListenerTLSBinding(
					ctx,
					gateway.Namespace,
					listener,
					secretCache,
					referenceGrantCache,
				)
				evaluation.tls = binding
				evaluation.resolved = resolved
			}
		}

		if evaluation.accepted.status && !attachment.ListenerHasOnlySupportedRouteKinds(listener) {
			evaluation.resolved = routeConditionState{
				status:  false,
				reason:  string(gatewayv1.ListenerReasonInvalidRouteKinds),
				message: "listener allowedRoutes.kinds contains route kinds not supported by ngxora",
			}
		}

		evaluations[string(listener.Name)] = evaluation
	}

	return evaluations, nil
}

func (r *HTTPRouteReconciler) resolveListenerTLSBinding(
	ctx context.Context,
	gatewayNamespace string,
	listener gatewayv1.Listener,
	secretCache map[types.NamespacedName]*corev1.Secret,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) (*controlv1.TlsBinding, routeConditionState) {
	if listener.TLS == nil {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: "HTTPS listener requires tls.certificateRefs",
		}
	}
	if len(listener.TLS.CertificateRefs) == 0 {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: "HTTPS listener requires at least one certificateRef",
		}
	}
	if len(listener.TLS.CertificateRefs) > 1 {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: "multiple certificateRefs are not supported by ngxora yet",
		}
	}

	ref := listener.TLS.CertificateRefs[0]
	group := ""
	if ref.Group != nil {
		group = string(*ref.Group)
	}
	kind := "Secret"
	if ref.Kind != nil {
		kind = string(*ref.Kind)
	}
	if group != "" || kind != "Secret" {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf("listener certificateRef %q must point to a core Secret", ref.Name),
		}
	}

	secretNamespace := gatewayNamespace
	if ref.Namespace != nil {
		secretNamespace = string(*ref.Namespace)
	}
	if secretNamespace != gatewayNamespace {
		allowed, err := r.certificateReferenceGrantAllows(
			ctx,
			gatewayNamespace,
			secretNamespace,
			string(ref.Name),
			referenceGrantCache,
		)
		if err != nil {
			return nil, routeConditionState{
				status:  false,
				reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
				message: err.Error(),
			}
		}
		if !allowed {
			return nil, routeConditionState{
				status: false,
				reason: string(gatewayv1.ListenerReasonRefNotPermitted),
				message: fmt.Sprintf(
					"cross-namespace certificateRef %s/%s is not permitted by any ReferenceGrant",
					secretNamespace,
					ref.Name,
				),
			}
		}
	}

	secretKey := types.NamespacedName{Namespace: secretNamespace, Name: string(ref.Name)}
	secret, ok := secretCache[secretKey]
	if !ok {
		secret = &corev1.Secret{}
		if err := r.Get(ctx, secretKey, secret); err != nil {
			return nil, routeConditionState{
				status:  false,
				reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
				message: fmt.Sprintf("resolve TLS Secret %s/%s: %v", secretKey.Namespace, secretKey.Name, err),
			}
		}
		secretCache[secretKey] = secret
	}

	certPEM := secret.Data[corev1.TLSCertKey]
	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, routeConditionState{
			status: false,
			reason: string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf(
				"TLS Secret %s/%s must contain %q and %q data keys",
				secretKey.Namespace,
				secretKey.Name,
				corev1.TLSCertKey,
				corev1.TLSPrivateKeyKey,
			),
		}
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, routeConditionState{
			status: false,
			reason: string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf(
				"TLS Secret %s/%s has invalid type %q; must be %q",
				secretKey.Namespace,
				secretKey.Name,
				secret.Type,
				corev1.SecretTypeTLS,
			),
		}
	}

	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, routeConditionState{
			status: false,
			reason: string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf(
				"TLS Secret %s/%s contains invalid certificate or private key: %v",
				secretKey.Namespace,
				secretKey.Name,
				err,
			),
		}
	}

	if len(keyPair.Certificate) > 0 {
		cert, err := x509.ParseCertificate(keyPair.Certificate[0])
		if err == nil {
			now := time.Now()
			if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
				return nil, routeConditionState{
					status:  false,
					reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
					message: fmt.Sprintf("TLS certificate in Secret %s/%s is expired or not yet valid", secretKey.Namespace, secretKey.Name),
				}
			}

			if listener.Hostname != nil {
				if err := cert.VerifyHostname(string(*listener.Hostname)); err != nil {
					return nil, routeConditionState{
						status:  false,
						reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
						message: fmt.Sprintf("TLS certificate in Secret %s/%s is not valid for listener hostname %q: %v", secretKey.Namespace, secretKey.Name, *listener.Hostname, err),
					}
				}
			}
		}
	}

	return &controlv1.TlsBinding{
			Cert: &controlv1.PemSource{
				Source: &controlv1.PemSource_InlinePem{InlinePem: string(certPEM)},
			},
			Key: &controlv1.PemSource{
				Source: &controlv1.PemSource_InlinePem{InlinePem: string(keyPEM)},
			},
		}, routeConditionState{
			status:  true,
			reason:  string(gatewayv1.ListenerReasonResolvedRefs),
			message: "listener TLS certificateRefs are resolved",
		}
}

func (r *HTTPRouteReconciler) certificateReferenceGrantAllows(
	ctx context.Context,
	fromNamespace string,
	secretNamespace string,
	secretName string,
	cache map[string][]gatewayv1beta1.ReferenceGrant,
) (bool, error) {
	grants, ok := cache[secretNamespace]
	if !ok {
		var grantList gatewayv1beta1.ReferenceGrantList
		if err := r.List(ctx, &grantList, client.InNamespace(secretNamespace)); err != nil {
			return false, fmt.Errorf("list ReferenceGrants in namespace %s: %w", secretNamespace, err)
		}
		grants = grantList.Items
		cache[secretNamespace] = grants
	}

	for _, grant := range grants {
		if certificateReferenceGrantMatches(grant, fromNamespace, secretName) {
			return true, nil
		}
	}

	return false, nil
}

func certificateReferenceGrantMatches(
	grant gatewayv1beta1.ReferenceGrant,
	fromNamespace string,
	secretName string,
) bool {
	matchedFrom := false
	for _, from := range grant.Spec.From {
		if string(from.Group) != string(gatewayv1.GroupName) {
			continue
		}
		if string(from.Kind) != "Gateway" {
			continue
		}
		if string(from.Namespace) != fromNamespace {
			continue
		}
		matchedFrom = true
		break
	}
	if !matchedFrom {
		return false
	}

	for _, to := range grant.Spec.To {
		if string(to.Group) != "" {
			continue
		}
		if string(to.Kind) != "Secret" {
			continue
		}
		if to.Name != nil && string(*to.Name) != secretName {
			continue
		}
		return true
	}

	return false
}

func listenerTLSBindings(
	evaluations map[string]gatewayListenerEvaluation,
) map[string]*controlv1.TlsBinding {
	bindings := make(map[string]*controlv1.TlsBinding, len(evaluations))
	for name, evaluation := range evaluations {
		if !evaluation.accepted.status {
			continue
		}
		if evaluation.tls == nil {
			continue
		}
		bindings[name] = evaluation.tls
	}
	return bindings
}

func listenerUsableForRoutes(
	evaluations map[string]gatewayListenerEvaluation,
) map[string]bool {
	usable := make(map[string]bool, len(evaluations))
	for name, evaluation := range evaluations {
		usable[name] = evaluation.accepted.status && evaluation.resolved.status
	}
	return usable
}

func findServicePort(service *corev1.Service, port int32) *corev1.ServicePort {
	for _, servicePort := range service.Spec.Ports {
		if servicePort.Port == port {
			return &servicePort
		}
	}
	return nil
}

func (r *HTTPRouteReconciler) getTargetGateway(ctx context.Context) (*gatewayv1.Gateway, error) {
	key := types.NamespacedName{
		Namespace: r.GatewayNamespace,
		Name:      r.GatewayName,
	}

	gateway := &gatewayv1.Gateway{}
	if err := r.Get(ctx, key, gateway); err != nil {
		return nil, err
	}

	return gateway, nil
}

func (r *HTTPRouteReconciler) gatewayListenerAttachedRoutes(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	routes []gatewayv1.HTTPRoute,
	namespaceLabelsCache map[string]map[string]string,
	listenerEvaluations map[string]gatewayListenerEvaluation,
) (map[string]int32, error) {
	attached := make(map[string]int32, len(gateway.Spec.Listeners))
	for _, route := range routes {
		parentRefs := r.Translator.MatchingParentRefs(route)
		if len(parentRefs) == 0 {
			continue
		}

		namespaceLabels, err := r.getNamespaceLabels(ctx, route.Namespace, namespaceLabelsCache)
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

func (r *HTTPRouteReconciler) syncGatewayStatus(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	attachedRoutes map[string]int32,
	listenerEvaluations map[string]gatewayListenerEvaluation,
	programmed bool,
	programmedReason string,
	programmedMessage string,
) error {
	before := gateway.DeepCopy()
	gateway.Status.Addresses = r.gatewayStatusAddresses(gateway)

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
			meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
				gateway.Generation,
				string(gatewayv1.ListenerConditionAccepted),
				evaluation.accepted.status,
				evaluation.accepted.reason,
				evaluation.accepted.message,
			))
			meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
				gateway.Generation,
				string(gatewayv1.ListenerConditionResolvedRefs),
				evaluation.resolved.status,
				evaluation.resolved.reason,
				evaluation.resolved.message,
			))
			meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
				gateway.Generation,
				string(gatewayv1.ListenerConditionProgrammed),
				evaluation.resolved.status && programmed,
				gatewayListenerProgrammedReason(evaluation, programmed, programmedReason),
				gatewayListenerProgrammedMessage(evaluation, programmed, programmedMessage),
			))
		} else {
			invalidListeners++
			meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
				gateway.Generation,
				string(gatewayv1.ListenerConditionAccepted),
				evaluation.accepted.status,
				evaluation.accepted.reason,
				evaluation.accepted.message,
			))
			meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
				gateway.Generation,
				string(gatewayv1.ListenerConditionResolvedRefs),
				evaluation.resolved.status,
				evaluation.resolved.reason,
				evaluation.resolved.message,
			))
			meta.SetStatusCondition(&listenerStatus.Conditions, routeCondition(
				gateway.Generation,
				string(gatewayv1.ListenerConditionProgrammed),
				false,
				gatewayListenerProgrammedReason(evaluation, programmed, programmedReason),
				gatewayListenerProgrammedMessage(evaluation, programmed, programmedMessage),
			))
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
	return r.Status().Patch(ctx, gateway, client.MergeFrom(before))
}

func isSupportedGatewayListener(listener gatewayv1.Listener) bool {
	return listener.Protocol == gatewayv1.HTTPProtocolType || listener.Protocol == gatewayv1.HTTPSProtocolType
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

func (r *HTTPRouteReconciler) gatewayStatusAddresses(gateway *gatewayv1.Gateway) []gatewayv1.GatewayStatusAddress {
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

func (r *HTTPRouteReconciler) getNamespaceLabels(
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
	if err := r.Get(ctx, types.NamespacedName{Name: namespace}, ns); err != nil {
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

func routeKey(route translator.DesiredRoute) string {
	return route.Namespace + "/" + route.Name
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

func (r *HTTPRouteReconciler) enqueueRoutesForSecret() handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		secret, ok := obj.(*corev1.Secret)
		if !ok {
			return nil
		}

		gateway := &gatewayv1.Gateway{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: r.GatewayNamespace, Name: r.GatewayName}, gateway); err != nil {
			return nil
		}

		used := false
		for _, listener := range gateway.Spec.Listeners {
			if listener.TLS == nil {
				continue
			}
			for _, ref := range listener.TLS.CertificateRefs {
				ns := gateway.Namespace
				if ref.Namespace != nil {
					ns = string(*ref.Namespace)
				}
				if string(ref.Name) == secret.Name && ns == secret.Namespace {
					used = true
					break
				}
			}
			if used {
				break
			}
		}

		if !used {
			return nil
		}

		return enqueueAllHTTPRoutes(r.Client, r.WatchNamespace)(ctx, obj)
	}
}

func (r *HTTPRouteReconciler) enqueueRoutesForNamespace() handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		_, ok := obj.(*corev1.Namespace)
		if !ok {
			return nil
		}

		gateway := &gatewayv1.Gateway{}
		if err := r.Get(ctx, types.NamespacedName{Namespace: r.GatewayNamespace, Name: r.GatewayName}, gateway); err != nil {
			return nil
		}

		used := false
		for _, listener := range gateway.Spec.Listeners {
			if listener.AllowedRoutes != nil && listener.AllowedRoutes.Namespaces != nil && listener.AllowedRoutes.Namespaces.From != nil {
				if *listener.AllowedRoutes.Namespaces.From == gatewayv1.NamespacesFromSelector {
					used = true
					break
				}
			}
		}

		// Also check WatchNamespace logic (global route enqueue)
		// If the namespace itself is exactly the watched namespace used by the reconciler,
		// we might want to watch it, but if it has no selector listeners, routes aren't dynamically attached by labels.
		// However, returning all routes upon namespace label change is safest if used is true.
		if !used {
			return nil
		}

		return enqueueAllHTTPRoutes(r.Client, r.WatchNamespace)(ctx, obj)
	}
}
