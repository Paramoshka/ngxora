package controller

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/paramoshka/ngxora/control-plane/internal/attachment"
	ngxoraclient "github.com/paramoshka/ngxora/control-plane/internal/client"
	"github.com/paramoshka/ngxora/control-plane/internal/snapshot"
	ngxorastatus "github.com/paramoshka/ngxora/control-plane/internal/status"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/predicate"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha3 "sigs.k8s.io/gateway-api/apis/v1alpha3"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// SnapshotClient defines the interface for communicating with the dataplane.
type SnapshotClient interface {
	ApplySnapshot(ctx context.Context, snap *controlv1.ConfigSnapshot) (*controlv1.ApplyResult, error)
	GetSnapshot(ctx context.Context) (*controlv1.ConfigSnapshot, error)
}

// Ensure the real client implements the interface.
var _ SnapshotClient = (*ngxoraclient.NGXoraClient)(nil)

// HTTPRouteReconciler orchestrates the reconciliation of HTTPRoute objects
// by delegating to specialized services.
type HTTPRouteReconciler struct {
	client.Client
	Logger           *slog.Logger
	WatchNamespace   string
	GatewayName      string
	GatewayNamespace string
	Translator       *translator.Translator
	SnapshotBuilder  *snapshot.Builder
	NGXoraClient     SnapshotClient
	BackendResolver  *BackendResolver
	FilterResolver   *FilterResolver
	TLSValidator     *TLSValidator
	StatusApplier    *StatusApplier
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

	gateway, err := r.StatusApplier.GetTargetGateway(ctx, types.NamespacedName{
		Namespace: r.GatewayNamespace,
		Name:      r.GatewayName,
	})
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

	// Phase 1: Translate and resolve each route
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
		if _, err := r.StatusApplier.GetNamespaceLabels(ctx, route.Namespace, namespaceLabelsCache); err != nil {
			return ctrl.Result{}, fmt.Errorf("get namespace labels for %s: %w", route.Namespace, err)
		}

		if err := r.BackendResolver.ResolveBackendRefs(ctx, route.Namespace, &desiredRoute, serviceCache, referenceGrantCache); err != nil {
			statusPlans = append(statusPlans, unresolvedRefsPlan(route, parentRefs, err))
			r.Logger.Warn("skipping unresolved HTTPRoute backends", "name", route.Name, "namespace", route.Namespace, "error", err)
			continue
		}

		if err := r.FilterResolver.ResolveFilters(ctx, route.Namespace, &desiredRoute); err != nil {
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

	// Phase 2: Evaluate Gateway listeners
	listenerEvaluations, err := r.evaluateGatewayListeners(ctx, gateway, secretCache, referenceGrantCache)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("evaluate Gateway listeners: %w", err)
	}

	// Phase 3: Compute attached routes for status
	listenerAttachedRoutes, err := r.StatusApplier.ComputeListenerAttachedRoutes(
		ctx, gateway, routeList.Items, namespaceLabelsCache, listenerEvaluations, r.Translator,
	)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("compute Gateway attached routes: %w", err)
	}

	// Phase 4: Build snapshot
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
		if statusErr := r.StatusApplier.ApplyStatusPlans(ctx, statusPlans); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("build snapshot: %w; update route status: %v", err, statusErr)
		}
		if statusErr := r.StatusApplier.SyncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, false, ngxorastatus.ReasonTranslationFailed, err.Error()); statusErr != nil {
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

	// Phase 5: Version the snapshot
	version, err := snapshot.StableVersion(buildResult.Snapshot)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("hash snapshot: %w", err)
	}
	buildResult.Snapshot.Version = version

	// Phase 6: No-op optimization
	activeSnapshot, err := r.NGXoraClient.GetSnapshot(ctx)
	if err == nil && activeSnapshot != nil && activeSnapshot.Version == version {
		r.markProgrammed(statusPlans, true, ngxorastatus.ReasonProgrammed, "active snapshot already matches desired version")
		if err := r.StatusApplier.ApplyStatusPlans(ctx, statusPlans); err != nil {
			return ctrl.Result{}, fmt.Errorf("update HTTPRoute status after no-op apply: %w", err)
		}
		if err := r.StatusApplier.SyncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, true, ngxorastatus.ReasonProgrammed, "active snapshot already matches desired version"); err != nil {
			return ctrl.Result{}, fmt.Errorf("update Gateway status after no-op apply: %w", err)
		}
		r.Logger.Info("snapshot unchanged, skipping apply", "version", version)
		return ctrl.Result{}, nil
	}

	// Phase 7: Apply snapshot
	result, err := r.NGXoraClient.ApplySnapshot(ctx, buildResult.Snapshot)
	if err != nil {
		r.markProgrammed(statusPlans, false, ngxorastatus.ReasonApplyFailed, err.Error())
		if statusErr := r.StatusApplier.ApplyStatusPlans(ctx, statusPlans); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("apply snapshot: %w; update status: %v", err, statusErr)
		}
		if statusErr := r.StatusApplier.SyncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, false, ngxorastatus.ReasonApplyFailed, err.Error()); statusErr != nil {
			return ctrl.Result{}, fmt.Errorf("apply snapshot: %w; update gateway status: %v", err, statusErr)
		}
		return ctrl.Result{}, fmt.Errorf("apply snapshot: %w", err)
	}

	// Phase 8: Update status with apply result
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
	if err := r.StatusApplier.ApplyStatusPlans(ctx, statusPlans); err != nil {
		return ctrl.Result{}, fmt.Errorf("update HTTPRoute status after apply: %w", err)
	}
	if err := r.StatusApplier.SyncGatewayStatus(ctx, gateway, listenerAttachedRoutes, listenerEvaluations, programmed, programmedReason, programmedMessage); err != nil {
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
				binding, resolved := r.TLSValidator.ResolveListenerTLSBinding(
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

func (r *HTTPRouteReconciler) classifyUnattachedRoute(
	ctx context.Context,
	gateway *gatewayv1.Gateway,
	route *gatewayv1.HTTPRoute,
	parentRefs []gatewayv1.ParentReference,
	namespaceLabelsCache map[string]map[string]string,
	listenerEvaluations map[string]gatewayListenerEvaluation,
) (string, string, error) {
	namespaceLabels, err := r.StatusApplier.GetNamespaceLabels(ctx, route.Namespace, namespaceLabelsCache)
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

// Status plan constructors — pure functions that build status plans.

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
	reason := string(gatewayv1.RouteReasonUnsupportedValue)
	var filterErr *filterResolutionError
	if errors.As(err, &filterErr) && filterErr.reason != "" {
		reason = filterErr.reason
	}

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

func routeKey(route translator.DesiredRoute) string {
	return route.Namespace + "/" + route.Name
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

func enqueueAllHTTPRoutes(c client.Client, watchNamespace string) handler.MapFunc {
	return func(ctx context.Context, obj client.Object) []reconcile.Request {
		var routeList gatewayv1.HTTPRouteList
		listOpts := []client.ListOption{}
		if watchNamespace != "" {
			listOpts = append(listOpts, client.InNamespace(watchNamespace))
		}
		if err := c.List(ctx, &routeList, listOpts...); err != nil {
			return nil
		}

		requests := make([]reconcile.Request, 0, len(routeList.Items))
		for _, route := range routeList.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: types.NamespacedName{
					Namespace: route.Namespace,
					Name:      route.Name,
				},
			})
		}
		return requests
	}
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

		if !used {
			return nil
		}

		return enqueueAllHTTPRoutes(r.Client, r.WatchNamespace)(ctx, obj)
	}
}
