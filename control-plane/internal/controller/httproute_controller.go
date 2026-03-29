package controller

import (
	"context"
	"fmt"
	"log/slog"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	ngxoraclient "github.com/paramoshka/ngxora/control-plane/internal/client"
	"github.com/paramoshka/ngxora/control-plane/internal/snapshot"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
)

type HTTPRouteReconciler struct {
	client.Client
	Logger          *slog.Logger
	WatchNamespace  string
	Translator      *translator.Translator
	SnapshotBuilder *snapshot.Builder
	NGXoraClient    *ngxoraclient.NGXoraClient
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

	desiredState, err := r.Translator.TranslateHTTPRoutes(routeList.Items)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("translate HTTPRoutes: %w", err)
	}

	compiledSnapshot, err := r.SnapshotBuilder.Build(desiredState)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("build snapshot: %w", err)
	}

	version, err := snapshot.StableVersion(compiledSnapshot)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("hash snapshot: %w", err)
	}
	compiledSnapshot.Version = version

	activeSnapshot, err := r.NGXoraClient.GetSnapshot(ctx)
	if err == nil && activeSnapshot != nil && activeSnapshot.Version == version {
		r.Logger.Info("snapshot unchanged, skipping apply", "version", version)
		return ctrl.Result{}, nil
	}

	result, err := r.NGXoraClient.ApplySnapshot(ctx, compiledSnapshot)
	if err != nil {
		return ctrl.Result{}, fmt.Errorf("apply snapshot: %w", err)
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
		Complete(r)
}
