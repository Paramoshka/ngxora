package controller

import (
	"context"
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/handler"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	ngxoraclient "github.com/paramoshka/ngxora/control-plane/internal/client"
	"github.com/paramoshka/ngxora/control-plane/internal/config"
	"github.com/paramoshka/ngxora/control-plane/internal/snapshot"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
)

func NewManager(cfg config.Config, logger *slog.Logger) (manager.Manager, error) {
	scheme := runtime.NewScheme()
	if err := corev1.AddToScheme(scheme); err != nil {
		return nil, err
	}
	if err := gatewayv1.Install(scheme); err != nil {
		return nil, err
	}
	if err := gatewayv1beta1.Install(scheme); err != nil {
		return nil, err
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	reconciler := &HTTPRouteReconciler{
		Client:           mgr.GetClient(),
		Logger:           logger.With("controller", "httproute"),
		WatchNamespace:   cfg.WatchNamespace,
		GatewayName:      cfg.GatewayName,
		GatewayNamespace: cfg.GatewayNamespace,
		Translator:       translator.New(cfg.GatewayName, cfg.GatewayNamespace),
		SnapshotBuilder:  snapshot.NewBuilder(),
		NGXoraClient:     ngxoraclient.New(cfg.SocketPath, cfg.ApplyTimeout),
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	return mgr, nil
}

func enqueueAllHTTPRoutes(c client.Client, watchNamespace string) handler.MapFunc {
	return func(ctx context.Context, _ client.Object) []reconcile.Request {
		var routeList gatewayv1.HTTPRouteList
		if err := c.List(ctx, &routeList, client.InNamespace(watchNamespace)); err != nil {
			return nil
		}

		requests := make([]reconcile.Request, 0, len(routeList.Items))
		for _, route := range routeList.Items {
			requests = append(requests, reconcile.Request{
				NamespacedName: client.ObjectKeyFromObject(&route),
			})
		}
		return requests
	}
}
