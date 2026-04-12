package controller

import (
	"log/slog"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"

	"github.com/paramoshka/ngxora/control-plane/api/v1alpha1"
	ngxoraclient "github.com/paramoshka/ngxora/control-plane/internal/client"
	"github.com/paramoshka/ngxora/control-plane/internal/config"
	"github.com/paramoshka/ngxora/control-plane/internal/snapshot"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
)

// NewManager builds the controller-runtime manager and installs the HTTPRoute
// reconciler for one target Gateway.
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
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		return nil, err
	}

	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{Scheme: scheme})
	if err != nil {
		return nil, err
	}

	c := mgr.GetClient()

	reconciler := &HTTPRouteReconciler{
		Client:           c,
		Logger:           logger.With("controller", "httproute"),
		WatchNamespace:   cfg.WatchNamespace,
		GatewayName:      cfg.GatewayName,
		GatewayNamespace: cfg.GatewayNamespace,
		Translator:       translator.New(cfg.GatewayName, cfg.GatewayNamespace),
		SnapshotBuilder:  snapshot.NewBuilder(),
		NGXoraClient:     ngxoraclient.New(cfg.SocketPath, cfg.ApplyTimeout),
		BackendResolver:  NewBackendResolver(c),
		FilterResolver:   NewFilterResolver(c),
		TLSValidator:     NewTLSValidator(c),
		StatusApplier:    NewStatusApplier(c),
	}

	if err := reconciler.SetupWithManager(mgr); err != nil {
		return nil, err
	}

	return mgr, nil
}
