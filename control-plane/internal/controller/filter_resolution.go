package controller

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/paramoshka/ngxora/control-plane/api/v1alpha1"
	ngxorastatus "github.com/paramoshka/ngxora/control-plane/internal/status"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// FilterResolver resolves ExtensionRef filters to plugin configurations.
type FilterResolver struct {
	client.Client
}

// NewFilterResolver creates a new FilterResolver.
func NewFilterResolver(c client.Client) *FilterResolver {
	return &FilterResolver{Client: c}
}

// ResolveFilters resolves all ExtensionRef filters in a route to their
// corresponding plugin CRD configurations.
func (r *FilterResolver) ResolveFilters(
	ctx context.Context,
	routeNamespace string,
	desiredRoute *translator.DesiredRoute,
) error {
	for i := range desiredRoute.Rules {
		rule := &desiredRoute.Rules[i]
		for j := range rule.Filters {
			filter := &rule.Filters[j]
			if filter.Type == string(gatewayv1.HTTPRouteFilterExtensionRef) && filter.ExtensionRef != nil {
				if err := r.resolveExtensionRef(ctx, routeNamespace, filter); err != nil {
					return fmt.Errorf("resolve filter ExtensionRef: %w", err)
				}
			}
		}
	}
	return nil
}

func (r *FilterResolver) resolveExtensionRef(
	ctx context.Context,
	routeNamespace string,
	filter *translator.DesiredFilter,
) error {
	extRef := filter.ExtensionRef
	group := string(extRef.Group)
	kind := string(extRef.Kind)
	name := string(extRef.Name)

	if group != "plugins.ngxora.io" {
		return newFilterResolutionError(
			ngxorastatus.ReasonInvalidExtensionRef,
			fmt.Errorf("unsupported ExtensionRef group %q", group),
		)
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
			if apierrors.IsNotFound(err) {
				return newFilterResolutionError(ngxorastatus.ReasonExtensionRefNotFound, err)
			}
			return err
		}
		pluginName = "rate-limit"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "JwtAuthPolicy":
		var policy v1alpha1.JwtAuthPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				return newFilterResolutionError(ngxorastatus.ReasonExtensionRefNotFound, err)
			}
			return err
		}
		pluginName = "jwt_auth"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "BasicAuthPolicy":
		var policy v1alpha1.BasicAuthPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				return newFilterResolutionError(ngxorastatus.ReasonExtensionRefNotFound, err)
			}
			return err
		}
		pluginName = "basic-auth"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "CorsPolicy":
		var policy v1alpha1.CorsPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				return newFilterResolutionError(ngxorastatus.ReasonExtensionRefNotFound, err)
			}
			return err
		}
		pluginName = "cors"
		jsonConfig, err = json.Marshal(policy.Spec)
	case "ExtAuthzPolicy":
		var policy v1alpha1.ExtAuthzPolicy
		if err = r.Get(ctx, key, &policy); err != nil {
			if apierrors.IsNotFound(err) {
				return newFilterResolutionError(ngxorastatus.ReasonExtensionRefNotFound, err)
			}
			return err
		}
		pluginName = "ext_authz"
		jsonConfig, err = json.Marshal(policy.Spec)
	default:
		return newFilterResolutionError(
			ngxorastatus.ReasonInvalidExtensionRef,
			fmt.Errorf("unsupported ExtensionRef kind %q", kind),
		)
	}

	if err != nil {
		return fmt.Errorf("marshal %s spec: %w", kind, err)
	}

	filter.PluginName = pluginName
	filter.PluginConfig = string(jsonConfig)
	return nil
}

// filterResolutionError wraps the reason string + underlying error, allowing
// the status layer to extract specific Gateway API reasons.
type filterResolutionError struct {
	reason string
	err    error
}

func (e *filterResolutionError) Error() string {
	return e.err.Error()
}

func (e *filterResolutionError) Unwrap() error {
	return e.err
}

func newFilterResolutionError(reason string, err error) error {
	return &filterResolutionError{
		reason: reason,
		err:    err,
	}
}
