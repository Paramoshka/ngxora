package controller

import (
	"context"
	"fmt"

	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	corev1 "k8s.io/api/core/v1"
	discoveryv1 "k8s.io/api/discovery/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1alpha3 "sigs.k8s.io/gateway-api/apis/v1alpha3"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// BackendResolver resolves backendRefs to actual Pod endpoints.
type BackendResolver struct {
	client.Client
}

// NewBackendResolver creates a new BackendResolver.
func NewBackendResolver(c client.Client) *BackendResolver {
	return &BackendResolver{Client: c}
}

// ResolveBackendRefs resolves all backend references in a route to actual
// Service endpoints, validating ports, protocols, and ReferenceGrants.
func (r *BackendResolver) ResolveBackendRefs(
	ctx context.Context,
	routeNamespace string,
	desiredRoute *translator.DesiredRoute,
	serviceCache map[types.NamespacedName]*corev1.Service,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) error {
	for i := range desiredRoute.Rules {
		rule := &desiredRoute.Rules[i]
		if len(rule.Backends) == 0 {
			return fmt.Errorf("rule has no backendRefs")
		}

		for j := range rule.Backends {
			backend := &rule.Backends[j]
			if err := r.resolveSingleBackend(ctx, routeNamespace, backend, serviceCache, referenceGrantCache); err != nil {
				return err
			}
		}

		if err := validateRuleConsistency(rule); err != nil {
			return err
		}
	}

	return nil
}

func (r *BackendResolver) resolveSingleBackend(
	ctx context.Context,
	routeNamespace string,
	backend *translator.DesiredBackend,
	serviceCache map[types.NamespacedName]*corev1.Service,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) error {
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

	service, ok := serviceCache[key]
	if !ok {
		service = &corev1.Service{}
		if err := r.Get(ctx, key, service); err != nil {
			return fmt.Errorf("resolve backend service %s/%s: %w", key.Namespace, key.Name, err)
		}
		serviceCache[key] = service
	}

	svcPort := findServicePort(service, backend.Port)
	if svcPort == nil {
		return fmt.Errorf("service %s/%s does not expose port %d", key.Namespace, key.Name, backend.Port)
	}

	backend.BackendProtocol = gatewayv1.HTTPProtocolType
	if svcPort.AppProtocol != nil && *svcPort.AppProtocol != "" {
		backend.BackendProtocol = gatewayv1.ProtocolType(*svcPort.AppProtocol)
	}

	if err := r.resolveBackendTLS(ctx, backend, service); err != nil {
		return err
	}

	if service.Spec.Type != corev1.ServiceTypeExternalName {
		if err := r.resolveEndpoints(ctx, backend, svcPort); err != nil {
			return err
		}
	}

	return nil
}

func (r *BackendResolver) resolveBackendTLS(
	ctx context.Context,
	backend *translator.DesiredBackend,
	service *corev1.Service,
) error {
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

	return nil
}

func (r *BackendResolver) resolveEndpoints(
	ctx context.Context,
	backend *translator.DesiredBackend,
	svcPort *corev1.ServicePort,
) error {
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

	return nil
}

func (r *BackendResolver) referenceGrantAllows(
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

func findServicePort(service *corev1.Service, port int32) *corev1.ServicePort {
	for _, servicePort := range service.Spec.Ports {
		if servicePort.Port == port {
			return &servicePort
		}
	}
	return nil
}

func validateRuleConsistency(rule *translator.DesiredRule) error {
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

	return nil
}
