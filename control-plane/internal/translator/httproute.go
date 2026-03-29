package translator

import (
	"fmt"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

type DesiredState struct {
	Routes []DesiredRoute
}

type DesiredRoute struct {
	Name      string
	Namespace string
	Hostnames []string
	Rules     []DesiredRule
}

type DesiredRule struct {
	PathMatch DesiredPathMatch
	Backends  []DesiredBackend
	Filters   []DesiredFilter
}

type DesiredPathMatch struct {
	Kind  string
	Value string
}

type DesiredBackend struct {
	Name      string
	Namespace string
	Port      int32
	Weight    int32
}

type DesiredFilter struct {
	Type string
}

type Translator struct{}

func New() *Translator {
	return &Translator{}
}

func (t *Translator) TranslateHTTPRoutes(routes []gatewayv1.HTTPRoute) (*DesiredState, error) {
	state := &DesiredState{
		Routes: make([]DesiredRoute, 0, len(routes)),
	}

	for _, route := range routes {
		desired, err := t.translateHTTPRoute(route)
		if err != nil {
			return nil, err
		}
		state.Routes = append(state.Routes, desired)
	}

	return state, nil
}

func (t *Translator) translateHTTPRoute(route gatewayv1.HTTPRoute) (DesiredRoute, error) {
	desired := DesiredRoute{
		Name:      route.Name,
		Namespace: route.Namespace,
	}

	for _, hostname := range route.Spec.Hostnames {
		desired.Hostnames = append(desired.Hostnames, string(hostname))
	}

	for _, rule := range route.Spec.Rules {
		rules, err := t.translateRule(route.Namespace, rule)
		if err != nil {
			return DesiredRoute{}, err
		}
		desired.Rules = append(desired.Rules, rules...)
	}

	return desired, nil
}

func (t *Translator) translateRule(namespace string, rule gatewayv1.HTTPRouteRule) ([]DesiredRule, error) {
	matches := rule.Matches
	if len(matches) == 0 {
		matches = []gatewayv1.HTTPRouteMatch{{}}
	}

	result := make([]DesiredRule, 0, len(matches))
	for _, match := range matches {
		pathMatch, err := translatePathMatch(match)
		if err != nil {
			return nil, err
		}

		backends, err := translateBackendRefs(namespace, rule.BackendRefs)
		if err != nil {
			return nil, err
		}

		filters := make([]DesiredFilter, 0, len(rule.Filters))
		for _, filter := range rule.Filters {
			filters = append(filters, DesiredFilter{Type: string(filter.Type)})
		}

		result = append(result, DesiredRule{
			PathMatch: pathMatch,
			Backends:  backends,
			Filters:   filters,
		})
	}

	return result, nil
}

func translatePathMatch(match gatewayv1.HTTPRouteMatch) (DesiredPathMatch, error) {
	if match.Path == nil || match.Path.Value == nil {
		return DesiredPathMatch{
			Kind:  "PathPrefix",
			Value: "/",
		}, nil
	}

	kind := gatewayv1.PathMatchPathPrefix
	if match.Path.Type != nil {
		kind = *match.Path.Type
	}

	switch kind {
	case gatewayv1.PathMatchPathPrefix:
		return DesiredPathMatch{Kind: "PathPrefix", Value: string(*match.Path.Value)}, nil
	case gatewayv1.PathMatchExact:
		return DesiredPathMatch{Kind: "Exact", Value: string(*match.Path.Value)}, nil
	default:
		return DesiredPathMatch{}, fmt.Errorf("unsupported HTTPRoute path match type: %s", kind)
	}
}

func translateBackendRefs(defaultNamespace string, refs []gatewayv1.HTTPBackendRef) ([]DesiredBackend, error) {
	backends := make([]DesiredBackend, 0, len(refs))

	for _, ref := range refs {
		if ref.BackendRef.Port == nil {
			return nil, fmt.Errorf("backend ref %q is missing port", ref.BackendRef.Name)
		}

		namespace := defaultNamespace
		if ref.BackendRef.Namespace != nil {
			namespace = string(*ref.BackendRef.Namespace)
		}

		weight := int32(1)
		if ref.Weight != nil {
			weight = int32(*ref.Weight)
		}

		backends = append(backends, DesiredBackend{
			Name:      string(ref.BackendRef.Name),
			Namespace: namespace,
			Port:      int32(*ref.BackendRef.Port),
			Weight:    weight,
		})
	}

	return backends, nil
}
