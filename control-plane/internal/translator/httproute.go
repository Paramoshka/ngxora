package translator

import (
	"fmt"

	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

// DesiredState is the normalized output of translation before snapshot build.
// References are preserved structurally, but they are not resolved here.
type DesiredState struct {
	Routes []DesiredRoute
}

// DesiredRoute is a Gateway-targeted HTTPRoute reduced to the fields used by
// later control-plane stages.
type DesiredRoute struct {
	Name       string
	Namespace  string
	Hostnames  []string
	ParentRefs []gatewayv1.ParentReference
	Rules      []DesiredRule
}

// DesiredRule is a single translated routing rule after HTTPRoute matches have
// been expanded into route-level entries.
type DesiredRule struct {
	PathMatch DesiredPathMatch
	Backends  []DesiredBackend
	Filters   []DesiredFilter
}

// DesiredPathMatch is the normalized path matcher supported by ngxora today.
type DesiredPathMatch struct {
	Kind  string
	Value string
}

// DesiredBackend is the translated backend reference. Existence and port
// validation happen later in the controller, not in the translator.
type DesiredBackend struct {
	Group     string
	Kind      string
	Name      string
	Namespace string
	Port      int32
	Weight    int32
}

type DesiredFilter struct {
	Type         string
	PluginName   string
	PluginConfig string
	ExtensionRef *gatewayv1.LocalObjectReference
}

// Translator converts HTTPRoute objects for one target Gateway into
// control-plane desired state.
type Translator struct {
	gatewayName      string
	gatewayNamespace string
}

// New creates a Translator scoped to one Gateway. If gatewayName is empty, the
// translator accepts all parentRefs without Gateway-name filtering.
func New(gatewayName, gatewayNamespace string) *Translator {
	return &Translator{
		gatewayName:      gatewayName,
		gatewayNamespace: gatewayNamespace,
	}
}

// TranslateHTTPRoutes converts matching HTTPRoutes into one DesiredState.
func (t *Translator) TranslateHTTPRoutes(routes []gatewayv1.HTTPRoute) (*DesiredState, error) {
	state := &DesiredState{
		Routes: make([]DesiredRoute, 0, len(routes)),
	}

	for _, route := range routes {
		if !t.MatchesGateway(route) {
			continue
		}

		desired, err := t.TranslateHTTPRoute(route)
		if err != nil {
			return nil, err
		}
		state.Routes = append(state.Routes, desired)
	}

	return state, nil
}

// MatchesGateway reports whether the HTTPRoute has at least one parentRef for
// the configured Gateway.
func (t *Translator) MatchesGateway(route gatewayv1.HTTPRoute) bool {
	return len(t.MatchingParentRefs(route)) > 0
}

// MatchingParentRefs returns only the parentRefs that target the configured
// Gateway. Namespace defaults to the HTTPRoute namespace when omitted.
func (t *Translator) MatchingParentRefs(route gatewayv1.HTTPRoute) []gatewayv1.ParentReference {
	if t.gatewayName == "" {
		return append([]gatewayv1.ParentReference(nil), route.Spec.ParentRefs...)
	}

	matches := make([]gatewayv1.ParentReference, 0, len(route.Spec.ParentRefs))
	for _, parent := range route.Spec.ParentRefs {
		if parent.Kind != nil && string(*parent.Kind) != "Gateway" {
			continue
		}
		if parent.Group != nil && string(*parent.Group) != gatewayv1.GroupName {
			continue
		}
		if string(parent.Name) != t.gatewayName {
			continue
		}

		namespace := route.Namespace
		if parent.Namespace != nil {
			namespace = string(*parent.Namespace)
		}
		if namespace != t.gatewayNamespace {
			continue
		}

		matches = append(matches, parent)
	}

	return matches
}

// TranslateHTTPRoute converts one HTTPRoute into DesiredRoute without resolving
// referenced Kubernetes objects.
func (t *Translator) TranslateHTTPRoute(route gatewayv1.HTTPRoute) (DesiredRoute, error) {
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
			desired := DesiredFilter{Type: string(filter.Type)}
			if filter.Type == gatewayv1.HTTPRouteFilterExtensionRef && filter.ExtensionRef != nil {
				desired.ExtensionRef = filter.ExtensionRef
			}
			filters = append(filters, desired)
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

		group := ""
		if ref.BackendRef.Group != nil {
			group = string(*ref.BackendRef.Group)
		}

		kind := "Service"
		if ref.BackendRef.Kind != nil {
			kind = string(*ref.BackendRef.Kind)
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
			Group:     group,
			Kind:      kind,
			Name:      string(ref.BackendRef.Name),
			Namespace: namespace,
			Port:      int32(*ref.BackendRef.Port),
			Weight:    weight,
		})
	}

	return backends, nil
}
