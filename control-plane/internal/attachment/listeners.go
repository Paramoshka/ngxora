package attachment

import (
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func ListenerSelectedByParentRefs(listener gatewayv1.Listener, refs []gatewayv1.ParentReference) bool {
	if len(refs) == 0 {
		return false
	}

	for _, ref := range refs {
		if ref.SectionName != nil && string(*ref.SectionName) != string(listener.Name) {
			continue
		}
		if ref.Port != nil && uint32(*ref.Port) != uint32(listener.Port) {
			continue
		}
		return true
	}

	return false
}

func ListenerAllowsHTTPRoute(
	listener gatewayv1.Listener,
	gatewayNamespace string,
	routeNamespace string,
	routeNamespaceLabels map[string]string,
) (bool, error) {
	if !listenerSupportsHTTPRoute(listener) {
		return false, nil
	}

	return namespaceAllowed(listener, gatewayNamespace, routeNamespace, routeNamespaceLabels)
}

func ListenerHasSupportedHTTPRouteKind(listener gatewayv1.Listener) bool {
	return listenerSupportsHTTPRoute(listener)
}

func ListenerHasOnlySupportedRouteKinds(listener gatewayv1.Listener) bool {
	if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
		return listenerSupportsHTTPRoute(listener)
	}

	for _, kind := range listener.AllowedRoutes.Kinds {
		group := string(gatewayv1.GroupName)
		if kind.Group != nil {
			group = string(*kind.Group)
		}
		if group != string(gatewayv1.GroupName) || string(kind.Kind) != "HTTPRoute" {
			return false
		}
	}

	return true
}

func EffectiveServerNames(routeHostnames []string, listenerHostname *gatewayv1.Hostname) []string {
	if listenerHostname == nil || *listenerHostname == "" {
		if len(routeHostnames) == 0 {
			return []string{"*"}
		}
		return dedupeStrings(routeHostnames)
	}

	listenerHost := string(*listenerHostname)
	if len(routeHostnames) == 0 {
		return []string{listenerHost}
	}

	serverNames := make([]string, 0, len(routeHostnames))
	for _, routeHostname := range routeHostnames {
		if hostnamesIntersect(routeHostname, listenerHost) {
			serverNames = append(serverNames, narrowerHostname(routeHostname, listenerHost))
		}
	}

	return dedupeStrings(serverNames)
}

func listenerSupportsHTTPRoute(listener gatewayv1.Listener) bool {
	if listener.Protocol != gatewayv1.HTTPProtocolType && listener.Protocol != gatewayv1.HTTPSProtocolType {
		return false
	}

	if listener.AllowedRoutes == nil || len(listener.AllowedRoutes.Kinds) == 0 {
		return true
	}

	for _, kind := range listener.AllowedRoutes.Kinds {
		group := string(gatewayv1.GroupName)
		if kind.Group != nil {
			group = string(*kind.Group)
		}
		if group == string(gatewayv1.GroupName) && string(kind.Kind) == "HTTPRoute" {
			return true
		}
	}

	return false
}

func namespaceAllowed(
	listener gatewayv1.Listener,
	gatewayNamespace string,
	routeNamespace string,
	routeNamespaceLabels map[string]string,
) (bool, error) {
	from := gatewayv1.NamespacesFromSame
	if listener.AllowedRoutes != nil && listener.AllowedRoutes.Namespaces != nil && listener.AllowedRoutes.Namespaces.From != nil {
		from = *listener.AllowedRoutes.Namespaces.From
	}

	switch from {
	case gatewayv1.NamespacesFromSame:
		return routeNamespace == gatewayNamespace, nil
	case gatewayv1.NamespacesFromAll:
		return true, nil
	case gatewayv1.NamespacesFromSelector:
		if listener.AllowedRoutes == nil || listener.AllowedRoutes.Namespaces == nil || listener.AllowedRoutes.Namespaces.Selector == nil {
			return false, nil
		}
		selector, err := metav1.LabelSelectorAsSelector(listener.AllowedRoutes.Namespaces.Selector)
		if err != nil {
			return false, err
		}
		return selector.Matches(labels.Set(routeNamespaceLabels)), nil
	default:
		return false, nil
	}
}

func hostnamesIntersect(left, right string) bool {
	left = strings.ToLower(left)
	right = strings.ToLower(right)

	switch {
	case left == right:
		return true
	case isWildcardHostname(left) && isWildcardHostname(right):
		leftSuffix := strings.TrimPrefix(left, "*.")
		rightSuffix := strings.TrimPrefix(right, "*.")
		return leftSuffix == rightSuffix ||
			strings.HasSuffix(leftSuffix, "."+rightSuffix) ||
			strings.HasSuffix(rightSuffix, "."+leftSuffix)
	case isWildcardHostname(left):
		return hostnameMatchesWildcard(right, left)
	case isWildcardHostname(right):
		return hostnameMatchesWildcard(left, right)
	default:
		return false
	}
}

func narrowerHostname(left, right string) string {
	leftWildcard := isWildcardHostname(left)
	rightWildcard := isWildcardHostname(right)

	switch {
	case leftWildcard && !rightWildcard:
		return right
	case !leftWildcard && rightWildcard:
		return left
	case leftWildcard && rightWildcard:
		if len(left) >= len(right) {
			return left
		}
		return right
	default:
		return left
	}
}

func isWildcardHostname(hostname string) bool {
	return strings.HasPrefix(hostname, "*.")
}

func hostnameMatchesWildcard(hostname, wildcard string) bool {
	suffix := strings.TrimPrefix(strings.ToLower(wildcard), "*.")
	hostname = strings.ToLower(hostname)
	return hostname != suffix && strings.HasSuffix(hostname, "."+suffix)
}

func dedupeStrings(values []string) []string {
	if len(values) == 0 {
		return nil
	}

	result := make([]string, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if _, ok := seen[value]; ok {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	return result
}
