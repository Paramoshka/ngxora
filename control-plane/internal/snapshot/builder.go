package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net"
	"sort"
	"strconv"
	"strings"

	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"google.golang.org/protobuf/proto"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"

	"github.com/paramoshka/ngxora/control-plane/internal/attachment"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
)

// Builder converts normalized desired state into the wire snapshot model used
// by the dataplane gRPC API.
type Builder struct{}

// BuildResult returns the compiled snapshot plus attachment counts used by
// higher layers to derive Gateway API status.
type BuildResult struct {
	Snapshot         *controlv1.ConfigSnapshot
	RouteAttachments map[string]int
}

type compiledListener struct {
	snapshotName string
	port         uint32
	sectionName  string
	tlsBinding   *controlv1.TlsBinding
	spec         gatewayv1.Listener
}

func NewBuilder() *Builder {
	return &Builder{}
}

// Build compiles desired state for one Gateway into a ConfigSnapshot.
// Reference resolution and listener validation are expected to be done before
// this method is called.
func (b *Builder) Build(
	state *translator.DesiredState,
	gateway *gatewayv1.Gateway,
	namespaceLabels map[string]map[string]string,
	listenerTLS map[string]*controlv1.TlsBinding,
	listenerUsable map[string]bool,
) (*BuildResult, error) {
	if state == nil {
		return nil, fmt.Errorf("desired state is nil")
	}
	if gateway == nil {
		return nil, fmt.Errorf("gateway is nil")
	}

	snapshot := &controlv1.ConfigSnapshot{}
	listeners, err := buildGatewayListeners(gateway, listenerTLS)
	if err != nil {
		return nil, err
	}
	snapshot.Listeners = make([]*controlv1.Listener, 0, len(listeners))
	for _, listener := range listeners {
		snapshot.Listeners = append(snapshot.Listeners, &controlv1.Listener{
			Name:    listener.snapshotName,
			Address: gatewayBindAddress(gateway),
			Port:    listener.port,
			Tls:     listener.tlsBinding != nil,
		})
	}

	sort.Slice(state.Routes, func(i, j int) bool {
		left := state.Routes[i].Namespace + "/" + state.Routes[i].Name
		right := state.Routes[j].Namespace + "/" + state.Routes[j].Name
		return left < right
	})

	result := &BuildResult{
		Snapshot:         snapshot,
		RouteAttachments: make(map[string]int, len(state.Routes)),
	}

	for _, route := range state.Routes {
		attachments, err := routeAttachments(route, gateway.Namespace, listeners, namespaceLabels, listenerUsable)
		if err != nil {
			return nil, err
		}
		result.RouteAttachments[routeKey(route)] = len(attachments)
		for _, attachment := range attachments {
			virtualHost, upstreamGroups, err := buildVirtualHost(route, attachment)
			if err != nil {
				return nil, err
			}
			snapshot.VirtualHosts = append(snapshot.VirtualHosts, virtualHost)
			snapshot.Upstreams = append(snapshot.Upstreams, upstreamGroups...)
		}
	}

	return result, nil
}

// StableVersion returns a deterministic hash of the snapshot payload with the
// version field cleared, so identical config produces the same version.
func StableVersion(snapshot *controlv1.ConfigSnapshot) (string, error) {
	if snapshot == nil {
		return "", fmt.Errorf("snapshot is nil")
	}

	clone, ok := proto.Clone(snapshot).(*controlv1.ConfigSnapshot)
	if !ok {
		return "", fmt.Errorf("clone snapshot: unexpected type")
	}

	clone.Version = ""

	payload, err := proto.MarshalOptions{Deterministic: true}.Marshal(clone)
	if err != nil {
		return "", fmt.Errorf("marshal snapshot deterministically: %w", err)
	}

	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:]), nil
}

func buildVirtualHost(route translator.DesiredRoute, attachment routeAttachment) (*controlv1.VirtualHost, []*controlv1.UpstreamGroup, error) {
	virtualHost := &controlv1.VirtualHost{
		Listener:      attachment.listenerName,
		ServerNames:   attachment.serverNames,
		DefaultServer: containsWildcard(attachment.serverNames),
		Tls:           cloneTLSBinding(attachment.tlsBinding),
	}

	upstreamGroups := make([]*controlv1.UpstreamGroup, 0, len(route.Rules))
	for index, rule := range route.Rules {
		groupName := upstreamGroupName(route, index)
		compiledRoute, upstreamGroup, err := buildRoute(rule, groupName)
		if err != nil {
			return nil, nil, err
		}
		virtualHost.Routes = append(virtualHost.Routes, compiledRoute)
		upstreamGroups = append(upstreamGroups, upstreamGroup)
	}

	return virtualHost, upstreamGroups, nil
}

func cloneTLSBinding(binding *controlv1.TlsBinding) *controlv1.TlsBinding {
	if binding == nil {
		return nil
	}

	clone, ok := proto.Clone(binding).(*controlv1.TlsBinding)
	if !ok {
		return nil
	}
	return clone
}

func buildRoute(rule translator.DesiredRule, upstreamGroupName string) (*controlv1.Route, *controlv1.UpstreamGroup, error) {
	if len(rule.Backends) == 0 {
		return nil, nil, fmt.Errorf("rule has no backends")
	}

	upstreamGroup := &controlv1.UpstreamGroup{
		Name:   upstreamGroupName,
		Policy: controlv1.UpstreamSelectionPolicy_UPSTREAM_SELECTION_POLICY_ROUND_ROBIN,
	}
	for _, backend := range rule.Backends {
		upstreamGroup.Backends = append(upstreamGroup.Backends, &controlv1.UpstreamBackend{
			Host: fmt.Sprintf("%s.%s.svc.cluster.local", backend.Name, backend.Namespace),
			Port: uint32(backend.Port),
		})
	}

	route := &controlv1.Route{
		Upstream: &controlv1.Upstream{
			Scheme:        "http",
			UpstreamGroup: upstreamGroupName,
		},
	}

	switch rule.PathMatch.Kind {
	case "Exact":
		route.Match = &controlv1.Match{
			Kind: &controlv1.Match_Exact{Exact: rule.PathMatch.Value},
		}
	case "PathPrefix":
		route.Match = &controlv1.Match{
			Kind: &controlv1.Match_Prefix{Prefix: rule.PathMatch.Value},
		}
	default:
		return nil, nil, fmt.Errorf("unsupported desired path kind: %s", rule.PathMatch.Kind)
	}

	return route, upstreamGroup, nil
}

type routeAttachment struct {
	listenerName string
	serverNames  []string
	tlsBinding   *controlv1.TlsBinding
}

func buildGatewayListeners(
	gateway *gatewayv1.Gateway,
	listenerTLS map[string]*controlv1.TlsBinding,
) ([]compiledListener, error) {
	listeners := make([]compiledListener, 0, len(gateway.Spec.Listeners))

	for _, listener := range gateway.Spec.Listeners {
		switch listener.Protocol {
		case gatewayv1.HTTPProtocolType:
		case gatewayv1.HTTPSProtocolType:
			if listenerTLS[string(listener.Name)] == nil {
				continue
			}
		default:
			continue
		}

		listeners = append(listeners, compiledListener{
			snapshotName: fmt.Sprintf("http-%s-%s-%s", sanitizeName(gateway.Namespace), sanitizeName(gateway.Name), sanitizeName(string(listener.Name))),
			port:         uint32(listener.Port),
			sectionName:  string(listener.Name),
			tlsBinding:   listenerTLS[string(listener.Name)],
			spec:         listener,
		})
	}

	if len(listeners) == 0 {
		return nil, fmt.Errorf("gateway %s/%s has no supported HTTP or HTTPS listeners", gateway.Namespace, gateway.Name)
	}

	return listeners, nil
}

func routeAttachments(
	route translator.DesiredRoute,
	gatewayNamespace string,
	listeners []compiledListener,
	namespaceLabels map[string]map[string]string,
	listenerUsable map[string]bool,
) ([]routeAttachment, error) {
	attachments := make([]routeAttachment, 0, len(listeners))
	for _, listener := range listeners {
		if !listenerUsable[listener.sectionName] {
			continue
		}

		if !attachment.ListenerSelectedByParentRefs(listener.spec, route.ParentRefs) {
			continue
		}

		allowed, err := attachment.ListenerAllowsHTTPRoute(
			listener.spec,
			gatewayNamespace,
			route.Namespace,
			namespaceLabels[route.Namespace],
		)
		if err != nil {
			return nil, fmt.Errorf("evaluate allowedRoutes for listener %s: %w", listener.sectionName, err)
		}
		if !allowed {
			continue
		}

		serverNames := attachment.EffectiveServerNames(route.Hostnames, listener.spec.Hostname)
		if len(serverNames) == 0 {
			continue
		}

		attachments = append(attachments, routeAttachment{
			listenerName: listener.snapshotName,
			serverNames:  serverNames,
			tlsBinding:   listener.tlsBinding,
		})
	}

	return attachments, nil
}

func gatewayBindAddress(gateway *gatewayv1.Gateway) string {
	for _, address := range gateway.Spec.Addresses {
		if address.Value == "" {
			continue
		}

		addressType := gatewayv1.IPAddressType
		if address.Type != nil {
			addressType = *address.Type
		}
		if addressType != gatewayv1.IPAddressType {
			continue
		}
		if net.ParseIP(address.Value) != nil {
			return address.Value
		}
	}

	return "0.0.0.0"
}

func containsWildcard(names []string) bool {
	for _, name := range names {
		if name == "*" || strings.HasPrefix(name, "*.") {
			return true
		}
	}
	return false
}

func routeKey(route translator.DesiredRoute) string {
	return route.Namespace + "/" + route.Name
}

func upstreamGroupName(route translator.DesiredRoute, ruleIndex int) string {
	return strings.Join([]string{
		sanitizeName(route.Namespace),
		sanitizeName(route.Name),
		"rule",
		strconv.Itoa(ruleIndex),
	}, "-")
}

func sanitizeName(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "_", "-")
	value = strings.ReplaceAll(value, ".", "-")
	value = strings.ReplaceAll(value, "/", "-")
	if value == "" {
		return "default"
	}
	return value
}
