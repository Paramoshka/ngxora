package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strconv"
	"strings"

	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	"google.golang.org/protobuf/proto"

	"github.com/paramoshka/ngxora/control-plane/internal/translator"
)

type Builder struct{}

func NewBuilder() *Builder {
	return &Builder{}
}

func (b *Builder) Build(state *translator.DesiredState) (*controlv1.ConfigSnapshot, error) {
	if state == nil {
		return nil, fmt.Errorf("desired state is nil")
	}

	snapshot := &controlv1.ConfigSnapshot{}

	// This builder is intentionally narrow for the first scaffold:
	// one default listener, one virtual host per translated route, and direct upstreams.
	snapshot.Listeners = []*controlv1.Listener{
		{
			Name:    "default-http",
			Address: "0.0.0.0",
			Port:    8080,
			Tls:     false,
		},
	}

	sort.Slice(state.Routes, func(i, j int) bool {
		left := state.Routes[i].Namespace + "/" + state.Routes[i].Name
		right := state.Routes[j].Namespace + "/" + state.Routes[j].Name
		return left < right
	})

	for _, route := range state.Routes {
		virtualHost, upstreamGroups, err := buildVirtualHost(route)
		if err != nil {
			return nil, err
		}
		snapshot.VirtualHosts = append(snapshot.VirtualHosts, virtualHost)
		snapshot.Upstreams = append(snapshot.Upstreams, upstreamGroups...)
	}

	return snapshot, nil
}

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

func buildVirtualHost(route translator.DesiredRoute) (*controlv1.VirtualHost, []*controlv1.UpstreamGroup, error) {
	serverNames := route.Hostnames
	if len(serverNames) == 0 {
		serverNames = []string{"*"}
	}

	virtualHost := &controlv1.VirtualHost{
		Listener:      "default-http",
		ServerNames:   serverNames,
		DefaultServer: containsWildcard(serverNames),
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

func containsWildcard(names []string) bool {
	for _, name := range names {
		if name == "*" || strings.HasPrefix(name, "*.") {
			return true
		}
	}
	return false
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
