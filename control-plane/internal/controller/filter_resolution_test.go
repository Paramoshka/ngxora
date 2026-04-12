package controller

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/paramoshka/ngxora/control-plane/api/v1alpha1"
	"github.com/paramoshka/ngxora/control-plane/internal/translator"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
)

func TestFilterResolver_ResolveFilters_RateLimitPolicy(t *testing.T) {
	ctx := context.Background()
	policy := &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rl-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.RateLimitPolicySpec{
			MaxRequestsPerSecond: 100,
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "RateLimitPolicy",
							Name:  "rl-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.NoError(t, err)

	filter := route.Rules[0].Filters[0]
	assert.Equal(t, "rate-limit", filter.PluginName)

	var cfg map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(filter.PluginConfig), &cfg))
	assert.Equal(t, float64(100), cfg["max_requests_per_second"])
}

func TestFilterResolver_ResolveFilters_JwtAuthPolicy(t *testing.T) {
	ctx := context.Background()
	policy := &v1alpha1.JwtAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "jwt-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.JwtAuthPolicySpec{
			Algorithm: "RS256",
			Secret:    "my-secret-key",
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "JwtAuthPolicy",
							Name:  "jwt-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.NoError(t, err)

	filter := route.Rules[0].Filters[0]
	assert.Equal(t, "jwt_auth", filter.PluginName)

	var cfg map[string]interface{}
	require.NoError(t, json.Unmarshal([]byte(filter.PluginConfig), &cfg))
	assert.Equal(t, "RS256", cfg["algorithm"])
	assert.Equal(t, "my-secret-key", cfg["secret"])
}

func TestFilterResolver_ResolveFilters_BasicAuthPolicy(t *testing.T) {
	ctx := context.Background()
	policy := &v1alpha1.BasicAuthPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "basic-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.BasicAuthPolicySpec{
			Username: "admin",
			Password: "hashed-password",
			Realm:    "ngxora",
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "BasicAuthPolicy",
							Name:  "basic-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.NoError(t, err)

	filter := route.Rules[0].Filters[0]
	assert.Equal(t, "basic-auth", filter.PluginName)
}

func TestFilterResolver_ResolveFilters_CorsPolicy(t *testing.T) {
	ctx := context.Background()
	allowOrigin := "https://example.com"
	allowMethods := "GET, POST"
	policy := &v1alpha1.CorsPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cors-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.CorsPolicySpec{
			AllowOrigin:  &allowOrigin,
			AllowMethods: &allowMethods,
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "CorsPolicy",
							Name:  "cors-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.NoError(t, err)

	filter := route.Rules[0].Filters[0]
	assert.Equal(t, "cors", filter.PluginName)
}

func TestFilterResolver_ResolveFilters_ExtAuthzPolicy(t *testing.T) {
	ctx := context.Background()
	policy := &v1alpha1.ExtAuthzPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "ext-authz-policy",
			Namespace: "default",
		},
		Spec: v1alpha1.ExtAuthzPolicySpec{
			URI: "https://auth.example.com/check",
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "ExtAuthzPolicy",
							Name:  "ext-authz-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.NoError(t, err)

	filter := route.Rules[0].Filters[0]
	assert.Equal(t, "ext_authz", filter.PluginName)
}

func TestFilterResolver_ResolveFilters_ExtensionRefNotFound(t *testing.T) {
	ctx := context.Background()
	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "RateLimitPolicy",
							Name:  "non-existent-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.Error(t, err)

	var filterErr *filterResolutionError
	require.ErrorAs(t, err, &filterErr)
	assert.Equal(t, "ExtensionRefNotFound", filterErr.reason)
}

func TestFilterResolver_ResolveFilters_InvalidExtensionRefGroup(t *testing.T) {
	ctx := context.Background()
	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "wrong-group.io",
							Kind:  "RateLimitPolicy",
							Name:  "some-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.Error(t, err)

	var filterErr *filterResolutionError
	require.ErrorAs(t, err, &filterErr)
	assert.Equal(t, "InvalidExtensionRef", filterErr.reason)
}

func TestFilterResolver_ResolveFilters_InvalidExtensionRefKind(t *testing.T) {
	ctx := context.Background()
	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "UnknownKind",
							Name:  "some-policy",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.Error(t, err)

	var filterErr *filterResolutionError
	require.ErrorAs(t, err, &filterErr)
	assert.Equal(t, "InvalidExtensionRef", filterErr.reason)
}

func TestFilterResolver_ResolveFilters_NoExtensionRef(t *testing.T) {
	ctx := context.Background()
	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type:         string(gatewayv1.HTTPRouteFilterRequestHeaderModifier),
						PluginName:   "headers",
						PluginConfig: `{"request":{"set":[{"name":"X-Custom","value":"test"}]}}`,
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.NoError(t, err)

	// Non-ExtensionRef filters should be left untouched
	assert.Equal(t, "headers", route.Rules[0].Filters[0].PluginName)
}

func TestFilterResolver_ResolveFilters_MultipleRules(t *testing.T) {
	ctx := context.Background()
	policy1 := &v1alpha1.RateLimitPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "rl-policy-1",
			Namespace: "default",
		},
		Spec: v1alpha1.RateLimitPolicySpec{
			MaxRequestsPerSecond: 50,
		},
	}
	policy2 := &v1alpha1.CorsPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cors-policy-1",
			Namespace: "default",
		},
		Spec: v1alpha1.CorsPolicySpec{
			AllowOrigin: ptrStr("*"),
		},
	}

	route := &translator.DesiredRoute{
		Name:      "test-route",
		Namespace: "default",
		Rules: []translator.DesiredRule{
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "RateLimitPolicy",
							Name:  "rl-policy-1",
						},
					},
				},
			},
			{
				Filters: []translator.DesiredFilter{
					{
						Type: string(gatewayv1.HTTPRouteFilterExtensionRef),
						ExtensionRef: &gatewayv1.LocalObjectReference{
							Group: "plugins.ngxora.io",
							Kind:  "CorsPolicy",
							Name:  "cors-policy-1",
						},
					},
				},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(policy1, policy2).
		Build()

	resolver := NewFilterResolver(fakeClient)
	err := resolver.ResolveFilters(ctx, "default", route)
	require.NoError(t, err)

	assert.Equal(t, "rate-limit", route.Rules[0].Filters[0].PluginName)
	assert.Equal(t, "cors", route.Rules[1].Filters[0].PluginName)
}

func TestFilterResolutionError_Unwrap(t *testing.T) {
	innerErr := assert.AnError
	wrapped := newFilterResolutionError("TestReason", innerErr)

	var filterErr *filterResolutionError
	require.ErrorAs(t, wrapped, &filterErr)
	assert.Equal(t, "TestReason", filterErr.reason)
	assert.Equal(t, innerErr, filterErr.Unwrap())
	assert.Contains(t, filterErr.Error(), assert.AnError.Error())
}
