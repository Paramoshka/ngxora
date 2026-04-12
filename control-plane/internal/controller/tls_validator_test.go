package controller

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

func TestTLSValidator_ResolveListenerTLSBinding_NoTLS(t *testing.T) {
	listener := gatewayv1.Listener{
		Name:     "http",
		Protocol: gatewayv1.HTTPProtocolType,
		TLS:      nil,
	}

	validator := NewTLSValidator(nil)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener, nil, nil,
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Equal(t, string(gatewayv1.ListenerReasonInvalidCertificateRef), state.reason)
}

func TestTLSValidator_ResolveListenerTLSBinding_EmptyCertificateRefs(t *testing.T) {
	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{},
		},
	}

	validator := NewTLSValidator(nil)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener, nil, nil,
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "requires at least one certificateRef")
}

func TestTLSValidator_ResolveListenerTLSBinding_MultipleCertificateRefs(t *testing.T) {
	name1 := gatewayv1.ObjectName("cert1")
	name2 := gatewayv1.ObjectName("cert2")
	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: name1},
				{Name: name2},
			},
		},
	}

	validator := NewTLSValidator(nil)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener, nil, nil,
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "multiple certificateRefs are not supported")
}

func TestTLSValidator_ResolveListenerTLSBinding_NonSecretRef(t *testing.T) {
	kind := gatewayv1.Kind("ConfigMap")
	name := gatewayv1.ObjectName("my-cert")
	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: name, Kind: &kind},
			},
		},
	}

	validator := NewTLSValidator(nil)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener, nil, nil,
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "must point to a core Secret")
}

func TestTLSValidator_ResolveListenerTLSBinding_SecretNotFound(t *testing.T) {
	name := gatewayv1.ObjectName("missing-cert")
	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: name},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		Build()

	validator := NewTLSValidator(fakeClient)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener,
		make(map[types.NamespacedName]*corev1.Secret),
		make(map[string][]gatewayv1beta1.ReferenceGrant),
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "resolve TLS Secret")
}

func TestTLSValidator_ValidateAndBuildTLSBinding_ValidCertificate(t *testing.T) {
	certPEM, keyPEM := generateTestCertificate(t, "localhost", time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-tls",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: (*gatewayv1.Hostname)(ptrStr("localhost")),
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: gatewayv1.ObjectName("test-tls")},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	validator := NewTLSValidator(fakeClient)
	secretCache := make(map[types.NamespacedName]*corev1.Secret)
	grantCache := make(map[string][]gatewayv1beta1.ReferenceGrant)

	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener, secretCache, grantCache,
	)

	require.NotNil(t, binding)
	assert.True(t, state.status)
	assert.Equal(t, string(gatewayv1.ListenerReasonResolvedRefs), state.reason)
	assert.Contains(t, binding.Cert.GetInlinePem(), "BEGIN CERTIFICATE")
	assert.Contains(t, binding.Key.GetInlinePem(), "BEGIN EC PRIVATE KEY")

	// Verify cache was populated
	_, cached := secretCache[types.NamespacedName{Namespace: "default", Name: "test-tls"}]
	assert.True(t, cached)
}

func TestTLSValidator_ResolveListenerTLSBinding_MissingCertData(t *testing.T) {
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "incomplete-tls",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey: {},
		},
	}

	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: gatewayv1.ObjectName("incomplete-tls")},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	validator := NewTLSValidator(fakeClient)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener,
		make(map[types.NamespacedName]*corev1.Secret),
		make(map[string][]gatewayv1beta1.ReferenceGrant),
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "must contain")
}

func TestTLSValidator_ResolveListenerTLSBinding_WrongSecretType(t *testing.T) {
	certPEM, keyPEM := generateTestCertificate(t, "localhost", time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "wrong-type-tls",
			Namespace: "default",
		},
		Type: corev1.SecretTypeOpaque,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: gatewayv1.ObjectName("wrong-type-tls")},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	validator := NewTLSValidator(fakeClient)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener,
		make(map[types.NamespacedName]*corev1.Secret),
		make(map[string][]gatewayv1beta1.ReferenceGrant),
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "invalid type")
}

func TestTLSValidator_ResolveListenerTLSBinding_ExpiredCertificate(t *testing.T) {
	certPEM, keyPEM := generateTestCertificate(t, "localhost", time.Now().Add(-720*24*time.Hour), time.Now().Add(-24*time.Hour))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "expired-tls",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: gatewayv1.ObjectName("expired-tls")},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	validator := NewTLSValidator(fakeClient)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener,
		make(map[types.NamespacedName]*corev1.Secret),
		make(map[string][]gatewayv1beta1.ReferenceGrant),
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "expired")
}

func TestTLSValidator_ResolveListenerTLSBinding_HostnameMismatch(t *testing.T) {
	certPEM, keyPEM := generateTestCertificate(t, "example.com", time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "mismatch-tls",
			Namespace: "default",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: (*gatewayv1.Hostname)(ptrStr("different.com")),
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: gatewayv1.ObjectName("mismatch-tls")},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	validator := NewTLSValidator(fakeClient)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener,
		make(map[types.NamespacedName]*corev1.Secret),
		make(map[string][]gatewayv1beta1.ReferenceGrant),
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "not valid for listener hostname")
}

func TestTLSValidator_ResolveListenerTLSBinding_CrossNamespaceWithoutGrant(t *testing.T) {
	certPEM, keyPEM := generateTestCertificate(t, "localhost", time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))

	ns := gatewayv1.Namespace("other-ns")
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-ns-cert",
			Namespace: "other-ns",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: gatewayv1.ObjectName("cross-ns-cert"), Namespace: &ns},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret).
		Build()

	validator := NewTLSValidator(fakeClient)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener,
		make(map[types.NamespacedName]*corev1.Secret),
		make(map[string][]gatewayv1beta1.ReferenceGrant),
	)

	assert.Nil(t, binding)
	assert.False(t, state.status)
	assert.Contains(t, state.message, "not permitted by any ReferenceGrant")
}

func TestTLSValidator_ResolveListenerTLSBinding_CrossNamespaceWithGrant(t *testing.T) {
	certPEM, keyPEM := generateTestCertificate(t, "localhost", time.Now().Add(-24*time.Hour), time.Now().Add(365*24*time.Hour))

	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "cross-ns-cert",
			Namespace: "other-ns",
		},
		Type: corev1.SecretTypeTLS,
		Data: map[string][]byte{
			corev1.TLSCertKey:       certPEM,
			corev1.TLSPrivateKeyKey: keyPEM,
		},
	}

	group := gatewayv1.Group(gatewayv1.GroupName)
	ns := gatewayv1.Namespace("other-ns")
	grant := &gatewayv1beta1.ReferenceGrant{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "allow-cert",
			Namespace: "other-ns",
		},
		Spec: gatewayv1beta1.ReferenceGrantSpec{
			From: []gatewayv1beta1.ReferenceGrantFrom{
				{
					Group:     gatewayv1.Group(group),
					Kind:      "Gateway",
					Namespace: "default",
				},
			},
			To: []gatewayv1beta1.ReferenceGrantTo{
				{Group: "", Kind: "Secret"},
			},
		},
	}

	listener := gatewayv1.Listener{
		Name:     "https",
		Protocol: gatewayv1.HTTPSProtocolType,
		Hostname: (*gatewayv1.Hostname)(ptrStr("localhost")),
		TLS: &gatewayv1.GatewayTLSConfig{
			CertificateRefs: []gatewayv1.SecretObjectReference{
				{Name: gatewayv1.ObjectName("cross-ns-cert"), Namespace: &ns},
			},
		},
	}

	scheme := buildTestScheme()
	fakeClient := fake.NewClientBuilder().
		WithScheme(scheme).
		WithObjects(secret, grant).
		Build()

	validator := NewTLSValidator(fakeClient)
	binding, state := validator.ResolveListenerTLSBinding(
		context.Background(), "default", listener,
		make(map[types.NamespacedName]*corev1.Secret),
		make(map[string][]gatewayv1beta1.ReferenceGrant),
	)

	require.NotNil(t, binding)
	assert.True(t, state.status)
}

func TestCertificateReferenceGrantMatches(t *testing.T) {
	group := gatewayv1.Group(gatewayv1.GroupName)

	tests := []struct {
		name          string
		grant         gatewayv1beta1.ReferenceGrant
		fromNamespace string
		secretName    string
		want          bool
	}{
		{
			name: "matches wildcard secret name",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "Gateway",
							Namespace: "default",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{Group: "", Kind: "Secret"},
					},
				},
			},
			fromNamespace: "default",
			secretName:    "my-cert",
			want:          true,
		},
		{
			name: "matches exact secret name",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "Gateway",
							Namespace: "default",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{
							Group: "",
							Kind:  "Secret",
							Name:  ptrSecretObjectName("my-cert"),
						},
					},
				},
			},
			fromNamespace: "default",
			secretName:    "my-cert",
			want:          true,
		},
		{
			name: "does not match wrong secret name",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "Gateway",
							Namespace: "default",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{
							Group: "",
							Kind:  "Secret",
							Name:  ptrSecretObjectName("other-cert"),
						},
					},
				},
			},
			fromNamespace: "default",
			secretName:    "my-cert",
			want:          false,
		},
		{
			name: "does not match wrong from namespace",
			grant: gatewayv1beta1.ReferenceGrant{
				Spec: gatewayv1beta1.ReferenceGrantSpec{
					From: []gatewayv1beta1.ReferenceGrantFrom{
						{
							Group:     gatewayv1.Group(group),
							Kind:      "Gateway",
							Namespace: "production",
						},
					},
					To: []gatewayv1beta1.ReferenceGrantTo{
						{Group: "", Kind: "Secret"},
					},
				},
			},
			fromNamespace: "default",
			secretName:    "my-cert",
			want:          false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := certificateReferenceGrantMatches(tc.grant, tc.fromNamespace, tc.secretName)
			assert.Equal(t, tc.want, got)
		})
	}
}

// generateTestCertificate creates a self-signed certificate for testing.
func generateTestCertificate(t *testing.T, hostname string, notBefore, notAfter time.Time) (certPEM, keyPEM []byte) {
	t.Helper()

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	require.NoError(t, err)

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: hostname,
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{hostname},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	require.NoError(t, err)

	certBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})

	keyDER, err := x509.MarshalECPrivateKey(priv)
	require.NoError(t, err)

	keyBuf := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})

	return certBuf, keyBuf
}

func ptrSecretObjectName(name string) *gatewayv1.ObjectName {
	n := gatewayv1.ObjectName(name)
	return &n
}
