package controller

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"time"

	controlv1 "github.com/paramoshka/ngxora/sdk/go/ngxora/control/v1"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	gatewayv1 "sigs.k8s.io/gateway-api/apis/v1"
	gatewayv1beta1 "sigs.k8s.io/gateway-api/apis/v1beta1"
)

// TLSReader defines the minimal read operations needed for TLS validation.
type TLSReader interface {
	Get(ctx context.Context, key types.NamespacedName, obj client.Object, opts ...client.GetOption) error
	List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error
}

// TLSValidator validates TLS certificates and builds TlsBinding objects.
type TLSValidator struct {
	reader TLSReader
}

// NewTLSValidator creates a new TLSValidator.
func NewTLSValidator(reader TLSReader) *TLSValidator {
	return &TLSValidator{reader: reader}
}

// ResolveListenerTLSBinding resolves and validates the TLS configuration for
// a Gateway listener, returning a TlsBinding and status condition.
func (v *TLSValidator) ResolveListenerTLSBinding(
	ctx context.Context,
	gatewayNamespace string,
	listener gatewayv1.Listener,
	secretCache map[types.NamespacedName]*corev1.Secret,
	referenceGrantCache map[string][]gatewayv1beta1.ReferenceGrant,
) (*controlv1.TlsBinding, routeConditionState) {
	if listener.TLS == nil {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: "HTTPS listener requires tls.certificateRefs",
		}
	}
	if len(listener.TLS.CertificateRefs) == 0 {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: "HTTPS listener requires at least one certificateRef",
		}
	}
	if len(listener.TLS.CertificateRefs) > 1 {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: "multiple certificateRefs are not supported by ngxora yet",
		}
	}

	ref := listener.TLS.CertificateRefs[0]
	group := ""
	if ref.Group != nil {
		group = string(*ref.Group)
	}
	kind := "Secret"
	if ref.Kind != nil {
		kind = string(*ref.Kind)
	}
	if group != "" || kind != "Secret" {
		return nil, routeConditionState{
			status:  false,
			reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf("listener certificateRef %q must point to a core Secret", ref.Name),
		}
	}

	secretNamespace := gatewayNamespace
	if ref.Namespace != nil {
		secretNamespace = string(*ref.Namespace)
	}
	if secretNamespace != gatewayNamespace {
		allowed, err := v.certificateReferenceGrantAllows(
			ctx,
			gatewayNamespace,
			secretNamespace,
			string(ref.Name),
			referenceGrantCache,
		)
		if err != nil {
			return nil, routeConditionState{
				status:  false,
				reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
				message: err.Error(),
			}
		}
		if !allowed {
			return nil, routeConditionState{
				status: false,
				reason: string(gatewayv1.ListenerReasonRefNotPermitted),
				message: fmt.Sprintf(
					"cross-namespace certificateRef %s/%s is not permitted by any ReferenceGrant",
					secretNamespace,
					ref.Name,
				),
			}
		}
	}

	secretKey := types.NamespacedName{Namespace: secretNamespace, Name: string(ref.Name)}
	secret, ok := secretCache[secretKey]
	if !ok {
		secret = &corev1.Secret{}
		if err := v.reader.Get(ctx, secretKey, secret); err != nil {
			return nil, routeConditionState{
				status:  false,
				reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
				message: fmt.Sprintf("resolve TLS Secret %s/%s: %v", secretKey.Namespace, secretKey.Name, err),
			}
		}
		secretCache[secretKey] = secret
	}

	return v.validateAndBuildTLSBinding(secret, secretKey, listener)
}

func (v *TLSValidator) validateAndBuildTLSBinding(
	secret *corev1.Secret,
	secretKey types.NamespacedName,
	listener gatewayv1.Listener,
) (*controlv1.TlsBinding, routeConditionState) {
	certPEM := secret.Data[corev1.TLSCertKey]
	keyPEM := secret.Data[corev1.TLSPrivateKeyKey]
	if len(certPEM) == 0 || len(keyPEM) == 0 {
		return nil, routeConditionState{
			status: false,
			reason: string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf(
				"TLS Secret %s/%s must contain %q and %q data keys",
				secretKey.Namespace,
				secretKey.Name,
				corev1.TLSCertKey,
				corev1.TLSPrivateKeyKey,
			),
		}
	}

	if secret.Type != corev1.SecretTypeTLS {
		return nil, routeConditionState{
			status: false,
			reason: string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf(
				"TLS Secret %s/%s has invalid type %q; must be %q",
				secretKey.Namespace,
				secretKey.Name,
				secret.Type,
				corev1.SecretTypeTLS,
			),
		}
	}

	keyPair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, routeConditionState{
			status: false,
			reason: string(gatewayv1.ListenerReasonInvalidCertificateRef),
			message: fmt.Sprintf(
				"TLS Secret %s/%s contains invalid certificate or private key: %v",
				secretKey.Namespace,
				secretKey.Name,
				err,
			),
		}
	}

	if len(keyPair.Certificate) > 0 {
		cert, err := x509.ParseCertificate(keyPair.Certificate[0])
		if err == nil {
			now := time.Now()
			if now.After(cert.NotAfter) || now.Before(cert.NotBefore) {
				return nil, routeConditionState{
					status:  false,
					reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
					message: fmt.Sprintf("TLS certificate in Secret %s/%s is expired or not yet valid", secretKey.Namespace, secretKey.Name),
				}
			}

			if listener.Hostname != nil {
				if err := cert.VerifyHostname(string(*listener.Hostname)); err != nil {
					return nil, routeConditionState{
						status:  false,
						reason:  string(gatewayv1.ListenerReasonInvalidCertificateRef),
						message: fmt.Sprintf("TLS certificate in Secret %s/%s is not valid for listener hostname %q: %v", secretKey.Namespace, secretKey.Name, *listener.Hostname, err),
					}
				}
			}
		}
	}

	return &controlv1.TlsBinding{
			Cert: &controlv1.PemSource{
				Source: &controlv1.PemSource_InlinePem{InlinePem: string(certPEM)},
			},
			Key: &controlv1.PemSource{
				Source: &controlv1.PemSource_InlinePem{InlinePem: string(keyPEM)},
			},
		}, routeConditionState{
			status:  true,
			reason:  string(gatewayv1.ListenerReasonResolvedRefs),
			message: "listener TLS certificateRefs are resolved",
		}
}

func (v *TLSValidator) certificateReferenceGrantAllows(
	ctx context.Context,
	fromNamespace string,
	secretNamespace string,
	secretName string,
	cache map[string][]gatewayv1beta1.ReferenceGrant,
) (bool, error) {
	grants, ok := cache[secretNamespace]
	if !ok {
		var grantList gatewayv1beta1.ReferenceGrantList
		if err := v.reader.List(ctx, &grantList, client.InNamespace(secretNamespace)); err != nil {
			return false, fmt.Errorf("list ReferenceGrants in namespace %s: %w", secretNamespace, err)
		}
		grants = grantList.Items
		cache[secretNamespace] = grants
	}

	for _, grant := range grants {
		if certificateReferenceGrantMatches(grant, fromNamespace, secretName) {
			return true, nil
		}
	}

	return false, nil
}

func certificateReferenceGrantMatches(
	grant gatewayv1beta1.ReferenceGrant,
	fromNamespace string,
	secretName string,
) bool {
	matchedFrom := false
	for _, from := range grant.Spec.From {
		if string(from.Group) != string(gatewayv1.GroupName) {
			continue
		}
		if string(from.Kind) != "Gateway" {
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
		if string(to.Group) != "" {
			continue
		}
		if string(to.Kind) != "Secret" {
			continue
		}
		if to.Name != nil && string(*to.Name) != secretName {
			continue
		}
		return true
	}

	return false
}
