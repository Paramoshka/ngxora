package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// CorsPolicySpec defines the desired state of CorsPolicy
type CorsPolicySpec struct {
	AllowOrigin      *string `json:"allow_origin,omitempty"`
	AllowMethods     *string `json:"allow_methods,omitempty"`
	AllowHeaders     *string `json:"allow_headers,omitempty"`
	ExposeHeaders    *string `json:"expose_headers,omitempty"`
	AllowCredentials *bool   `json:"allow_credentials,omitempty"`
	MaxAge           *uint64 `json:"max_age,omitempty"`
}

// CorsPolicyStatus defines the observed state of CorsPolicy
type CorsPolicyStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// CorsPolicy is the Schema for the corspolicies API
type CorsPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   CorsPolicySpec   `json:"spec,omitempty"`
	Status CorsPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// CorsPolicyList contains a list of CorsPolicy
type CorsPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []CorsPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&CorsPolicy{}, &CorsPolicyList{})
}
