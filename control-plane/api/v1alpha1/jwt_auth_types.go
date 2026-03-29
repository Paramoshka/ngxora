package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// JwtAuthPolicySpec defines the desired state of JwtAuthPolicy
type JwtAuthPolicySpec struct {
	Algorithm  string `json:"algorithm"`
	Secret     string `json:"secret,omitempty"`
	SecretFile string `json:"secret_file,omitempty"`
}

// JwtAuthPolicyStatus defines the observed state of JwtAuthPolicy
type JwtAuthPolicyStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// JwtAuthPolicy is the Schema for the jwtauthpolicies API
type JwtAuthPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   JwtAuthPolicySpec   `json:"spec,omitempty"`
	Status JwtAuthPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// JwtAuthPolicyList contains a list of JwtAuthPolicy
type JwtAuthPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []JwtAuthPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&JwtAuthPolicy{}, &JwtAuthPolicyList{})
}
