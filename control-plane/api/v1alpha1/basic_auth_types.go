package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// BasicAuthPolicySpec defines the desired state of BasicAuthPolicy
type BasicAuthPolicySpec struct {
	Username string `json:"username"`
	Password string `json:"password"`
	Realm    string `json:"realm,omitempty"`
}

// BasicAuthPolicyStatus defines the observed state of BasicAuthPolicy
type BasicAuthPolicyStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// BasicAuthPolicy is the Schema for the basicauthpolicies API
type BasicAuthPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   BasicAuthPolicySpec   `json:"spec,omitempty"`
	Status BasicAuthPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// BasicAuthPolicyList contains a list of BasicAuthPolicy
type BasicAuthPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []BasicAuthPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&BasicAuthPolicy{}, &BasicAuthPolicyList{})
}
