package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// ExtAuthzPolicySpec defines the desired state of ExtAuthzPolicy
type ExtAuthzPolicySpec struct {
	URI                 string   `json:"uri"`
	TimeoutMs           *uint64  `json:"timeout_ms,omitempty"`
	PassRequestHeaders  []string `json:"pass_request_headers,omitempty"`
	PassResponseHeaders []string `json:"pass_response_headers,omitempty"`
}

// ExtAuthzPolicyStatus defines the observed state of ExtAuthzPolicy
type ExtAuthzPolicyStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// ExtAuthzPolicy is the Schema for the extauthzpolicies API
type ExtAuthzPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   ExtAuthzPolicySpec   `json:"spec,omitempty"`
	Status ExtAuthzPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// ExtAuthzPolicyList contains a list of ExtAuthzPolicy
type ExtAuthzPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []ExtAuthzPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&ExtAuthzPolicy{}, &ExtAuthzPolicyList{})
}
