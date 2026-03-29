package v1alpha1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// RateLimitPolicySpec defines the desired state of RateLimitPolicy
type RateLimitPolicySpec struct {
	MaxRequestsPerSecond int32 `json:"max_requests_per_second"`
}

// RateLimitPolicyStatus defines the observed state of RateLimitPolicy
type RateLimitPolicyStatus struct {
}

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// RateLimitPolicy is the Schema for the ratelimitpolicies API
type RateLimitPolicy struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   RateLimitPolicySpec   `json:"spec,omitempty"`
	Status RateLimitPolicyStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true
// RateLimitPolicyList contains a list of RateLimitPolicy
type RateLimitPolicyList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []RateLimitPolicy `json:"items"`
}

func init() {
	SchemeBuilder.Register(&RateLimitPolicy{}, &RateLimitPolicyList{})
}
