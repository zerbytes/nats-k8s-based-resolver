package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=natsusers,shortName=nu,scope=Namespaced
// +kubebuilder:printcolumn:name="Account",type=string,JSONPath=".spec.accountRef.name"
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=".status.ready"
// NatsUser represents a user credential within a NATS account.
type NatsUser struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NatsUserSpec   `json:"spec,omitempty"`
	Status NatsUserStatus `json:"status,omitempty"`
}

type NatsUserSpec struct {
	// AccountRef references the parent account.
	AccountRef corev1.ObjectReference `json:"accountRef"`

	// Expiration RFC3339 time - optional, infinite if omitted.
	// +optional
	Expiration *metav1.Time `json:"expiration,omitempty"`

	// TODO: wire permissions/limits into JWT generation.

	// Permissions placeholder - will be mapped to publish/subscribe
	// permissions in the user JWT.
	// +optional
	Permissions *UserPermissions `json:"permissions,omitempty"`
}

type UserPermissions struct {
	// TODO: add fields like Pub.Allow, Sub.Deny etc.
}

type NatsUserStatus struct {
	Ready         bool   `json:"ready,omitempty"`
	UserPublicKey string `json:"userPublicKey,omitempty"`
	SecretName    string `json:"secretName,omitempty"`
}

// +kubebuilder:object:root=true
type NatsUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NatsUser `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NatsAccount{}, &NatsAccountList{})
	SchemeBuilder.Register(&NatsUser{}, &NatsUserList{})
}
