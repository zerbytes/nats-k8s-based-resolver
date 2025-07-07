package v1alpha1

import (
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:pruning:PreserveUnknownFields
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

	// Limits applied to this user (payload, subs, …).
	// +optional
	Limits *UserLimits `json:"limits,omitempty"`

	// Permissions (publish / subscribe allow|deny lists).
	// +optional
	Permissions *UserPermissions `json:"permissions,omitempty"`
}

// UserLimits captures resource ceilings for an individual user.
// +kubebuilder:object:generate=true
// +kubebuilder:validation:Optional
type UserLimits struct {
	// MaxPayload defines the maximum message payload a user can publish (bytes).
	// +optional
	MaxPayload *int64 `json:"maxPayload,omitempty"`

	// MaxSubs caps how many subscriptions a connection can register.
	// +optional
	MaxSubs *int64 `json:"maxSubs,omitempty"`

	// MaxData defines the maximum data a user can store in the server (bytes).
	// +optional
	MaxData *int64 `json:"maxData,omitempty"`
}

type UserPermissions struct {
	// Publish rules
	// +optional
	Publish PermissionRules `json:"publish,omitempty"`

	// Subscribe rules
	// +optional
	Subscribe PermissionRules `json:"subscribe,omitempty"`
}

type NatsUserStatus struct {
	// Ready indicates that the user creds secret was successfully created.
	Ready bool `json:"ready,omitempty"`

	// UserPublicKey contains the public NKey of the user.
	UserPublicKey string `json:"userPublicKey,omitempty"`

	// SecretName referencing the Kubernetes Secret with the creds.
	SecretName string `json:"secretName,omitempty"`
}

// +kubebuilder:object:root=true
type NatsUserList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NatsUser `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NatsUser{}, &NatsUserList{})
}
