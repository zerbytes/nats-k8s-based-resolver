package v1alpha1

import (
	"time"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:path=natsaccounts,shortName=na,scope=Namespaced
// +kubebuilder:printcolumn:name="JetStream",type=boolean,JSONPath=".spec.jetStreamEnabled"
// +kubebuilder:printcolumn:name="Ready",type=boolean,JSONPath=".status.ready"
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=".metadata.creationTimestamp"

// NatsAccount is the Schema for the accounts API
type NatsAccount struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	Spec   NatsAccountSpec   `json:"spec,omitempty"`
	Status NatsAccountStatus `json:"status,omitempty"`
}

type NatsAccountSpec struct {
	// JetStreamEnabled toggles JetStream for the account.
	// +optional
	JetStreamEnabled bool `json:"jetStreamEnabled,omitempty"`

	// Limits for the account (connections, subscriptions, etc.).
	// All fields optional - if omitted NATS defaults apply.
	// +optional
	Limits *AccountLimits `json:"limits,omitempty"`

	// Permissions for the account.
	// +optional
	Permissions *AccountPermissions `json:"permissions,omitempty"`

	// Expiration specifies an RFC3339 timestamp when the account JWT
	// should expire. If omitted the JWT does not expire.
	// +optional
	Expiration *metav1.Time `json:"expiration,omitempty"`

	// SystemAccount marks this account as the NATS $SYS account.
	// Automatically set by the operator; users should not set this.
	// +kubebuilder:default=false
	SystemAccount bool `json:"systemAccount,omitempty"`
}

type AccountLimits struct {
	// +optional
	MaxConnections *int `json:"maxConnections,omitempty"`
	// +optional
	MaxSubs *int `json:"maxSubs,omitempty"`
	// +optional
	MaxData *int `json:"maxData,omitempty"`
	// +optional
	MaxPayload *int `json:"maxPayload,omitempty"`
	// +optional
	MaxDiskStorage *int `json:"maxDiskStorage,omitempty"`
	// +optional
	MaxMemoryStorage *int `json:"maxMemoryStorage,omitempty"`
}

type AccountPermissions struct {
	// Publish defines the permissions for publishing messages.
	Publish PermissionRules `json:"publish,omitempty"`
	// Subscribe defines the permissions for subscribing to messages.
	Subscribe PermissionRules `json:"subscribe,omitempty"`
	// Response defines the permissions for responding to messages.
	Response *ResponsePermissions `json:"response,omitempty"`
}

type ResponsePermissions struct {
	MaxMsgs int           `json:"max,omitempty"`
	Expires time.Duration `json:"ttl,omitempty"`
}

type NatsAccountStatus struct {
	// Ready indicates that the JWT secret was successfully created.
	Ready bool `json:"ready,omitempty"`

	// AccountPublicKey contains the public NKey of the account.
	AccountPublicKey string `json:"accountPublicKey,omitempty"`

	// SecretName referencing the Kubernetes Secret with the JWT.
	SecretName string `json:"secretName,omitempty"`
}

// +kubebuilder:object:root=true

// NatsAccountList contains a list of NatsAccount
// kubebuilder marker generates list type automatically.
type NatsAccountList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata,omitempty"`
	Items           []NatsAccount `json:"items"`
}

func init() {
	SchemeBuilder.Register(&NatsAccount{}, &NatsAccountList{})
}
