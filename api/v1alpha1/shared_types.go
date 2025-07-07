package v1alpha1

// Permission rule helper – Allow/Deny lists of subjects.
type PermissionRules struct {
	// Subjects that are explicitly allowed.
	// Use NATS wildcards (>, *).
	// +kubebuilder:validation:Optional
	Allow []string `json:"allow,omitempty"`

	// Subjects that are explicitly denied.
	// +kubebuilder:validation:Optional
	Deny []string `json:"deny,omitempty"`
}
