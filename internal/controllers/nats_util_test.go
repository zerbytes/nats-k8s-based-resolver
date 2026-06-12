package controllers

import (
	"testing"

	"k8s.io/apimachinery/pkg/util/validation"
)

func TestAccountLabelValue(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "sys account",
			input:    NatsSYSAcc,
			expected: NatsSYSAccountLabelValue,
		},
		{
			name:     "regular account",
			input:    "account-1",
			expected: "account-1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			got := accountLabelValue(tt.input)
			if got != tt.expected {
				t.Fatalf("accountLabelValue(%q) = %q, want %q", tt.input, got, tt.expected)
			}

			if errs := validation.IsValidLabelValue(got); len(errs) != 0 {
				t.Fatalf("accountLabelValue(%q) returned invalid label value %q: %v", tt.input, got, errs)
			}
		})
	}
}
