package controllers

import (
	"bytes"
	"context"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
)

func getSecret(ctx context.Context, c client.Client, nn types.NamespacedName, sec *corev1.Secret) (bool, error) {
	if err := c.Get(ctx, nn, sec); err != nil {
		if errors.IsNotFound(err) {
			return false, nil
		}
		return false, err
	}

	return true, nil
}

func prepareManagedSecret(sec *corev1.Secret, owner client.Object, scheme *runtime.Scheme, name, namespace string, labels map[string]string, data map[string][]byte) error {
	sec.Type = corev1.SecretTypeOpaque
	sec.Name = name
	sec.Namespace = namespace
	sec.Data = data

	if sec.Labels == nil {
		sec.Labels = map[string]string{}
	}
	sec.Labels["app.kubernetes.io/managed-by"] = AccountOperatorName
	for k, v := range labels {
		sec.Labels[k] = v
	}

	return controllerutil.SetControllerReference(owner, sec, scheme)
}

func updateSecretData(sec *corev1.Secret, desired map[string][]byte) bool {
	if sec.Data == nil {
		sec.Data = map[string][]byte{}
	}

	dirty := false
	for k, v := range desired {
		if !bytes.Equal(sec.Data[k], v) {
			sec.Data[k] = v
			dirty = true
		}
	}

	return dirty
}
