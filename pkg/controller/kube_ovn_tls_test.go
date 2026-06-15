package controller

import (
	"context"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

func TestReconcileKubeOVNTLSAddsBaselineAnnotation(t *testing.T) {
	const namespace = "kube-system"
	data, hash, err := generateKubeOVNTLSData(time.Now(), kubeOVNTLSCADuration, kubeOVNTLSCertDuration)
	if err != nil {
		t.Fatalf("generateKubeOVNTLSData returned error: %v", err)
	}
	client := fake.NewSimpleClientset(
		testKubeOVNTLSSecret(namespace, data, nil),
	)
	c := &Controller{config: &Configuration{KubeClient: client, PodNamespace: namespace}}

	if err = c.reconcileKubeOVNTLS(context.Background()); err != nil {
		t.Fatalf("reconcileKubeOVNTLS returned error: %v", err)
	}

	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), kubeOVNTLSSecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get kube-ovn-tls secret: %v", err)
	}
	if got := secret.Annotations[kubeOVNTLSCertHashAnnotation]; got != hash {
		t.Fatalf("cert hash annotation = %q, want %q", got, hash)
	}
}

func TestReconcileKubeOVNTLSRotatesExpiredSecret(t *testing.T) {
	const namespace = "kube-system"
	expiredData, oldHash, err := generateKubeOVNTLSData(time.Now().Add(-20*24*time.Hour), 10*24*time.Hour, 10*24*time.Hour)
	if err != nil {
		t.Fatalf("generateKubeOVNTLSData returned error: %v", err)
	}
	client := fake.NewSimpleClientset(
		testKubeOVNTLSSecret(namespace, expiredData, map[string]string{
			kubeOVNTLSCertHashAnnotation: oldHash,
		}),
	)
	c := &Controller{config: &Configuration{KubeClient: client, PodNamespace: namespace}}

	if err = c.reconcileKubeOVNTLS(context.Background()); err != nil {
		t.Fatalf("reconcileKubeOVNTLS returned error: %v", err)
	}

	secret, err := client.CoreV1().Secrets(namespace).Get(context.Background(), kubeOVNTLSSecretName, metav1.GetOptions{})
	if err != nil {
		t.Fatalf("failed to get kube-ovn-tls secret: %v", err)
	}
	newHash := secret.Annotations[kubeOVNTLSCertHashAnnotation]
	if newHash == "" || newHash == oldHash {
		t.Fatalf("cert hash annotation = %q, want non-empty value different from %q", newHash, oldHash)
	}
}

func testKubeOVNTLSSecret(namespace string, data map[string][]byte, annotations map[string]string) *corev1.Secret {
	return &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:        kubeOVNTLSSecretName,
			Namespace:   namespace,
			Annotations: annotations,
		},
		Data: data,
	}
}
