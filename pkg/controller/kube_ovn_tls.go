package controller

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/client-go/util/retry"
	"k8s.io/klog/v2"

	"github.com/kubeovn/kube-ovn/pkg/util"
)

const (
	kubeOVNTLSSecretName              = "kube-ovn-tls"
	kubeOVNTLSDefaultRotationInterval = 24 * time.Hour
	kubeOVNTLSCADuration              = 10 * 365 * 24 * time.Hour
	kubeOVNTLSCertDuration            = 10 * 365 * 24 * time.Hour
	kubeOVNTLSCommonName              = "ovn"

	kubeOVNTLSCertHashAnnotation = "kube-ovn.io/kube-ovn-tls-cert-hash"
)

func (c *Controller) startKubeOVNTLSManager(ctx context.Context) {
	if os.Getenv(util.EnvSSLEnabled) != "true" {
		return
	}
	interval, err := kubeOVNTLSRotationInterval()
	if err != nil {
		klog.Errorf("failed to parse kube-ovn TLS rotation interval: %v", err)
		return
	}
	if interval <= 0 {
		return
	}

	go wait.UntilWithContext(ctx, func(ctx context.Context) {
		if err := c.reconcileKubeOVNTLS(ctx); err != nil {
			klog.Errorf("failed to reconcile kube-ovn TLS secret: %v", err)
		}
	}, interval)
}

func kubeOVNTLSRotationInterval() (time.Duration, error) {
	value := strings.TrimSpace(os.Getenv(util.EnvKubeOVNTLSRotationInterval))
	if value == "" {
		return kubeOVNTLSDefaultRotationInterval, nil
	}
	interval, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("parse %s=%q: %w", util.EnvKubeOVNTLSRotationInterval, value, err)
	}
	return interval, nil
}

func (c *Controller) reconcileKubeOVNTLS(ctx context.Context) error {
	secret, err := c.config.KubeClient.CoreV1().Secrets(c.config.PodNamespace).Get(ctx, kubeOVNTLSSecretName, metav1.GetOptions{})
	if apierrors.IsNotFound(err) {
		data, hash, genErr := generateKubeOVNTLSData(time.Now(), kubeOVNTLSCADuration, kubeOVNTLSCertDuration)
		if genErr != nil {
			return genErr
		}
		secret = &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      kubeOVNTLSSecretName,
				Namespace: c.config.PodNamespace,
				Annotations: map[string]string{
					kubeOVNTLSCertHashAnnotation: hash,
				},
			},
			Data: data,
		}
		if _, err = c.config.KubeClient.CoreV1().Secrets(c.config.PodNamespace).Create(ctx, secret, metav1.CreateOptions{}); err != nil {
			return err
		}
		return nil
	}
	if err != nil {
		return err
	}

	// kube-ovn-tls keeps the legacy cacert/cert/key schema. The manager only
	// adds metadata on first adoption so upgrades do not restart OVN workloads.
	hash, err := kubeOVNTLSHash(secret.Data)
	if err != nil {
		return err
	}

	if secret.Annotations[kubeOVNTLSCertHashAnnotation] != hash {
		if err = c.setKubeOVNTLSHash(ctx, hash); err != nil {
			return err
		}
	}

	renew, err := kubeOVNTLSNeedsRenewal(time.Now(), secret.Data)
	if err != nil {
		return err
	}
	if renew {
		data, newHash, genErr := generateKubeOVNTLSData(time.Now(), kubeOVNTLSCADuration, kubeOVNTLSCertDuration)
		if genErr != nil {
			return genErr
		}
		if err = c.updateKubeOVNTLSSecretData(ctx, data, newHash); err != nil {
			return err
		}
	}

	return nil
}

func kubeOVNTLSNeedsRenewal(now time.Time, data map[string][]byte) (bool, error) {
	cert, err := parseKubeOVNTLSCert(data)
	if err != nil {
		return false, err
	}
	refreshTime := cert.NotBefore.Add(cert.NotAfter.Sub(cert.NotBefore) / 2)
	return !now.Before(refreshTime), nil
}

func parseKubeOVNTLSCert(data map[string][]byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(data["cert"])
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("kube-ovn-tls cert must be a PEM certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse kube-ovn-tls cert: %w", err)
	}
	return cert, nil
}

func generateKubeOVNTLSData(now time.Time, caDuration, certDuration time.Duration) (map[string][]byte, string, error) {
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("generate kube-ovn-tls CA key: %w", err)
	}
	caSerial, err := randomSerialNumber()
	if err != nil {
		return nil, "", err
	}
	caTemplate := &x509.Certificate{
		SerialNumber: caSerial,
		Subject: pkix.Name{
			CommonName:   "ovn-ca",
			Organization: []string{"kube-ovn"},
		},
		NotBefore:             now.Add(-time.Second),
		NotAfter:              now.Add(caDuration),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		return nil, "", fmt.Errorf("create kube-ovn-tls CA certificate: %w", err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		return nil, "", fmt.Errorf("parse generated kube-ovn-tls CA certificate: %w", err)
	}

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, "", fmt.Errorf("generate kube-ovn-tls key: %w", err)
	}
	serial, err := randomSerialNumber()
	if err != nil {
		return nil, "", err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   kubeOVNTLSCommonName,
			Organization: []string{"kube-ovn"},
		},
		NotBefore:             now.Add(-time.Second),
		NotAfter:              now.Add(certDuration),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		BasicConstraintsValid: true,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, "", fmt.Errorf("create kube-ovn-tls certificate: %w", err)
	}

	data := map[string][]byte{
		"cacert": encodeCertificate(caDER),
		"cert":   encodeCertificate(certDER),
		"key":    encodeRSAPrivateKey(key),
	}
	hash, err := kubeOVNTLSHash(data)
	if err != nil {
		return nil, "", err
	}
	return data, hash, nil
}

func kubeOVNTLSHash(data map[string][]byte) (string, error) {
	for _, key := range []string{"cacert", "cert", "key"} {
		if len(data[key]) == 0 {
			return "", fmt.Errorf("kube-ovn-tls missing %s", key)
		}
	}
	h := sha256.New()
	for _, key := range []string{"cacert", "cert", "key"} {
		h.Write([]byte(key))
		h.Write([]byte{0})
		h.Write(data[key])
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func randomSerialNumber() (*big.Int, error) {
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial number: %w", err)
	}
	return serial, nil
}

func encodeCertificate(der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func encodeRSAPrivateKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}

func (c *Controller) updateKubeOVNTLSSecretData(ctx context.Context, data map[string][]byte, hash string) error {
	secrets := c.config.KubeClient.CoreV1().Secrets(c.config.PodNamespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret, err := secrets.Get(ctx, kubeOVNTLSSecretName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		secret = secret.DeepCopy()
		secret.Data = data
		setKubeOVNTLSAnnotation(secret, kubeOVNTLSCertHashAnnotation, hash)
		_, err = secrets.Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
}

func (c *Controller) setKubeOVNTLSHash(ctx context.Context, hash string) error {
	secrets := c.config.KubeClient.CoreV1().Secrets(c.config.PodNamespace)
	return retry.RetryOnConflict(retry.DefaultRetry, func() error {
		secret, err := secrets.Get(ctx, kubeOVNTLSSecretName, metav1.GetOptions{})
		if err != nil {
			return err
		}
		secret = secret.DeepCopy()
		setKubeOVNTLSAnnotation(secret, kubeOVNTLSCertHashAnnotation, hash)
		_, err = secrets.Update(ctx, secret, metav1.UpdateOptions{})
		return err
	})
}

func setKubeOVNTLSAnnotation(secret *corev1.Secret, key, value string) {
	if secret.Annotations == nil {
		secret.Annotations = map[string]string{}
	}
	secret.Annotations[key] = value
}
