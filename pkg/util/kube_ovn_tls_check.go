package util

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

const kubeOVNTLSCheckInterval = 30 * time.Second

var kubeOVNTLSFiles = []string{SslCACert, SslCertPath, SslKeyPath}
var kubeOVNTLSProbeHashFile = "/tmp/kube-ovn-tls.hash"

func StartKubeOVNTLSExitCheck(ctx context.Context) {
	if os.Getenv(EnvSSLEnabled) != "true" {
		return
	}
	CheckKubeOVNTLSFilesPeriodically(ctx, kubeOVNTLSCheckInterval, func() {
		klog.Info("kube-ovn TLS files changed, exiting for restart")
		os.Exit(0)
	})
}

func CheckKubeOVNTLSFilesChanged() error {
	if os.Getenv(EnvSSLEnabled) != "true" {
		return nil
	}
	hash, err := hashKubeOVNTLSFiles()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(kubeOVNTLSProbeHashFile)
	if os.IsNotExist(err) {
		return os.WriteFile(kubeOVNTLSProbeHashFile, []byte(hash), 0o600)
	}
	if err != nil {
		return fmt.Errorf("read %s: %w", kubeOVNTLSProbeHashFile, err)
	}
	if string(data) != hash {
		return errors.New("kube-ovn TLS files changed")
	}
	return nil
}

func CheckKubeOVNTLSFilesPeriodically(ctx context.Context, interval time.Duration, onChange func()) {
	lastHash, err := hashKubeOVNTLSFiles()
	if err != nil {
		klog.Infof("waiting for kube-ovn TLS files: %v", err)
	}

	go wait.UntilWithContext(ctx, func(_ context.Context) {
		currentHash, err := hashKubeOVNTLSFiles()
		if err != nil {
			klog.Infof("waiting for kube-ovn TLS files: %v", err)
			return
		}
		if lastHash == "" {
			lastHash = currentHash
			return
		}
		if currentHash == lastHash {
			return
		}
		onChange()
	}, interval)
}

func hashKubeOVNTLSFiles() (string, error) {
	h := sha256.New()
	for _, path := range kubeOVNTLSFiles {
		data, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("read %s: %w", path, err)
		}
		h.Write([]byte(path))
		h.Write([]byte{0})
		h.Write(data)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
