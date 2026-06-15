package util

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"syscall"
	"time"

	"k8s.io/apimachinery/pkg/util/wait"
	"k8s.io/klog/v2"
)

const kubeOVNTLSWatchInterval = 30 * time.Second

var kubeOVNTLSFiles = []string{SslCACert, SslCertPath, SslKeyPath}

func StartKubeOVNTLSExitWatcher(ctx context.Context) {
	if os.Getenv(EnvSSLEnabled) != "true" {
		return
	}
	WatchKubeOVNTLSFiles(ctx, kubeOVNTLSWatchInterval, func() {
		klog.Info("kube-ovn TLS files changed, exiting for restart")
		os.Exit(0)
	})
}

func RunKubeOVNTLSPID1Watcher(ctx context.Context) {
	if os.Getenv(EnvSSLEnabled) != "true" {
		return
	}
	WatchKubeOVNTLSFiles(ctx, kubeOVNTLSWatchInterval, func() {
		klog.Info("kube-ovn TLS files changed, terminating pid 1 for restart")
		terminatePID1()
	})
	<-ctx.Done()
}

func terminatePID1() {
	if err := syscall.Kill(1, syscall.SIGTERM); err != nil {
		klog.Errorf("failed to terminate pid 1: %v", err)
		os.Exit(1)
	}

	timer := time.NewTimer(30 * time.Second)
	ticker := time.NewTicker(time.Second)

	for {
		select {
		case <-ticker.C:
			if err := syscall.Kill(1, 0); err != nil {
				timer.Stop()
				ticker.Stop()
				os.Exit(0)
			}
		case <-timer.C:
			klog.Warning("pid 1 did not exit after SIGTERM, sending SIGKILL")
			_ = syscall.Kill(1, syscall.SIGKILL)
			ticker.Stop()
			os.Exit(0)
		}
	}
}

func WatchKubeOVNTLSFiles(ctx context.Context, interval time.Duration, onChange func()) {
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
