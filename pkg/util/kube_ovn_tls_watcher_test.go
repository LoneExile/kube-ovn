package util

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestWatchKubeOVNTLSFilesCallsOnChange(t *testing.T) {
	dir := t.TempDir()
	oldFiles := kubeOVNTLSFiles
	kubeOVNTLSFiles = []string{
		filepath.Join(dir, "cacert"),
		filepath.Join(dir, "cert"),
		filepath.Join(dir, "key"),
	}
	t.Cleanup(func() {
		kubeOVNTLSFiles = oldFiles
	})

	for _, path := range kubeOVNTLSFiles {
		if err := os.WriteFile(path, []byte("old"), 0o600); err != nil {
			t.Fatalf("failed to write %s: %v", path, err)
		}
	}

	changed := make(chan struct{}, 1)
	WatchKubeOVNTLSFiles(t.Context(), 10*time.Millisecond, func() {
		changed <- struct{}{}
	})

	if err := os.WriteFile(kubeOVNTLSFiles[1], []byte("new"), 0o600); err != nil {
		t.Fatalf("failed to update cert: %v", err)
	}

	select {
	case <-changed:
	case <-time.After(time.Second):
		t.Fatal("watcher did not call onChange after TLS file update")
	}
}
