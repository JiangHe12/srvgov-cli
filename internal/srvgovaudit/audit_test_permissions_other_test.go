//go:build !windows

package srvgovaudit

import (
	"os"
	"testing"
)

func secureAuditTestDirectory(t *testing.T, path string) {
	t.Helper()
	if err := os.Mkdir(path, 0o700); err != nil {
		t.Fatalf("create private audit test directory: %v", err)
	}
}
