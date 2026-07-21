//go:build !windows

package cmd

import (
	"os"
	"testing"
)

func secureMutationAuditTestParent(t *testing.T, path string) {
	t.Helper()
	if err := os.Chmod(path, 0o700); err != nil {
		t.Fatalf("Chmod(test parent) error = %v", err)
	}
}
