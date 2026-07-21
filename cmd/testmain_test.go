package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	home, err := os.MkdirTemp("", "srvgov-cli-test-home-")
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create isolated test home: %v\n", err)
		os.Exit(1)
	}
	resolvedHome, err := filepath.EvalSymlinks(home)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "resolve isolated test home: %v\n", err)
		_ = os.RemoveAll(home)
		os.Exit(1)
	}
	home = resolvedHome

	previousEnv := make(map[string]*string, 5)
	for _, name := range []string{"HOME", "USERPROFILE", "TMPDIR", "TEMP", "TMP"} {
		if value, ok := os.LookupEnv(name); ok {
			savedValue := value
			previousEnv[name] = &savedValue
		} else {
			previousEnv[name] = nil
		}
		_ = os.Setenv(name, home)
	}
	if err := createPrivateMutationAuditDirectory(filepath.Join(home, ".srvgov")); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "create isolated audit directory: %v\n", err)
		_ = os.RemoveAll(home)
		os.Exit(1)
	}

	code := m.Run()

	for name, value := range previousEnv {
		if value == nil {
			_ = os.Unsetenv(name)
		} else {
			_ = os.Setenv(name, *value)
		}
	}
	_ = os.RemoveAll(home)
	os.Exit(code)
}
