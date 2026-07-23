package sshexec

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestMain(m *testing.M) {
	if err := configureTestProcessSecurity(); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "configure test process security: %v\n", err)
		os.Exit(1)
	}
	home, err := os.MkdirTemp("", "sshexec-test-home-")
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
	if err := secureTestHome(home); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "secure isolated test home: %v\n", err)
		_ = os.RemoveAll(home)
		os.Exit(1)
	}

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
