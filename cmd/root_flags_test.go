package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"
)

func TestGlobalFlagsHelp(t *testing.T) {
	var out, errOut bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"--help"})
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute() error = %v, stderr=%s", err, errOut.String())
	}
	for _, flag := range []string{"--debug", "--trace", "--no-color"} {
		if !strings.Contains(out.String(), flag) {
			t.Fatalf("help missing %s:\n%s", flag, out.String())
		}
	}
}

func TestGlobalFlagsWithVersion(t *testing.T) {
	SetVersionInfo("v0.0.0-test", "deadbeef", "2026-06-29")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })

	out, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "--debug", "--trace", "--no-color", "-o", "plain", "version")
	if err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if want := "v0.0.0-test\n"; out != want {
		t.Fatalf("version plain = %q, want %q", out, want)
	}
}
