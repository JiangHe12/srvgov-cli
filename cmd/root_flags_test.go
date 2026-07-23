package cmd

import (
	"bytes"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
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
	for _, flag := range []string{
		"--debug",
		"--trace",
		"--no-color",
		"--allow-context-change",
		"--allow-context-delete",
		"--allow-role-change",
		"--allow-audit-prune",
	} {
		if !strings.Contains(out.String(), flag) {
			t.Fatalf("help missing %s:\n%s", flag, out.String())
		}
	}
}

func TestGlobalFlagsWithVersion(t *testing.T) {
	SetVersionInfo("v0.0.0-test", "deadbeef", "2026-06-29")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })

	for _, args := range [][]string{
		{"--debug", "--trace", "--no-color", "-o", "plain", "version"},
		{"--debug", "--trace", "--no-color", "-o", "plain", "--version"},
	} {
		out, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), args...)
		if err != nil {
			t.Fatalf("Execute(%v) error = %v", args, err)
		}
		if want := "v0.0.0-test\n"; out != want {
			t.Fatalf("version plain = %q, want %q", out, want)
		}
	}
}

func TestInvalidOutputFormatFailsBeforeCommandOutput(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"capabilities", "version"} {
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			output, err := executeRoot(
				t,
				filepath.Join(t.TempDir(), "config.yaml"),
				"-o",
				"definitely-invalid",
				command,
			)
			assertAppError(t, err, apperrors.CodeUsageError, 1)
			if output != "" {
				t.Fatalf("output = %q, want empty", output)
			}
		})
	}
}

func TestInvalidOutputFormatFailsBeforeRootVersionOutput(t *testing.T) {
	t.Parallel()

	output, err := executeRoot(
		t,
		filepath.Join(t.TempDir(), "config.yaml"),
		"-o",
		"definitely-invalid",
		"--version",
	)
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	if output != "" {
		t.Fatalf("output = %q, want empty", output)
	}
}
