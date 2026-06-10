package cmd

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

func TestExitCodeContract(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		configPath := prepareExecContext(t, false)
		_, err := executeRoot(t, configPath, "--yes", "exec", "touch ./ready")
		assertAppError(t, err, apperrors.CodeUsageError, 1)
	})

	t.Run("authorization denied", func(t *testing.T) {
		configPath := prepareExecContext(t, false)
		_, err := executeRoot(t, configPath,
			"--non-interactive",
			"exec", "--reason", "prepare deploy", "touch ./ready",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	})

	t.Run("remote nonzero", func(t *testing.T) {
		configPath := prepareExecContext(t, false)
		runner := &fakeSSHRunner{result: sshexec.Result{ExitCode: 19}}
		restore := replaceSSHRunner(runner)
		t.Cleanup(restore)
		_, err := executeRoot(t, configPath, "-o", "json", "exec", "pwd")
		assertAppError(t, err, apperrors.CodeBackendError, 7)
	})
}

func TestJSONOutputContract(t *testing.T) {
	configPath := prepareExecContext(t, false)
	cases := []struct {
		name      string
		args      []string
		wantArray bool
	}{
		{name: "exec dry-run object", args: []string{"-o", "json", "exec", "--dry-run", "pwd"}},
		{name: "capabilities object", args: []string{"-o", "json", "capabilities"}},
		{name: "ctx list array", args: []string{"-o", "json", "ctx", "list"}, wantArray: true},
		{name: "ctx role list array", args: []string{"-o", "json", "ctx", "role", "list", "dev"}, wantArray: true},
		{name: "audit query object", args: []string{"-o", "json", "audit", "query"}},
		{name: "audit verify object", args: []string{"-o", "json", "audit", "verify", "--path", "testdata/missing-audit.log"}},
		{name: "audit prune object", args: []string{"-o", "json", "audit", "prune", "--path", "testdata/missing-audit.log", "--keep-last", "1"}},
		{name: "doctor object", args: []string{"-o", "json", "doctor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := executeRoot(t, configPath, tc.args...)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			if !json.Valid([]byte(output)) {
				t.Fatalf("invalid JSON: %q", output)
			}
			var value any
			if err := json.Unmarshal([]byte(output), &value); err != nil {
				t.Fatalf("Unmarshal() error = %v", err)
			}
			_, isArray := value.([]any)
			_, isObject := value.(map[string]any)
			if tc.wantArray && !isArray {
				t.Fatalf("top-level JSON = %T, want array", value)
			}
			if !tc.wantArray && !isObject {
				t.Fatalf("top-level JSON = %T, want object", value)
			}
		})
	}
}

func TestVersionDefaultsRemainLocal(t *testing.T) {
	SetVersionInfo("dev", "", "")
	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "-o", "json", "version")
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	if !json.Valid([]byte(output)) {
		t.Fatalf("invalid JSON: %q", output)
	}
}
