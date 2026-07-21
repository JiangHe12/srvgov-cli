package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

const auditWarningText = "warning: failed to write audit log:"

func TestAuditCommandWriteFailureWarnsWithoutChangingSuccess(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	blockDefaultAuditPath(t, home)

	stderr, err := executeSrvgovWithStderr(t,
		filepath.Join(home, "config.yaml"),
		"-o", "json",
		"audit", "query", "--path", filepath.Join(home, "missing.log"),
	)
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	if !strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, want audit warning", stderr)
	}
}

func TestExecAuditWriteFailureWarnsWithoutChangingSuccess(t *testing.T) {
	configPath := prepareExecContext(t, false)
	blockDefaultAuditPath(t, filepath.Dir(configPath))
	runner := &fakeSSHRunner{result: sshexec.Result{Stdout: "ok\n"}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	stderr, err := executeSrvgovWithStderr(t, configPath, "-o", "json", "exec", "pwd")
	if err != nil {
		t.Fatalf("exec error = %v", err)
	}
	if !strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, want audit warning", stderr)
	}
}

func TestExecAuditWriteFailureDoesNotReplaceRemoteExitCode(t *testing.T) {
	configPath := prepareExecContext(t, false)
	blockDefaultAuditPath(t, filepath.Dir(configPath))
	runner := &fakeSSHRunner{result: sshexec.Result{ExitCode: 23, Stderr: "failed"}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	stderr, err := executeSrvgovWithStderr(t, configPath, "-o", "json", "exec", "pwd")
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	if !strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, want audit warning", stderr)
	}
}

func TestMissingReasonAuditFailureWarnsWithoutReplacingUsageError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	blockDefaultAuditPath(t, filepath.Dir(configPath))
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	stderr, err := executeSrvgovWithStderr(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"exec", "systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	if !strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, want audit warning", stderr)
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestFileWriteAuditIntentFailureBlocksMutation(t *testing.T) {
	configPath := prepareExecContext(t, false)
	blockDefaultAuditPath(t, filepath.Dir(configPath))
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	stderr, err := executeSrvgovWithStderr(t, configPath,
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app.txt", "--content", "hello",
		"--reason", "update reviewed file",
	)
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	if strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, mutation audit failure must be returned, not downgraded to a warning", stderr)
	}
}

func TestAuditDefaultPathFailureWarnsWithoutChangingSuccess(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
	configPath := filepath.Join(t.TempDir(), "config.yaml")

	stderr, err := executeSrvgovWithStderr(t, configPath,
		"-o", "json",
		"audit", "query", "--path", filepath.Join(t.TempDir(), "missing.log"),
	)
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	if !strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, want DefaultPath audit warning", stderr)
	}
}

func executeSrvgovWithStderr(t *testing.T, configPath string, args ...string) (string, error) {
	t.Helper()
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	command := NewRootCmd()
	command.SetOut(&stdout)
	command.SetErr(&stderr)
	command.SetArgs(append([]string{"--config", configPath}, args...))
	err := command.Execute()
	return stderr.String(), err
}

func blockDefaultAuditPath(t *testing.T, home string) {
	t.Helper()
	path := filepath.Join(home, ".srvgov", "audit.log")
	if err := os.MkdirAll(path, 0o700); err != nil {
		t.Fatalf("MkdirAll(%s) error = %v", path, err)
	}
}
