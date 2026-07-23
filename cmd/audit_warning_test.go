package cmd

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

const auditWarningText = "warning: failed to write audit log:"

func TestAuditCommandRequiredReadIntentFailureReturnsLocalIO(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	blockDefaultAuditPath(t, home)

	stderr, err := executeSrvgovWithStderr(t,
		filepath.Join(home, "config.yaml"),
		"-o", "json",
		"audit", "query", "--path", filepath.Join(home, "missing.log"),
	)
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
	if strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, required audit failure must be returned", stderr)
	}
}

func TestAuditCommandRequiredReadOutcomeFailureWithholdsResult(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := createPrivateMutationAuditDirectory(filepath.Join(home, ".srvgov")); err != nil {
		t.Fatalf("create audit directory: %v", err)
	}

	appendCalls := 0
	f := &cliFlags{
		Output:          "json",
		trustedOperator: "tester@localhost",
		mutationAudit: &mutationAuditRuntime{
			appendEventWithResult: func(string, srvgovaudit.Event, coreaudit.Options) (coreaudit.AppendResult, error) {
				appendCalls++
				if appendCalls == 1 {
					return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
				}
				return coreaudit.AppendResult{State: coreaudit.AppendCommitNotCommitted}, errors.New("injected outcome failure")
			},
			now:    func() time.Time { return time.Unix(1, 0).UTC() },
			random: bytes.NewReader(make([]byte, 16)),
		},
	}
	var stdout, stderr bytes.Buffer
	root := newRootCmdWith(f)
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{
		"--config", filepath.Join(home, "config.yaml"),
		"-o", "json",
		"audit", "query", "--path", filepath.Join(home, "missing.log"),
	})
	err := root.Execute()
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
	if appendCalls != 2 {
		t.Fatalf("audit append calls = %d, want intent and outcome", appendCalls)
	}
	if stdout.Len() != 0 {
		t.Fatalf("audit query result was released: %q", stdout.String())
	}
}

func TestExecRequiredReadAuditIntentFailureBlocksSSH(t *testing.T) {
	configPath := prepareExecContext(t, false)
	blockDefaultAuditPath(t, filepath.Dir(configPath))
	runner := &fakeSSHRunner{result: sshexec.Result{Stdout: "ok\n"}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	stderr, err := executeSrvgovWithStderr(t, configPath, "-o", "json", "exec", "pwd")
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	if strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, required audit failure must be returned", stderr)
	}
}

func TestExecRequiredReadAuditOutcomeFailureWithholdsResult(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{result: sshexec.Result{Stdout: "must-not-be-released\n"}}
	previous := newSSHRunner
	newSSHRunner = func(notify func(sshexec.Pin)) sshRunner {
		notify(sshexec.Pin{
			Address:     "must-not-be-released.example:22",
			KeyType:     "ssh-ed25519",
			Fingerprint: "SHA256:must-not-be-released",
		})
		return runner
	}
	t.Cleanup(func() { newSSHRunner = previous })

	appendCalls := 0
	f := &cliFlags{
		Output:          "table",
		trustedOperator: "tester@localhost",
		mutationAudit: &mutationAuditRuntime{
			appendEventWithResult: func(string, srvgovaudit.Event, coreaudit.Options) (coreaudit.AppendResult, error) {
				appendCalls++
				if appendCalls == 1 {
					return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
				}
				return coreaudit.AppendResult{State: coreaudit.AppendCommitNotCommitted}, errors.New("injected outcome failure")
			},
			now:    func() time.Time { return time.Unix(1, 0).UTC() },
			random: bytes.NewReader(make([]byte, 16)),
		},
	}
	var stdout, stderr bytes.Buffer
	root := newRootCmdWith(f)
	root.SetOut(&stdout)
	root.SetErr(&stderr)
	root.SetArgs([]string{"--config", configPath, "-o", "json", "exec", "pwd"})
	err := root.Execute()
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
	if appendCalls != 2 {
		t.Fatalf("audit append calls = %d, want intent and outcome", appendCalls)
	}
	if stdout.Len() != 0 || strings.Contains(stderr.String(), "must-not-be-released") ||
		strings.Contains(stderr.String(), "pinned SSH host key") {
		t.Fatalf("read result was released: stdout=%q stderr=%q", stdout.String(), stderr.String())
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

func TestAuditDefaultPathFailureReturnsLocalIO(t *testing.T) {
	t.Setenv("HOME", "")
	t.Setenv("USERPROFILE", "")
	t.Setenv("HOMEDRIVE", "")
	t.Setenv("HOMEPATH", "")
	configPath := filepath.Join(t.TempDir(), "config.yaml")

	stderr, err := executeSrvgovWithStderr(t, configPath,
		"-o", "json",
		"audit", "query", "--path", filepath.Join(t.TempDir(), "missing.log"),
	)
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
	if strings.Contains(stderr, auditWarningText) {
		t.Fatalf("stderr = %q, required audit failure must be returned", stderr)
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
