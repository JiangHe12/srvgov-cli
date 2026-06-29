package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/audit"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type fakeSSHRunner struct {
	result  sshexec.Result
	err     error
	calls   int
	command string
}

func (f *fakeSSHRunner) Run(_ context.Context, _ string, _ srvgovctx.Context, command string) (sshexec.Result, error) {
	f.calls++
	f.command = command
	return f.result, f.err
}

func TestExecDryRunClassifiesWithoutConnecting(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "exec", "--dry-run", "mystery-command")
	if err != nil {
		t.Fatalf("exec dry-run error = %v", err)
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	got := decodeJSONData[execDryRunView](t, output, "ExecDryRun")
	if !got.DryRun || got.RiskTier != "R2" || got.EffectiveRiskTier != "R2" {
		t.Fatalf("dry-run view = %#v", got)
	}
	if strings.Join(got.RequiredAuthorization, ",") != "--yes,--ticket" {
		t.Fatalf("required authorization = %#v", got.RequiredAuthorization)
	}
	if _, err := os.Stat(defaultAuditPath(t)); !os.IsNotExist(err) {
		t.Fatalf("dry-run audit file error = %v, want not exist", err)
	}
}

func TestExecRequiresReasonBeforeAuthorization(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"exec", "systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	message := apperrors.AsAppError(err).Message
	for _, flag := range []string{"--reason", "--yes", "--ticket"} {
		if !strings.Contains(message, flag) {
			t.Fatalf("message = %q, want %s", message, flag)
		}
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	events := readAuditEvents(t)
	if len(events) != 1 ||
		events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied ||
		events[0].Status != srvgovaudit.StatusDenied ||
		events[0].RiskTier != "R2" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestMissingReasonReportsCompleteRequirementsByTier(t *testing.T) {
	tests := []struct {
		name    string
		command string
		flags   []string
	}{
		{name: "R1", command: "touch ./ready", flags: []string{"--reason", "--yes"}},
		{name: "R2", command: "systemctl restart nginx", flags: []string{"--reason", "--yes", "--ticket"}},
		{name: "R3", command: "rm -rf /tmp/release", flags: []string{"--reason", "--yes", "--ticket", "--allow-destructive"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := prepareExecContext(t, false)
			runner := &fakeSSHRunner{}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			_, err := executeRoot(t, configPath, "--non-interactive", "exec", tt.command)
			assertAppError(t, err, apperrors.CodeUsageError, 1)
			message := apperrors.AsAppError(err).Message
			for _, flag := range tt.flags {
				if !strings.Contains(message, flag) {
					t.Fatalf("message = %q, want %s", message, flag)
				}
			}
			if runner.calls != 0 {
				t.Fatalf("runner calls = %d, want 0", runner.calls)
			}
		})
	}
}

func TestExecProtectedContextRaisesRisk(t *testing.T) {
	configPath := prepareExecContext(t, true)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes",
		"exec", "--reason", "prepare deploy", "touch ./ready",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	events := readAuditEvents(t)
	if len(events) != 1 || events[0].RiskTier != "R2" || events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestExecR3RequiresAllowAndAuditsDenial(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"exec", "--reason", "remove failed deployment", "rm -rf /tmp/release",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	events := readAuditEvents(t)
	if len(events) != 1 {
		t.Fatalf("audit event count = %d", len(events))
	}
	event := events[0]
	if event.EventType != srvgovaudit.EventTypeAuthorizationDenied ||
		event.Status != srvgovaudit.StatusDenied ||
		event.RiskTier != "R3" ||
		event.Ticket != "OPS-42" {
		t.Fatalf("audit event = %#v", event)
	}
}

func TestExecRedactsCallerOutputAndAudit(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{result: sshexec.Result{
		Stdout:   "PRIVATE_KEY=stdout-private API_KEY=stdout-api STRIPE_KEY=stdout-stripe cookie=stdout-cookie\n",
		Stderr:   "credential=stderr-credential sessionid=stderr-session\n",
		ExitCode: 0,
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "exec", "echo privatekey=command-private")
	if err != nil {
		t.Fatalf("exec error = %v", err)
	}
	secrets := []string{
		"command-private",
		"stdout-private",
		"stdout-api",
		"stdout-stripe",
		"stdout-cookie",
		"stderr-credential",
		"stderr-session",
	}
	for _, secret := range secrets {
		if strings.Contains(output, secret) {
			t.Fatalf("caller output leaked %q: %s", secret, output)
		}
	}
	if runner.command != "echo privatekey=command-private" {
		t.Fatalf("runner command = %q", runner.command)
	}
	auditData, err := os.ReadFile(defaultAuditPath(t))
	if err != nil {
		t.Fatalf("ReadFile(audit) error = %v", err)
	}
	for _, secret := range secrets {
		if bytes.Contains(auditData, []byte(secret)) {
			t.Fatalf("audit leaked %q: %s", secret, auditData)
		}
	}
}

func TestExecRemoteNonzeroReturnsBackendErrorAfterResult(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{result: sshexec.Result{
		Stdout:   "partial output",
		Stderr:   "command failed",
		ExitCode: 23,
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "exec", "pwd")
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	got := decodeJSONData[execResultView](t, output, "ExecResult")
	if got.ExitCode != 23 || got.Stdout != "partial output" || got.Stderr != "command failed" {
		t.Fatalf("result = %#v", got)
	}
	events := readAuditEvents(t)
	if len(events) != 1 ||
		events[0].Status != srvgovaudit.StatusFailed ||
		events[0].ExitCode != 23 ||
		events[0].Error == nil ||
		events[0].Error.Code != string(apperrors.CodeBackendError) {
		t.Fatalf("audit events = %#v", events)
	}
}

func prepareExecContext(t *testing.T, protected bool) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	args := []string{
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
	}
	if protected {
		args = append(args, "--protected")
	}
	runCommand(t, configPath, args...)
	runCommand(t, configPath, "ctx", "use", "dev")
	return configPath
}

func executeRoot(t *testing.T, configPath string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"--config", configPath}, args...))
	err := root.Execute()
	return out.String(), err
}

func replaceSSHRunner(runner sshRunner) func() {
	previous := newSSHRunner
	newSSHRunner = func() sshRunner { return runner }
	return func() { newSSHRunner = previous }
}

func defaultAuditPath(t *testing.T) string {
	t.Helper()
	path, err := coreaudit.DefaultPath()
	if err != nil {
		t.Fatalf("DefaultPath() error = %v", err)
	}
	return path
}

func readAuditEvents(t *testing.T) []srvgovaudit.Event {
	t.Helper()
	data, err := os.ReadFile(defaultAuditPath(t))
	if err != nil {
		t.Fatalf("ReadFile(audit) error = %v", err)
	}
	lines := bytes.Split(bytes.TrimSpace(data), []byte("\n"))
	events := make([]srvgovaudit.Event, 0, len(lines))
	for _, line := range lines {
		var event srvgovaudit.Event
		if err := json.Unmarshal(line, &event); err != nil {
			t.Fatalf("Unmarshal(audit) error = %v; line = %q", err, line)
		}
		events = append(events, event)
	}
	return events
}

func assertAppError(t *testing.T, err error, code apperrors.ErrorCode, exitCode int) {
	t.Helper()
	if err == nil {
		t.Fatalf("error = nil, want %s", code)
	}
	appErr := apperrors.AsAppError(err)
	if appErr.Code != code || apperrors.ExitCode(err) != exitCode {
		t.Fatalf("error = %#v; exit = %d", appErr, apperrors.ExitCode(err))
	}
}
