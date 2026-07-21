package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"

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

type failingTOFUNoticeWriter struct{}

func (failingTOFUNoticeWriter) Write([]byte) (int, error) {
	return 0, errors.New("notice writer failed")
}

func (f *fakeSSHRunner) Run(_ context.Context, _ string, _ srvgovctx.Context, command string) (sshexec.Result, error) {
	f.calls++
	f.command = command
	return f.result, f.err
}

func TestExecReportsFirstTOFUPinToStderr(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	previous := newSSHRunner
	newSSHRunner = func(notify func(sshexec.Pin)) sshRunner {
		notify(sshexec.Pin{
			Address:     "example.com:22",
			KeyType:     "ssh-ed25519",
			Fingerprint: "SHA256:test-fingerprint",
		})
		return runner
	}
	t.Cleanup(func() { newSSHRunner = previous })

	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"--config", configPath, "exec", "pwd"})
	if err := root.Execute(); err != nil {
		t.Fatalf("exec error = %v", err)
	}
	notice := errOut.String()
	for _, value := range []string{"pinned SSH host key", `"example.com:22"`, "ssh-ed25519", "SHA256:test-fingerprint", "future key changes will be rejected"} {
		if !strings.Contains(notice, value) {
			t.Fatalf("TOFU notice %q does not contain %q", notice, value)
		}
	}
}

func TestTOFUNoticeWriteFailureDoesNotReplaceRemoteSuccess(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	previous := newSSHRunner
	newSSHRunner = func(notify func(sshexec.Pin)) sshRunner {
		notify(sshexec.Pin{Address: "example.com:22", KeyType: "ssh-ed25519", Fingerprint: "SHA256:test"})
		return runner
	}
	t.Cleanup(func() { newSSHRunner = previous })

	var out bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(failingTOFUNoticeWriter{})
	root.SetArgs([]string{"--config", configPath, "exec", "pwd"})
	if err := root.Execute(); err != nil {
		t.Fatalf("exec error after TOFU notice write failure = %v", err)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
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

func TestExecReportsSuccessfulCommandWithTruncatedSSHOutput(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{result: sshexec.Result{
		Stdout:          "bounded-prefix",
		StdoutTruncated: true,
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "-o", "json", "exec", "uptime")
	if err == nil {
		t.Fatal("exec error = nil, want incomplete-output failure")
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodePartialFailure {
		t.Fatalf("exec error code = %s, want %s; error=%v", got, apperrors.CodePartialFailure, err)
	}
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
}

func TestMutatingExecTruncatedOutputRecordsCompletedMutationAndWarnsAgainstRetry(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{result: sshexec.Result{
		Stdout:          "bounded-prefix",
		StdoutTruncated: true,
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes",
		"exec", "touch /tmp/app", "--reason", "create reviewed marker",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	appErr := apperrors.AsAppError(err)
	if !strings.Contains(appErr.Suggestion, "already ran") ||
		!strings.Contains(appErr.Suggestion, "verify target state") {
		t.Fatalf("suggestion = %q, want no-blind-retry warning", appErr.Suggestion)
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeExecRun), "dev", "R1")
	if outcome.Status != srvgovaudit.StatusSucceeded ||
		outcome.Outcome.Succeeded != 1 ||
		!outcome.Outcome.OutputIncomplete {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestMutatingExecTransportFailureRecordsUncertainAndWarnsAgainstRetry(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{err: errors.New("connection reset after command start")}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes",
		"exec", "touch /tmp/app", "--reason", "create reviewed marker",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	appErr := apperrors.AsAppError(err)
	if !strings.Contains(appErr.Suggestion, "verify the target state") ||
		!strings.Contains(appErr.Suggestion, "before any retry") {
		t.Fatalf("suggestion = %q, want uncertainty warning", appErr.Suggestion)
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeExecRun), "dev", "R1")
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Outcome.Uncertain != 1 ||
		outcome.Outcome.Failed != 0 {
		t.Fatalf("outcome = %#v", outcome)
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
		event.Ticket != "" ||
		event.TicketBytes != len("OPS-42") ||
		!strings.HasPrefix(event.TicketFingerprint, "sha256:") {
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
	auditData := readAuditData(t)
	for _, secret := range secrets {
		if bytes.Contains(auditData, []byte(secret)) {
			t.Fatalf("audit leaked %q: %s", secret, auditData)
		}
	}
}

func TestExecRemoteNonzeroReturnsBackendErrorAfterResult(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{result: sshexec.Result{
		Stdout:          "partial output",
		Stderr:          "command failed",
		ExitCode:        23,
		StderrTruncated: true,
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "exec", "pwd")
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	if !strings.Contains(apperrors.AsAppError(err).Message, "stderr was truncated") {
		t.Fatalf("error message = %q, want truncation disclosure", apperrors.AsAppError(err).Message)
	}
	got := decodeJSONData[execResultView](t, output, "ExecResult")
	if got.ExitCode != 23 || got.Stdout != "partial output" || got.Stderr != "command failed" {
		t.Fatalf("result = %#v", got)
	}
	events := readAuditEvents(t)
	if len(events) != 1 ||
		events[0].Status != srvgovaudit.StatusFailed ||
		events[0].ExitCode != 23 ||
		!events[0].OutputIncomplete ||
		events[0].Error == nil ||
		events[0].Error.Code != string(apperrors.CodeBackendError) {
		t.Fatalf("audit events = %#v", events)
	}
}

func prepareExecContext(t *testing.T, protected bool) string {
	t.Helper()
	stubFileWriteTargetResolution(t)
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := createPrivateMutationAuditDirectory(filepath.Join(home, ".srvgov")); err != nil {
		t.Fatalf("create isolated audit directory: %v", err)
	}
	configPath := filepath.Join(home, "config.yaml")
	srvgovctx.SetConfigPath(configPath)
	item := srvgovctx.Context{
		Host: "example.com",
		Port: 22,
	}
	item.Username = "alice"
	item.Protected = protected
	item.CredentialBackend = "plain-yaml"
	item.OTLPRedact = true
	if err := srvgovctx.SetContext("dev", item); err != nil {
		t.Fatalf("SetContext() error = %v", err)
	}
	if err := srvgovctx.UseContext("dev"); err != nil {
		t.Fatalf("UseContext() error = %v", err)
	}
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
	newSSHRunner = func(func(sshexec.Pin)) sshRunner { return runner }
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
	result, err := coreaudit.QueryRaw(defaultAuditPath(t), coreaudit.Filter{})
	if err != nil {
		t.Fatalf("QueryRaw(audit) error = %v", err)
	}
	events := make([]srvgovaudit.Event, 0, len(result.Records))
	for _, record := range result.Records {
		var event srvgovaudit.Event
		if err := json.Unmarshal([]byte(record.Line), &event); err != nil {
			t.Fatalf("Unmarshal(audit) error = %v; line = %q", err, record.Line)
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
