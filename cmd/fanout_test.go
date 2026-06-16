package cmd

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type targetSSHRunner struct {
	mu       sync.Mutex
	results  map[string]sshexec.Result
	errors   map[string]error
	commands []string
}

func (r *targetSSHRunner) Run(_ context.Context, contextName string, _ srvgovctx.Context, command string) (sshexec.Result, error) {
	key := contextName + "\x00" + command
	r.mu.Lock()
	r.commands = append(r.commands, key)
	result := r.results[key]
	err := r.errors[key]
	r.mu.Unlock()
	return result, err
}

func TestExecFanoutRejectsTargetParsingErrorsBeforeSSH(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		code        apperrors.ErrorCode
		wantMessage string
	}{
		{
			name:        "empty target set",
			args:        []string{"exec", "--targets", " , ", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "at least one target",
		},
		{
			name:        "context conflict",
			args:        []string{"--context", "alpha", "exec", "--targets", "bravo", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "mutually exclusive",
		},
		{
			name:        "explicit empty context conflict",
			args:        []string{"--context=", "exec", "--targets", "bravo", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "mutually exclusive",
		},
		{
			name:        "unknown target",
			args:        []string{"exec", "--targets", "missing", "pwd"},
			code:        apperrors.CodeResourceNotFound,
			wantMessage: "missing",
		},
		{
			name:        "invalid concurrency",
			args:        []string{"exec", "--targets", "alpha", "--concurrency", "0", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "concurrency",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := prepareFanoutContexts(t)
			runner := &targetSSHRunner{}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			_, err := executeRoot(t, configPath, tt.args...)
			appErr := apperrors.AsAppError(err)
			if appErr.Code != tt.code || !strings.Contains(appErr.Message, tt.wantMessage) {
				t.Fatalf("error = %#v, want code %s containing %q", appErr, tt.code, tt.wantMessage)
			}
			if len(runner.commands) != 0 {
				t.Fatalf("commands = %#v, want no SSH", runner.commands)
			}
		})
	}
}

func TestFanoutSelectorParsingErrorsHappenBeforeSSH(t *testing.T) {
	tests := []struct {
		name        string
		args        []string
		code        apperrors.ErrorCode
		wantMessage string
	}{
		{
			name:        "context conflict",
			args:        []string{"--context", "alpha", "exec", "--selector", "env=prod", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "mutually exclusive",
		},
		{
			name:        "targets conflict",
			args:        []string{"exec", "--targets", "alpha", "--selector", "env=prod", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "mutually exclusive",
		},
		{
			name:        "empty selector",
			args:        []string{"exec", "--selector", "", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "selector",
		},
		{
			name:        "missing equals",
			args:        []string{"exec", "--selector", "env", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "selector",
		},
		{
			name:        "empty value",
			args:        []string{"exec", "--selector", "env=", "pwd"},
			code:        apperrors.CodeUsageError,
			wantMessage: "selector",
		},
		{
			name:        "zero match",
			args:        []string{"exec", "--selector", "env=missing", "pwd"},
			code:        apperrors.CodeResourceNotFound,
			wantMessage: "no contexts match selector",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
				{Name: "alpha", Labels: map[string]string{"env": "prod"}},
				{Name: "bravo", Labels: map[string]string{"env": "staging"}},
			})
			runner := &targetSSHRunner{}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			_, err := executeRoot(t, configPath, tt.args...)
			appErr := apperrors.AsAppError(err)
			if appErr.Code != tt.code || !strings.Contains(appErr.Message, tt.wantMessage) {
				t.Fatalf("error = %#v, want code %s containing %q", appErr, tt.code, tt.wantMessage)
			}
			if len(runner.commands) != 0 {
				t.Fatalf("commands = %#v, want no SSH", runner.commands)
			}
		})
	}
}

func TestExecFanoutSelectorSelectsSortedTargetsAndDryRunShowsBlastRadius(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "bravo", Labels: map[string]string{"env": "prod", "role": "web"}},
		{Name: "alpha", Labels: map[string]string{"env": "prod", "role": "web"}},
		{Name: "charlie", Labels: map[string]string{"env": "prod", "role": "db"}},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "exec", "--selector", "env=prod,role=web", "--dry-run",
		"systemctl restart nginx",
	)
	if err != nil {
		t.Fatalf("exec selector dry-run error = %v", err)
	}
	var got fanoutView
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal(fanout) error = %v; output = %q", err, output)
	}
	if strings.Join(got.Targets, ",") != "alpha,bravo" || got.MaxEffectiveRiskTier != "R2" {
		t.Fatalf("fanout = %#v", got)
	}
	if len(got.Results) != 2 {
		t.Fatalf("results = %#v", got.Results)
	}
	for _, result := range got.Results {
		data, ok := result.Data.(map[string]any)
		if !ok || data["effectiveRiskTier"] != "R2" {
			t.Fatalf("dry-run data = %#v", result.Data)
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want no SSH", runner.commands)
	}
}

func TestExecFanoutSelectorCannotBypassAuthorization(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha", Labels: map[string]string{"env": "prod"}},
		{Name: "bravo", Labels: map[string]string{"env": "prod"}},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "exec", "--selector", "env=prod", "rm -rf /")
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want selector authorization failure before SSH", runner.commands)
	}
}

func TestExecFanoutPreauthorizationPreventsPartialWrites(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha", TicketPattern: `^OPS-[0-9]+$`},
		{Name: "bravo", TicketPattern: `^CHG-[0-9]+$`},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--yes", "--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo", "--reason", "restart reviewed service",
		"systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	appErr := apperrors.AsAppError(err)
	if !strings.Contains(appErr.Message, `target "bravo"`) || !strings.Contains(appErr.Message, "R2") {
		t.Fatalf("error = %#v, want rejected target and effective tier", appErr)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want zero partial writes", runner.commands)
	}
	events := readAuditEvents(t)
	if len(events) != 1 ||
		events[0].Context.Name != "bravo" ||
		events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied ||
		events[0].Status != srvgovaudit.StatusDenied {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestExecFanoutProtectedTargetRequiresR3AllowBeforeAnySSH(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha"},
		{Name: "bravo", Protected: true},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--yes", "--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo", "--reason", "restart reviewed service",
		"systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	appErr := apperrors.AsAppError(err)
	if !strings.Contains(appErr.Message, `target "bravo"`) || !strings.Contains(appErr.Message, "R3") {
		t.Fatalf("error = %#v, want protected target R3", appErr)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want zero partial writes", runner.commands)
	}
}

func TestExecFanoutRequiresTicketToMatchEveryTarget(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha", TicketPattern: `^OPS-[0-9]+$`},
		{Name: "bravo", TicketPattern: `^CHG-[0-9]+$`},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--yes", "--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo", "--reason", "restart reviewed service",
		"systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if !strings.Contains(apperrors.AsAppError(err).Message, `target "bravo"`) {
		t.Fatalf("error = %#v, want bravo ticket rejection", apperrors.AsAppError(err))
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want no SSH", runner.commands)
	}
}

func TestExecFanoutRequiresRBACOnEveryTarget(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha", Roles: map[string]string{"alice": "writer"}},
		{Name: "bravo", Roles: map[string]string{"bob": "writer"}},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--operator", "alice", "--yes", "--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo", "--reason", "restart reviewed service",
		"systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if !strings.Contains(apperrors.AsAppError(err).Message, `target "bravo"`) {
		t.Fatalf("error = %#v, want bravo RBAC rejection", apperrors.AsAppError(err))
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want no SSH", runner.commands)
	}
}

func TestExecFanoutRequiresReasonBeforeAnySSH(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha"},
		{Name: "bravo", Protected: true},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--yes", "--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo",
		"systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	message := apperrors.AsAppError(err).Message
	for _, flag := range []string{"--reason", "--yes", "--ticket", "--allow-destructive"} {
		if !strings.Contains(message, flag) {
			t.Fatalf("message = %q, want %s", message, flag)
		}
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want no SSH", runner.commands)
	}
	events := readAuditEvents(t)
	if len(events) != 1 ||
		events[0].Context.Name != "bravo" ||
		events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied ||
		events[0].Status != srvgovaudit.StatusDenied ||
		events[0].RiskTier != "R3" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestExecFanoutAuthorizationIsAlwaysNonInteractive(t *testing.T) {
	configPath := prepareFanoutContexts(t)
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRootWithInput(t, configPath, strings.NewReader("yes\n"),
		"--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo", "--reason", "restart reviewed service",
		"systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if output != "" {
		t.Fatalf("authorization prompted unexpectedly: %q", output)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want no SSH", runner.commands)
	}
}

func TestExecFanoutExecutesAllAuthorizedR2TargetsAndAuditsOwnRisk(t *testing.T) {
	configPath := prepareFanoutContexts(t)
	runner := &targetSSHRunner{results: map[string]sshexec.Result{
		"alpha\x00systemctl restart nginx": {},
		"bravo\x00systemctl restart nginx": {},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "--yes", "--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo", "--reason", "restart reviewed service",
		"systemctl restart nginx",
	)
	if err != nil {
		t.Fatalf("exec fanout error = %v", err)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v, want both targets", runner.commands)
	}
	var got map[string]any
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal(fanout) error = %v; output = %q", err, output)
	}
	if _, ok := got["maxEffectiveRiskTier"]; ok {
		t.Fatalf("execution output added dry-run field: %s", output)
	}
	events := readAuditEvents(t)
	if len(events) != 2 {
		t.Fatalf("audit events = %#v", events)
	}
	for _, event := range events {
		if event.RiskTier != "R2" || event.EventType != srvgovaudit.EventTypeExecRun {
			t.Fatalf("audit event = %#v", event)
		}
	}
}

func TestExecFanoutDryRunShowsPerTargetAndMaximumEffectiveRiskWithoutAuthorization(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha"},
		{Name: "bravo", Protected: true},
	})
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "exec", "--targets", "bravo,alpha", "--dry-run",
		"systemctl restart nginx",
	)
	if err != nil {
		t.Fatalf("exec dry-run error = %v", err)
	}
	var got fanoutView
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal(fanout) error = %v; output = %q", err, output)
	}
	if got.MaxEffectiveRiskTier != "R3" {
		t.Fatalf("max effective risk = %q, want R3", got.MaxEffectiveRiskTier)
	}
	if len(got.Results) != 2 {
		t.Fatalf("results = %#v", got.Results)
	}
	alpha, ok := got.Results[0].Data.(map[string]any)
	if !ok {
		t.Fatalf("alpha data = %#v", got.Results[0].Data)
	}
	bravo, ok := got.Results[1].Data.(map[string]any)
	if !ok {
		t.Fatalf("bravo data = %#v", got.Results[1].Data)
	}
	if alpha["effectiveRiskTier"] != "R2" || bravo["effectiveRiskTier"] != "R3" {
		t.Fatalf("dry-run data = %#v / %#v", alpha, bravo)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want no SSH", runner.commands)
	}
	if _, err := os.Stat(defaultAuditPath(t)); !os.IsNotExist(err) {
		t.Fatalf("dry-run audit file error = %v, want not exist", err)
	}
}

func TestExecFanoutSortsDeduplicatesRedactsAndAuditsEachTarget(t *testing.T) {
	configPath := prepareFanoutContexts(t)
	runner := &targetSSHRunner{
		results: map[string]sshexec.Result{
			"alpha\x00pwd": {Stdout: "password=alpha-secret\n"},
			"bravo\x00pwd": {Stdout: "/srv/bravo\n"},
		},
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "exec", "--targets", "bravo,alpha,bravo", "--concurrency", "2", "pwd")
	if err != nil {
		t.Fatalf("exec fanout error = %v", err)
	}
	const v1Output = `{
  "targets": [
    "alpha",
    "bravo"
  ],
  "concurrency": 2,
  "summary": {
    "total": 2,
    "succeeded": 2,
    "failed": 0
  },
  "results": [
    {
      "target": "alpha",
      "host": "alpha.example:22",
      "ok": true,
      "data": {
        "context": "alpha",
        "host": "alpha.example:22",
        "command": "pwd",
        "riskTier": "R0",
        "stdout": "password=[REDACTED]\n",
        "stderr": "",
        "exitCode": 0
      }
    },
    {
      "target": "bravo",
      "host": "bravo.example:22",
      "ok": true,
      "data": {
        "context": "bravo",
        "host": "bravo.example:22",
        "command": "pwd",
        "riskTier": "R0",
        "stdout": "/srv/bravo\n",
        "stderr": "",
        "exitCode": 0
      }
    }
  ]
}
`
	if output != v1Output {
		t.Fatalf("execution JSON changed from v1\nactual:\n%s\nwant:\n%s", output, v1Output)
	}
	var got fanoutView
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal(fanout) error = %v; output = %q", err, output)
	}
	if strings.Join(got.Targets, ",") != "alpha,bravo" || got.Concurrency != 2 {
		t.Fatalf("fanout = %#v", got)
	}
	if got.Summary.Total != 2 || got.Summary.Succeeded != 2 || got.Summary.Failed != 0 {
		t.Fatalf("summary = %#v", got.Summary)
	}
	if len(got.Results) != 2 || got.Results[0].Target != "alpha" || got.Results[1].Target != "bravo" {
		t.Fatalf("results = %#v", got.Results)
	}
	if strings.Contains(output, "alpha-secret") {
		t.Fatalf("output leaked secret: %s", output)
	}
	events := readAuditEvents(t)
	if len(events) != 2 || events[0].Target.Host == events[1].Target.Host {
		t.Fatalf("audit events = %#v, want one event per target", events)
	}
}

func TestExecFanoutContinuesAfterFailureAndReturnsBackendError(t *testing.T) {
	configPath := prepareFanoutContexts(t)
	runner := &targetSSHRunner{
		results: map[string]sshexec.Result{
			"alpha\x00systemctl restart nginx": {Stdout: "restarted\n"},
			"bravo\x00systemctl restart nginx": {ExitCode: 23, Stderr: "password=failed-secret"},
		},
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "--yes", "--ticket", "OPS-42",
		"exec", "--targets", "alpha,bravo", "--reason", "restart reviewed service",
		"systemctl restart nginx",
	)
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	var got fanoutView
	if jsonErr := json.Unmarshal([]byte(output), &got); jsonErr != nil {
		t.Fatalf("Unmarshal(fanout) error = %v; output = %q", jsonErr, output)
	}
	if got.Summary.Succeeded != 1 || got.Summary.Failed != 1 || got.Results[1].Error == nil {
		t.Fatalf("fanout = %#v", got)
	}
	if got.Results[1].Error.Code != string(apperrors.CodeBackendError) {
		t.Fatalf("per-target error = %#v", got.Results[1].Error)
	}
	if strings.Contains(output, "failed-secret") {
		t.Fatalf("output leaked secret: %s", output)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v, want both targets attempted", runner.commands)
	}
}

func TestStatusAndPortsFanoutUseIndependentR0Probes(t *testing.T) {
	configPath := prepareFanoutContexts(t)
	statusResults := make(map[string]sshexec.Result)
	for _, target := range []string{"alpha", "bravo"} {
		for _, probe := range observe.StatusProbes() {
			statusResults[target+"\x00"+probe.Command] = sshexec.Result{}
		}
		statusResults[target+"\x00hostname"] = sshexec.Result{Stdout: target + "\n"}
	}
	runner := &targetSSHRunner{results: statusResults}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "status", "--targets", "bravo,alpha")
	if err != nil {
		t.Fatalf("status fanout error = %v", err)
	}
	var statusFanout fanoutView
	if err := json.Unmarshal([]byte(output), &statusFanout); err != nil {
		t.Fatalf("Unmarshal(status fanout) error = %v; output = %q", err, output)
	}
	if len(statusFanout.Results) != 2 || statusFanout.Results[0].Target != "alpha" || statusFanout.Results[1].Target != "bravo" {
		t.Fatalf("status results = %#v", statusFanout.Results)
	}

	ssCommand := observe.PortProbes()[0].Command
	runner.mu.Lock()
	runner.results = map[string]sshexec.Result{
		"alpha\x00" + ssCommand: {Stdout: "tcp LISTEN 0 128 127.0.0.1:22 0.0.0.0:*\n"},
		"bravo\x00" + ssCommand: {Stdout: "tcp LISTEN 0 128 127.0.0.1:80 0.0.0.0:*\n"},
	}
	runner.commands = nil
	runner.mu.Unlock()
	output, err = executeRoot(t, configPath, "-o", "json", "ports", "--targets", "alpha,bravo")
	if err != nil {
		t.Fatalf("ports fanout error = %v", err)
	}
	var portsFanout fanoutView
	if err := json.Unmarshal([]byte(output), &portsFanout); err != nil {
		t.Fatalf("Unmarshal(ports fanout) error = %v; output = %q", err, output)
	}
	if portsFanout.Summary.Succeeded != 2 || len(portsFanout.Results) != 2 {
		t.Fatalf("ports fanout = %#v", portsFanout)
	}
}

func TestLogsFanoutSelectorUsesReadOnlyCapAndAuditsEachTarget(t *testing.T) {
	opts := observe.LogOptions{
		File:  "/var/log/app; rm -rf /",
		Lines: 2,
		Grep:  "ERROR; reboot",
	}
	command := observe.FileCommand(opts)
	if risk := cmdclass.Classify(command); risk != safety.R0 {
		t.Fatalf("logs file command risk = %v, want R0; command = %q", risk, command)
	}
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "bravo", Labels: map[string]string{"env": "prod", "role": "web"}},
		{Name: "alpha", Labels: map[string]string{"env": "prod", "role": "web"}},
		{Name: "charlie", Labels: map[string]string{"env": "staging", "role": "web"}},
	})
	runner := &targetSSHRunner{
		results: map[string]sshexec.Result{
			"alpha\x00" + command: {Stdout: "INFO ok\nERROR; reboot password=alpha-secret\n"},
			"bravo\x00" + command: {Stdout: "ERROR; reboot token=bravo-secret\n"},
		},
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "logs",
		"--selector", "env=prod,role=web",
		"--file", opts.File,
		"--lines", "2",
		"--grep", opts.Grep,
	)
	if err != nil {
		t.Fatalf("logs fanout error = %v", err)
	}
	var got fanoutView
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal(logs fanout) error = %v; output = %q", err, output)
	}
	if strings.Join(got.Targets, ",") != "alpha,bravo" || got.Summary.Succeeded != 2 || got.Summary.Failed != 0 {
		t.Fatalf("fanout = %#v", got)
	}
	if strings.Contains(output, "alpha-secret") || strings.Contains(output, "bravo-secret") {
		t.Fatalf("logs fanout leaked secret: %s", output)
	}
	runner.mu.Lock()
	commands := append([]string(nil), runner.commands...)
	runner.mu.Unlock()
	sort.Strings(commands)
	wantCommands := []string{"alpha\x00" + command, "bravo\x00" + command}
	if strings.Join(commands, "\n") != strings.Join(wantCommands, "\n") {
		t.Fatalf("commands = %#v, want %#v", commands, wantCommands)
	}
	events := readAuditEvents(t)
	if len(events) != 2 {
		t.Fatalf("audit events = %#v", events)
	}
	for _, event := range events {
		if event.EventType != srvgovaudit.EventTypeLogsObserve || event.RiskTier != "R0" {
			t.Fatalf("audit event = %#v", event)
		}
	}
}

func TestLogsFanoutContinuesAfterTargetFailure(t *testing.T) {
	opts := observe.LogOptions{File: "/var/log/app.log", Lines: 1}
	command := observe.FileCommand(opts)
	configPath := prepareFanoutContexts(t)
	runner := &targetSSHRunner{
		results: map[string]sshexec.Result{
			"alpha\x00" + command: {Stdout: "ready\n"},
			"bravo\x00" + command: {ExitCode: 1, Stderr: "tail: cannot open '/var/log/app.log' for reading: Permission denied"},
		},
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "logs", "--targets", "alpha,bravo", "--file", opts.File, "--lines", "1")
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	var got fanoutView
	if jsonErr := json.Unmarshal([]byte(output), &got); jsonErr != nil {
		t.Fatalf("Unmarshal(logs fanout) error = %v; output = %q", jsonErr, output)
	}
	if got.Summary.Succeeded != 1 || got.Summary.Failed != 1 || got.Results[1].Error == nil {
		t.Fatalf("fanout = %#v", got)
	}
	if strings.Contains(got.Results[1].Error.Message, "tail is not available") {
		t.Fatalf("error misreported tool absence: %#v", got.Results[1].Error)
	}
	if len(runner.commands) != 2 {
		t.Fatalf("commands = %#v, want both targets attempted", runner.commands)
	}
	events := readAuditEvents(t)
	if len(events) != 2 {
		t.Fatalf("audit events = %#v", events)
	}
}

func prepareFanoutContexts(t *testing.T) string {
	return prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "bravo"},
		{Name: "alpha"},
	})
}

type fanoutContextSpec struct {
	Name          string
	Protected     bool
	TicketPattern string
	Roles         map[string]string
	Labels        map[string]string
}

func prepareFanoutContextsWith(t *testing.T, specs []fanoutContextSpec) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	for _, spec := range specs {
		args := []string{
			"ctx", "set", spec.Name,
			"--server", "ssh://alice@" + spec.Name + ".example:22",
		}
		if spec.Protected {
			args = append(args, "--protected")
		}
		if spec.TicketPattern != "" {
			args = append(args, "--ticket-pattern", spec.TicketPattern)
		}
		for _, label := range sortedLabelFlags(spec.Labels) {
			args = append(args, "--label", label)
		}
		runCommand(t, configPath, args...)
		for operator, role := range spec.Roles {
			runCommand(t, configPath,
				"ctx", "role", "set", spec.Name,
				"--target-operator", operator,
				"--role", role,
			)
		}
	}
	if len(specs) > 0 {
		runCommand(t, configPath, "ctx", "use", specs[0].Name)
	}
	return configPath
}

func sortedLabelFlags(labels map[string]string) []string {
	if len(labels) == 0 {
		return nil
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	out := make([]string, 0, len(keys))
	for _, key := range keys {
		out = append(out, key+"="+labels[key])
	}
	return out
}
