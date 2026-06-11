package cmd

import (
	"context"
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
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

func TestExecFanoutRejectsAnyEffectiveRiskAboveR0BeforeSSH(t *testing.T) {
	configPath := prepareFanoutContexts(t)
	runner := &targetSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "exec", "--targets", "bravo,alpha", "systemctl restart nginx")
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	appErr := apperrors.AsAppError(err)
	if !strings.Contains(appErr.Message, `target "alpha"`) || !strings.Contains(appErr.Message, "R2") {
		t.Fatalf("error = %#v, want sorted first target and effective tier", appErr)
	}
	if len(runner.commands) != 0 {
		t.Fatalf("commands = %#v, want entire fanout rejected before SSH", runner.commands)
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
			"alpha\x00pwd": {Stdout: "/srv/alpha\n"},
			"bravo\x00pwd": {ExitCode: 23, Stderr: "password=failed-secret"},
		},
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "exec", "--targets", "alpha,bravo", "pwd")
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

func prepareFanoutContexts(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	configPath := filepath.Join(home, "config.yaml")
	for _, target := range []string{"bravo", "alpha"} {
		runCommand(t, configPath,
			"ctx", "set", target,
			"--server", "ssh://alice@"+target+".example:22",
		)
	}
	runCommand(t, configPath, "ctx", "use", "alpha")
	return configPath
}
