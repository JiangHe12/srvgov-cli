package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type targetStdinSSHRunner struct {
	mu     sync.Mutex
	inputs map[string]string
	calls  int
}

func (r *targetStdinSSHRunner) RunWithStdin(
	_ context.Context,
	contextName string,
	_ srvgovctx.Context,
	_ string,
	stdin io.Reader,
) (sshexec.Result, error) {
	data, err := io.ReadAll(stdin)
	if err != nil {
		return sshexec.Result{}, err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.inputs == nil {
		r.inputs = make(map[string]string)
	}
	r.calls++
	r.inputs[contextName] = string(data)
	return sshexec.Result{}, nil
}

func TestGovernedActionFanoutPreauthorizationPreventsPartialWrites(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		useStdin  bool
		wantEvent srvgovaudit.EventType
	}{
		{
			name:      "svc",
			args:      []string{"svc", "restart", "nginx", "--targets", "alpha,bravo", "--reason", "restart service"},
			wantEvent: srvgovaudit.EventTypeSvcAction,
		},
		{
			name:      "file",
			args:      []string{"file", "write", "/tmp/app", "--content", "data", "--targets", "alpha,bravo", "--reason", "write file"},
			useStdin:  true,
			wantEvent: srvgovaudit.EventTypeFileWrite,
		},
		{
			name:      "docker",
			args:      []string{"docker", "restart", "api", "--targets", "alpha,bravo", "--reason", "restart container"},
			wantEvent: srvgovaudit.EventTypeDockerAction,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
				{Name: "alpha"},
				{Name: "bravo", Protected: true},
			})
			runner := &targetSSHRunner{}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)
			stdinRunner := &targetStdinSSHRunner{}
			if tt.useStdin {
				restoreStdin := replaceSSHStdinRunner(stdinRunner)
				t.Cleanup(restoreStdin)
			}

			args := append([]string{"--yes", "--ticket", "OPS-42"}, tt.args...)
			_, err := executeRoot(t, configPath, args...)
			assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
			if len(runner.commands) != 0 || stdinRunner.calls != 0 {
				t.Fatalf("SSH occurred before all targets were authorized: commands=%#v stdinCalls=%d", runner.commands, stdinRunner.calls)
			}
			events := readAuditEvents(t)
			if len(events) != 1 ||
				events[0].Context.Name != "bravo" ||
				events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied ||
				events[0].RiskTier != "R3" {
				t.Fatalf("audit events = %#v; action event type %s must not be emitted", events, tt.wantEvent)
			}
		})
	}
}

func TestGovernedReadFanoutAuditsEachTargetWithOwnEventType(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		command   string
		result    sshexec.Result
		eventType srvgovaudit.EventType
	}{
		{
			name:      "svc status",
			args:      []string{"svc", "status", "nginx", "--targets", "alpha,bravo"},
			command:   serviceStatusCommand("nginx"),
			result:    sshexec.Result{Stdout: "LoadState=loaded\nActiveState=active\n"},
			eventType: srvgovaudit.EventTypeSvcStatus,
		},
		{
			name:      "file stat",
			args:      []string{"file", "stat", "/tmp/app", "--targets", "alpha,bravo"},
			command:   fileStatCommand("/tmp/app"),
			result:    sshexec.Result{Stdout: "regular file\t12\t640\talice\tstaff\t1710000000\n"},
			eventType: srvgovaudit.EventTypeFileStat,
		},
		{
			name:      "docker list",
			args:      []string{"docker", "list", "--targets", "alpha,bravo"},
			command:   dockerListCommand(),
			result:    sshexec.Result{Stdout: `{"ID":"abc","Names":"api","Image":"repo","State":"running","Status":"Up","Ports":"","CreatedAt":"now"}` + "\n"},
			eventType: srvgovaudit.EventTypeDockerList,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := prepareFanoutContexts(t)
			runner := &targetSSHRunner{results: map[string]sshexec.Result{
				"alpha\x00" + tt.command: tt.result,
				"bravo\x00" + tt.command: tt.result,
			}}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			output, err := executeRoot(t, configPath, append([]string{"-o", "json"}, tt.args...)...)
			if err != nil {
				t.Fatalf("%s fanout error = %v", tt.name, err)
			}
			view := decodeJSONData[fanoutView](t, output, "FanoutResult")
			if view.Summary.Succeeded != 2 || view.MaxEffectiveRiskTier != "" {
				t.Fatalf("view = %#v", view)
			}
			events := readAuditEvents(t)
			outcomes := requireReadAuditPairs(t, events, string(tt.eventType), "R0", 2)
			for _, event := range outcomes {
				if event.EventType != tt.eventType || event.RiskTier != "R0" {
					t.Fatalf("event = %#v", event)
				}
			}
		})
	}
}

func TestGovernedActionFanoutAuditsEachTargetAtItsOwnTier(t *testing.T) {
	tests := []struct {
		name      string
		args      []string
		command   string
		eventType srvgovaudit.EventType
	}{
		{
			name:      "svc",
			args:      []string{"svc", "restart", "nginx", "--targets", "alpha,bravo", "--reason", "restart service", "--allow-destructive"},
			command:   serviceActionCommand("restart", "nginx"),
			eventType: srvgovaudit.EventTypeSvcAction,
		},
		{
			name:      "docker",
			args:      []string{"docker", "restart", "api", "--targets", "alpha,bravo", "--reason", "restart container", "--allow-destructive"},
			command:   dockerActionCommand("restart", "api"),
			eventType: srvgovaudit.EventTypeDockerAction,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
				{Name: "alpha"},
				{Name: "bravo", Protected: true},
			})
			runner := &targetSSHRunner{results: map[string]sshexec.Result{
				"alpha\x00" + tt.command: {},
				"bravo\x00" + tt.command: {},
			}}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			_, err := executeRoot(t, configPath, append([]string{"--yes", "--ticket", "OPS-42"}, tt.args...)...)
			if err != nil {
				t.Fatalf("%s fanout error = %v", tt.name, err)
			}
			events := readAuditEvents(t)
			if len(events) != 6 {
				t.Fatalf("events = %#v", events)
			}
			_, batchOutcome := requireMutationPair(t, events, string(tt.eventType)+".batch", "fanout", "R3")
			_, alphaOutcome := requireMutationPair(t, events, string(tt.eventType), "alpha", "R2")
			_, bravoOutcome := requireMutationPair(t, events, string(tt.eventType), "bravo", "R3")
			if batchOutcome.Outcome.Succeeded != 2 ||
				alphaOutcome.Outcome.Succeeded != 1 ||
				bravoOutcome.Outcome.Succeeded != 1 {
				t.Fatalf("mutation outcomes = %#v / %#v / %#v", batchOutcome, alphaOutcome, bravoOutcome)
			}
		})
	}
}

func TestGovernedFanoutDryRunDoesNotConnectOrAudit(t *testing.T) {
	tests := [][]string{
		{"svc", "restart", "nginx", "--targets", "alpha,bravo", "--dry-run"},
		{"docker", "restart", "api", "--targets", "alpha,bravo", "--dry-run"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
				{Name: "alpha"},
				{Name: "bravo", Protected: true},
			})
			runner := &targetSSHRunner{}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)
			stdin := &failOnRead{}

			output, err := executeRootWithInput(t, configPath, stdin, append([]string{"-o", "json"}, args...)...)
			if err != nil {
				t.Fatalf("dry-run error = %v", err)
			}
			view := decodeJSONData[fanoutView](t, output, "FanoutResult")
			if view.MaxEffectiveRiskTier != "R3" || len(runner.commands) != 0 || stdin.reads != 0 {
				t.Fatalf("view=%#v commands=%#v stdinReads=%d", view, runner.commands, stdin.reads)
			}
			if _, err := os.Stat(defaultAuditPath(t)); !os.IsNotExist(err) {
				t.Fatalf("dry-run audit file error = %v, want not exist", err)
			}
		})
	}
}

func TestGovernedSingleTargetDryRunDoesNotConnectOrAudit(t *testing.T) {
	tests := [][]string{
		{"svc", "restart", "nginx", "--dry-run"},
		{"docker", "restart", "api", "--dry-run"},
	}
	for _, args := range tests {
		t.Run(args[0], func(t *testing.T) {
			configPath := prepareExecContext(t, false)
			runner := &targetSSHRunner{}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)
			stdin := &failOnRead{}

			output, err := executeRootWithInput(t, configPath, stdin, append([]string{"-o", "json"}, args...)...)
			if err != nil {
				t.Fatalf("dry-run error = %v", err)
			}
			view := decodeJSONData[execDryRunView](t, output, "ExecDryRun")
			if !view.DryRun || view.EffectiveRiskTier != "R2" ||
				len(runner.commands) != 0 || stdin.reads != 0 {
				t.Fatalf("view=%#v commands=%#v stdinReads=%d", view, runner.commands, stdin.reads)
			}
			if _, err := os.Stat(defaultAuditPath(t)); !os.IsNotExist(err) {
				t.Fatalf("dry-run audit file error = %v, want not exist", err)
			}
		})
	}
}

func TestFileWriteFanoutBuffersOnceAndAuditsIndependentDigests(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{
		{Name: "alpha"},
		{Name: "bravo", Protected: true},
	})
	content := "password=fanout-secret\nsecond line"
	runner := &targetStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	output, err := executeRootWithInput(t, configPath, strings.NewReader(content),
		"-o", "json", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--targets", "alpha,bravo",
		"--reason", "write reviewed file", "--allow-destructive",
	)
	if err != nil {
		t.Fatalf("file write fanout error = %v", err)
	}
	if runner.calls != 2 || runner.inputs["alpha"] != content || runner.inputs["bravo"] != content {
		t.Fatalf("runner = %#v", runner)
	}
	digest := sha256.Sum256([]byte(content))
	wantSHA := "sha256:" + hex.EncodeToString(digest[:])
	events := readAuditEvents(t)
	if len(events) != 6 {
		t.Fatalf("events = %#v", events)
	}
	_, batchOutcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeFileWrite)+".batch", "fanout", "R3")
	_, alphaOutcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeFileWrite), "alpha", "R2")
	_, bravoOutcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeFileWrite), "bravo", "R3")
	if batchOutcome.Outcome.Succeeded != 2 ||
		alphaOutcome.Outcome.PayloadBytes != int64(len(content)) ||
		alphaOutcome.Outcome.PayloadFingerprint != wantSHA ||
		bravoOutcome.Outcome.PayloadBytes != int64(len(content)) ||
		bravoOutcome.Outcome.PayloadFingerprint != wantSHA {
		t.Fatalf("mutation outcomes = %#v / %#v / %#v", batchOutcome, alphaOutcome, bravoOutcome)
	}
	raw := string(readAuditData(t))
	if strings.Contains(raw, "fanout-secret") || strings.Contains(output, "fanout-secret") {
		t.Fatalf("content leaked; output=%s audit=%s", output, raw)
	}
}
