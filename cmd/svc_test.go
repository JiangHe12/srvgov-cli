package cmd

import (
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

func TestSvcStatusUsesGovernedR0CommandAndRedacts(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := serviceStatusCommand("nginx; rm -rf /")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stdout: strings.Join([]string{
			"LoadState=loaded",
			"ActiveState=active",
			"SubState=running",
			"UnitFileState=enabled",
			"Description=password=service-secret",
			"MainPID=123",
		}, "\n")},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "svc", "status", "nginx; rm -rf /")
	if err != nil {
		t.Fatalf("svc status error = %v", err)
	}
	got := decodeJSONData[serviceStatusView](t, output, "ServiceStatus")
	if len(runner.commands) != 1 || runner.commands[0] != command {
		t.Fatalf("commands = %#v, want %q", runner.commands, command)
	}
	if cmdclass.Classify(command) != safety.R0 {
		t.Fatalf("Classify(%q) = R%d, want R0", command, cmdclass.Classify(command))
	}
	if !strings.HasPrefix(command, "systemctl show ") || strings.Contains(output, "service-secret") {
		t.Fatalf("command = %q; output = %s", command, output)
	}
	if got.Unit != "nginx; rm -rf /" || got.ActiveState != "active" || got.MainPID != 123 {
		t.Fatalf("status = %#v", got)
	}
	events := readAuditEvents(t)
	outcomes := requireReadAuditPairs(t, events, string(srvgovaudit.EventTypeSvcStatus), "R0", 1)
	if strings.Contains(outcomes[0].Stdout, "service-secret") {
		t.Fatalf("audit leaked service secret: %#v", outcomes[0])
	}
}

func TestSvcActionsUseFixedR2Commands(t *testing.T) {
	actions := []string{"start", "stop", "restart", "reload", "enable", "disable"}
	for _, action := range actions {
		t.Run(action, func(t *testing.T) {
			configPath := prepareExecContext(t, false)
			command := serviceActionCommand(action, "nginx")
			runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
				command: {Stdout: "token=action-secret"},
			}}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			output, err := executeRoot(t, configPath,
				"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
				"svc", "--reason", "operate service", action, "nginx",
			)
			if err != nil {
				t.Fatalf("svc %s error = %v", action, err)
			}
			got := decodeJSONData[serviceActionView](t, output, "ServiceAction")
			if cmdclass.Classify(command) != safety.R2 || got.Action != action || !got.Success || got.ExitCode != 0 {
				t.Fatalf("command = %q; action = %#v", command, got)
			}
			if strings.Contains(output, "action-secret") {
				t.Fatalf("caller output leaked secret: %s", output)
			}
		})
	}
}

func TestSvcActionRequiresHumanAuthorization(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes",
		"svc", "--reason", "restart service", "restart", "nginx",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestSvcActionQuotesUnitInjectionAsOneR2Command(t *testing.T) {
	configPath := prepareExecContext(t, false)
	unit := "nginx; systemctl reboot"
	command := serviceActionCommand("restart", unit)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{command: {}}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"svc", "--reason", "restart service", "restart", unit,
	)
	if err != nil {
		t.Fatalf("svc restart error = %v", err)
	}
	if len(runner.commands) != 1 || runner.commands[0] != command || cmdclass.Classify(command) != safety.R2 {
		t.Fatalf("commands = %#v; risk = R%d", runner.commands, cmdclass.Classify(command))
	}
}

func TestSvcProtectedActionRequiresDestructiveAllow(t *testing.T) {
	configPath := prepareExecContext(t, true)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"svc", "--reason", "restart protected service", "restart", "reboot.service",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	events := readAuditEvents(t)
	if len(events) != 1 || events[0].RiskTier != "R3" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestSvcProtectedActionRunsWithHumanDestructiveAllow(t *testing.T) {
	configPath := prepareExecContext(t, true)
	command := serviceActionCommand("restart", "nginx")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{command: {}}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"svc", "--reason", "restart protected service", "--allow-destructive", "restart", "nginx",
	)
	if err != nil {
		t.Fatalf("svc restart error = %v", err)
	}
	if len(runner.commands) != 1 || runner.commands[0] != command {
		t.Fatalf("commands = %#v, want %q", runner.commands, command)
	}
	events := readAuditEvents(t)
	intent, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeSvcAction), "dev", "R3")
	if intent.Metadata == nil || intent.Metadata.PayloadFingerprint == "" ||
		outcome.Status != srvgovaudit.StatusSucceeded {
		t.Fatalf("mutation events = %#v / %#v", intent, outcome)
	}
}

func TestSvcRejectsUnknownActionAsUsageError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "svc", "reboot", "nginx")
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestSvcRemoteNonzeroReturnsStructuredBackendError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := serviceActionCommand("restart", "nginx")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stderr: "password=remote-secret", ExitCode: 5},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"svc", "--reason", "restart service", "restart", "nginx",
	)
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	got := decodeJSONData[serviceActionView](t, output, "ServiceAction")
	if got.Success || got.ExitCode != 5 || strings.Contains(output, "remote-secret") {
		t.Fatalf("action = %#v; output = %s", got, output)
	}
}
