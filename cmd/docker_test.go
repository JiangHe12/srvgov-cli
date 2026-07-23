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

func TestDockerCommandsClassifyAndQuoteContainer(t *testing.T) {
	container := "app; docker run alpine"
	tests := []struct {
		name    string
		command string
		want    safety.Risk
	}{
		{name: "list", command: dockerListCommand(), want: safety.R0},
		{name: "inspect", command: dockerInspectCommand(container), want: safety.R0},
		{name: "logs", command: dockerLogsCommand(container, 100), want: safety.R0},
		{name: "start", command: dockerActionCommand("start", container), want: safety.R2},
		{name: "stop", command: dockerActionCommand("stop", container), want: safety.R2},
		{name: "restart", command: dockerActionCommand("restart", container), want: safety.R2},
		{name: "rm", command: dockerActionCommand("rm", container), want: safety.R3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cmdclass.Classify(tt.command); got != tt.want {
				t.Fatalf("Classify(%q) = R%d, want R%d", tt.command, got, tt.want)
			}
			if tt.name != "list" && !strings.Contains(tt.command, "'"+container+"'") {
				t.Fatalf("command does not quote container: %q", tt.command)
			}
		})
	}
}

func TestDockerListParsesStructuredRedactedRows(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := dockerListCommand()
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stdout: `{"ID":"abc","Names":"api","Image":"repo:tag","State":"running","Status":"Up 2 hours password=list-secret","Ports":"0.0.0.0:8080->80/tcp","CreatedAt":"2026-06-11 10:00:00 +0000 UTC"}` + "\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "docker", "ps")
	if err != nil {
		t.Fatalf("docker ps error = %v", err)
	}
	got := decodeJSONList[dockerListItem](t, output, "DockerList").Items
	if len(got) != 1 || got[0].ID != "abc" || got[0].Name != "api" || strings.Contains(output, "list-secret") {
		t.Fatalf("list = %#v; output = %s", got, output)
	}
	events := readAuditEvents(t)
	outcomes := requireReadAuditPairs(t, events, string(srvgovaudit.EventTypeDockerList), "R0", 1)
	if strings.Contains(string(readAuditData(t)), "list-secret") {
		t.Fatalf("audit leaked docker list secret: %#v", outcomes[0])
	}
}

func TestDockerInspectProjectsSafeFieldsAndExcludesEnv(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := dockerInspectCommand("api")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stdout: `{
			"id":"abc",
			"name":"/api",
			"image":"repo:tag",
			"state":"running",
			"status":"running",
			"restartPolicy":"unless-stopped",
			"ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]},
			"mounts":[{"Type":"bind","Source":"/srv/api","Destination":"/app","Mode":"ro","RW":false,"Propagation":"rprivate"}],
			"createdAt":"2026-06-11T10:00:00Z"
		}`},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "docker", "inspect", "api")
	if err != nil {
		t.Fatalf("docker inspect error = %v", err)
	}
	got := decodeJSONData[dockerInspectView](t, output, "DockerInspect")
	if got.ID != "abc" || got.Name != "api" || len(got.Ports) != 1 || len(got.Mounts) != 1 {
		t.Fatalf("inspect = %#v", got)
	}
	if strings.Contains(command, ".Config.Env") || strings.Contains(output, "Env") {
		t.Fatalf("inspect exposed Env; command = %q; output = %s", command, output)
	}
}

func TestDockerLogsLimitsAndRedactsStdoutAndStderr(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := dockerLogsCommand("api", 2)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {
			Stdout: "2026-06-12T08:15:30.123456789Z first password=stdout-secret\nsecond without timestamp\n",
			Stderr: "2026-06-12T08:15:31Z third token=stderr-secret\n",
		},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "docker", "logs", "api", "--tail", "2")
	if err != nil {
		t.Fatalf("docker logs error = %v", err)
	}
	got := decodeJSONData[dockerLogsView](t, output, "DockerLogs")
	if got.Meta.Backend != "docker" || got.Meta.Container != "api" ||
		got.Meta.RequestedLines != 2 || got.Meta.ReturnedLines != 3 ||
		len(got.Lines) != 3 ||
		strings.Contains(output, "stdout-secret") || strings.Contains(output, "stderr-secret") {
		t.Fatalf("logs = %#v; output = %s", got, output)
	}
	if got.Lines[0].Timestamp != "2026-06-12T08:15:30.123456789Z" ||
		got.Lines[1].Timestamp != "" ||
		got.Lines[1].Message != "second without timestamp" {
		t.Fatalf("logs = %#v", got)
	}
	audit := string(readAuditData(t))
	if strings.Contains(audit, "stdout-secret") || strings.Contains(audit, "stderr-secret") {
		t.Fatalf("audit leaked docker logs: %s", audit)
	}
}

func TestDockerActionsUseGovernedHumanAuthorization(t *testing.T) {
	actions := []struct {
		name string
		risk safety.Risk
	}{
		{name: "start", risk: safety.R2},
		{name: "stop", risk: safety.R2},
		{name: "restart", risk: safety.R2},
		{name: "rm", risk: safety.R3},
	}
	for _, action := range actions {
		t.Run(action.name, func(t *testing.T) {
			configPath := prepareExecContext(t, false)
			command := dockerActionCommand(action.name, "run")
			runner := &scriptedSSHRunner{results: map[string]sshexec.Result{command: {}}}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			args := []string{
				"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
			}
			args = append(args, "docker", action.name, "run", "--reason", "operate container")
			if action.risk == safety.R3 {
				args = append(args, "--allow-destructive")
			}
			output, err := executeRoot(t, configPath, args...)
			if err != nil {
				t.Fatalf("docker %s error = %v", action.name, err)
			}
			got := decodeJSONData[dockerActionView](t, output, "DockerAction")
			if cmdclass.Classify(command) != action.risk || got.Container != "run" || !got.Success {
				t.Fatalf("command = %q; action = %#v", command, got)
			}
		})
	}
}

func TestDockerRemoveRequiresDestructiveAllowBeforeSSH(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"docker", "rm", "api", "--reason", "remove retired container",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestDockerRejectsUnknownAndDangerousActionsBeforeSSH(t *testing.T) {
	for _, action := range []string{"run", "exec", "build", "cp", "prune", "mystery"} {
		t.Run(action, func(t *testing.T) {
			configPath := prepareExecContext(t, false)
			runner := &fakeSSHRunner{}
			restore := replaceSSHRunner(runner)
			t.Cleanup(restore)

			_, err := executeRoot(t, configPath, "docker", action, "api")
			assertAppError(t, err, apperrors.CodeUsageError, 1)
			if runner.calls != 0 {
				t.Fatalf("runner calls = %d", runner.calls)
			}
		})
	}
}

func TestDockerUnavailableIsResourceNotFound(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := dockerListCommand()
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {ExitCode: 127, Stderr: "docker: command not found"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "docker", "list")
	assertAppError(t, err, apperrors.CodeResourceNotFound, 4)
	if apperrors.AsAppError(err).Message != "docker is not available" {
		t.Fatalf("message = %q", apperrors.AsAppError(err).Message)
	}
}

func TestDockerMissingContainerRemainsBackendError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := dockerInspectCommand("missing")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {ExitCode: 1, Stderr: "Error: No such container: password=missing-secret"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "docker", "inspect", "missing")
	assertAppError(t, err, apperrors.CodeBackendError, 7)
}

func TestDockerProtectedActionRequiresAllow(t *testing.T) {
	configPath := prepareExecContext(t, true)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"docker", "restart", "api", "--reason", "restart protected container",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d", runner.calls)
	}
}

func TestDockerProtectedActionRunsWithAllowAndAuditsR3(t *testing.T) {
	configPath := prepareExecContext(t, true)
	command := dockerActionCommand("restart", "api")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{command: {}}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"docker", "restart", "api", "--reason", "restart protected container", "--allow-destructive",
	)
	if err != nil {
		t.Fatalf("docker restart error = %v", err)
	}
	events := readAuditEvents(t)
	intent, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeDockerAction), "dev", "R3")
	if intent.Metadata == nil || intent.Metadata.TargetFingerprint == "" ||
		outcome.Status != srvgovaudit.StatusSucceeded ||
		outcome.Outcome.Status != srvgovaudit.StatusSucceeded {
		t.Fatalf("mutation events = %#v / %#v", intent, outcome)
	}
}

func TestDockerActionRemoteNonzeroReturnsStructuredBackendError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	command := dockerActionCommand("restart", "api")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stderr: "password=remote-secret", ExitCode: 5},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"docker", "restart", "api", "--reason", "restart container",
	)
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	got := decodeJSONData[dockerActionView](t, output, "DockerAction")
	if got.Success || got.ExitCode != 5 || strings.Contains(output, "remote-secret") {
		t.Fatalf("action = %#v; output = %s", got, output)
	}
}

func TestDockerTailValidation(t *testing.T) {
	configPath := prepareExecContext(t, false)
	for _, value := range []string{"0", "10001"} {
		_, err := executeRoot(t, configPath, "docker", "logs", "api", "--tail", value)
		assertAppError(t, err, apperrors.CodeUsageError, 1)
	}
}
