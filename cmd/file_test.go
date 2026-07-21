package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type scriptedStdinSSHRunner struct {
	result  sshexec.Result
	err     error
	command string
	input   string
	calls   int
}

func (s *scriptedStdinSSHRunner) RunWithStdin(
	_ context.Context,
	_ string,
	_ srvgovctx.Context,
	command string,
	stdin io.Reader,
) (sshexec.Result, error) {
	s.calls++
	s.command = command
	data, err := io.ReadAll(stdin)
	if err != nil {
		return sshexec.Result{}, err
	}
	s.input = string(data)
	return s.result, s.err
}

type noReadStdinSSHRunner struct {
	calls int
}

func (s *noReadStdinSSHRunner) RunWithStdin(
	context.Context,
	string,
	srvgovctx.Context,
	string,
	io.Reader,
) (sshexec.Result, error) {
	s.calls++
	return sshexec.Result{}, nil
}

type failOnRead struct {
	reads int
}

func (r *failOnRead) Read([]byte) (int, error) {
	r.reads++
	return 0, apperrors.New(apperrors.CodeLocalIOError, "stdin must not be read", nil)
}

func TestFileCommandsClassifyAndQuotePaths(t *testing.T) {
	path := "/tmp/app; rm -rf /"
	tests := []struct {
		name    string
		command string
		want    safety.Risk
	}{
		{name: "read", command: fileReadCommand(path, 1024), want: safety.R0},
		{name: "stat", command: fileStatCommand(path), want: safety.R0},
		{name: "list", command: fileListCommand(path), want: safety.R0},
		{name: "write", command: fileWritePolicyCommand(path), want: safety.R2},
		{name: "sensitive write", command: fileWritePolicyCommand("~/.ssh/authorized_keys"), want: safety.R3},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := cmdclass.Classify(tt.command); got != tt.want {
				t.Fatalf("Classify(%q) = R%d, want R%d", tt.command, got, tt.want)
			}
			if !strings.Contains(tt.command, "'"+path+"'") && tt.name != "sensitive write" {
				t.Fatalf("command does not quote path: %q", tt.command)
			}
		})
	}
	statCommand := fileStatCommand(path)
	if strings.Contains(statCommand, `\t`) || strings.Count(statCommand, "\t") != 5 {
		t.Fatalf("fileStatCommand() separators = %q, want five literal tabs", statCommand)
	}
}

func TestFileWriteCommandUsesFixedBoundedAtomicWrapper(t *testing.T) {
	path := "/tmp/app'; touch /tmp/injected"
	payload := []byte("payload")
	command := fileWriteCommand(testFileWriteTargetBinding(t, path), 17, payload)
	digest := sha256.Sum256(payload)
	for _, marker := range []string{
		"sh -c ",
		"mktemp",
		"head -c",
		"stat -c",
		"mv -fT",
		"target changed during file write",
		"'\"'\"'",
		" 17",
		" 7",
		hex.EncodeToString(digest[:]),
	} {
		if !strings.Contains(command, marker) {
			t.Fatalf("fileWriteCommand() missing %q: %s", marker, command)
		}
	}
	if strings.Contains(command, "tee --") {
		t.Fatalf("fileWriteCommand() still uses direct tee: %s", command)
	}
	if got := cmdclass.Classify(fileWritePolicyCommand(path)); got != safety.R2 {
		t.Fatalf("file-write policy risk = R%d, want R2", got)
	}
}

func TestFileReadTruncatesAndRedacts(t *testing.T) {
	configPath := prepareExecContext(t, false)
	path := "/tmp/password=path-secret"
	command := fileReadCommand(path, 32)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stdout: "password=content-secret extra bytes beyond limit"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "file", "read", path, "--max-bytes", "32")
	if err != nil {
		t.Fatalf("file read error = %v", err)
	}
	got := decodeJSONData[fileReadView](t, output, "FileRead")
	if !got.Truncated || got.Bytes != 32 || strings.Contains(output, "content-secret") || strings.Contains(output, "path-secret") {
		t.Fatalf("read = %#v; output = %s", got, output)
	}
	events := readAuditEvents(t)
	if len(events) != 1 || events[0].EventType != srvgovaudit.EventTypeFileRead || events[0].RiskTier != "R0" {
		t.Fatalf("audit events = %#v", events)
	}
	if strings.Contains(events[0].Stdout, "content-secret") || strings.Contains(events[0].Command, "path-secret") {
		t.Fatalf("audit leaked read secret: %#v", events[0])
	}
}

func TestFileStatAndListStructuredOutput(t *testing.T) {
	configPath := prepareExecContext(t, false)
	statCommand := fileStatCommand("/tmp/app")
	listCommand := fileListCommand("/tmp/app")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		statCommand: {Stdout: "regular file\t12\t640\talice\tstaff\t1710000000\n"},
		listCommand: {Stdout: "a file\x00f\x0012\x00640\x001710000000.0\x00subdir\x00d\x000\x00755\x001710000001.0\x00"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	statOutput, err := executeRoot(t, configPath, "-o", "json", "file", "stat", "/tmp/app")
	if err != nil {
		t.Fatalf("file stat error = %v", err)
	}
	stat := decodeJSONData[fileStatView](t, statOutput, "FileStat")
	if stat.Type != "regular file" || stat.Size != 12 || stat.Mode != "640" || stat.Owner != "alice" {
		t.Fatalf("stat = %#v", stat)
	}

	listOutput, err := executeRoot(t, configPath, "-o", "json", "file", "list", "/tmp/app")
	if err != nil {
		t.Fatalf("file list error = %v", err)
	}
	list := decodeJSONList[fileListItem](t, listOutput, "FileList").Items
	if len(list) != 2 || list[0].Name != "a file" || list[0].Type != "file" || list[1].Type != "directory" {
		t.Fatalf("list = %#v", list)
	}
}

func TestFileMissingIsNotReportedAsMissingTool(t *testing.T) {
	configPath := prepareExecContext(t, false)
	path := "/tmp/missing"
	command := fileReadCommand(path, defaultFileReadMaxBytes)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {ExitCode: 1, Stderr: "head: cannot open '/tmp/missing': No such file or directory"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "file", "read", path)
	assertAppError(t, err, apperrors.CodeResourceNotFound, 4)
	message := apperrors.AsAppError(err).Message
	if strings.Contains(message, "head is not available") || !strings.Contains(message, "file not found or unreadable") {
		t.Fatalf("message = %q", message)
	}
}

func TestFileWriteContentFlagDoesNotReadCommandStdin(t *testing.T) {
	configPath := prepareExecContext(t, false)
	stdin := &failOnRead{}
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	output, err := executeRootWithInput(t, configPath, stdin,
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--content", "password=write-secret", "--reason", "update app file",
	)
	if err != nil {
		t.Fatalf("file write error = %v", err)
	}
	if stdin.reads != 0 ||
		runner.input != "password=write-secret" ||
		runner.command != fileWriteCommand(testFileWriteTargetBinding(t, "/tmp/app"), defaultFileReadMaxBytes, []byte("password=write-secret")) {
		t.Fatalf("stdin reads = %d; runner = %#v", stdin.reads, runner)
	}
	got := decodeJSONData[fileWriteView](t, output, "FileWrite")
	if !got.Success || got.BytesWritten != int64(len("password=write-secret")) || strings.Contains(output, "write-secret") {
		t.Fatalf("write = %#v; output = %s", got, output)
	}
}

func TestFileWriteRejectsOversizedContentBeforeSSH(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--content", "12345", "--max-bytes", "4", "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodeValidationFailed, 9)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestFileWriteRejectsOversizedStdinBeforeAuditOrSSH(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRootWithInput(t, configPath, strings.NewReader("123456789"),
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--max-bytes", "4", "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodeValidationFailed, 9)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	if _, statErr := os.Stat(defaultAuditPath(t)); !os.IsNotExist(statErr) {
		t.Fatalf("audit file error = %v, want no mutation intent", statErr)
	}
}

func TestFileWriteInputReadFailureOccursBeforeAuditOrSSH(t *testing.T) {
	configPath := prepareExecContext(t, false)
	input := &failOnRead{}
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRootWithInput(t, configPath, input,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--max-bytes", "4", "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
	if input.reads != 1 || runner.calls != 0 {
		t.Fatalf("input reads = %d; runner calls = %d", input.reads, runner.calls)
	}
	if _, statErr := os.Stat(defaultAuditPath(t)); !os.IsNotExist(statErr) {
		t.Fatalf("audit file error = %v, want no mutation intent", statErr)
	}
}

func TestFileWriteFailsClosedWhenSSHDoesNotConsumeWholePayload(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &noReadStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--content", "data", "--max-bytes", "4", "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	if runner.calls != 1 {
		t.Fatalf("runner calls = %d, want 1", runner.calls)
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeFileWrite), "dev", "R2")
	if outcome.Status != srvgovaudit.StatusFailed || outcome.Outcome.Failed != 1 {
		t.Fatalf("outcome = %#v", outcome)
	}
}

func TestFileWriteStdinRequiresYesBeforeReading(t *testing.T) {
	configPath := prepareExecContext(t, false)
	stdin := &failOnRead{}
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRootWithInput(t, configPath, stdin,
		"--non-interactive", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	if apperrors.AsAppError(err).Message != "reading content from stdin requires --yes" {
		t.Fatalf("message = %q", apperrors.AsAppError(err).Message)
	}
	if stdin.reads != 0 || runner.calls != 0 {
		t.Fatalf("stdin reads = %d; runner calls = %d", stdin.reads, runner.calls)
	}
}

func TestFileWriteStdinMissingTicketDoesNotReadContent(t *testing.T) {
	configPath := prepareExecContext(t, false)
	stdin := &failOnRead{}
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRootWithInput(t, configPath, stdin,
		"--non-interactive", "--yes",
		"file", "write", "/tmp/app", "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if stdin.reads != 0 || runner.calls != 0 {
		t.Fatalf("stdin reads = %d; runner calls = %d", stdin.reads, runner.calls)
	}
}

func TestFileWriteMissingReasonAuditsDenialBeforeReadingContent(t *testing.T) {
	configPath := prepareExecContext(t, false)
	stdin := &failOnRead{}
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRootWithInput(t, configPath, stdin,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--content", "data",
	)
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	message := apperrors.AsAppError(err).Message
	for _, flag := range []string{"--reason", "--yes", "--ticket"} {
		if !strings.Contains(message, flag) {
			t.Fatalf("message = %q, want %s", message, flag)
		}
	}
	if stdin.reads != 0 || runner.calls != 0 {
		t.Fatalf("stdin reads = %d; runner calls = %d", stdin.reads, runner.calls)
	}
	events := readAuditEvents(t)
	if len(events) != 1 ||
		events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied ||
		events[0].Status != srvgovaudit.StatusDenied ||
		events[0].RiskTier != "R2" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestFileWriteStdinAuthorizesThenStreamsAndAuditsDigest(t *testing.T) {
	configPath := prepareExecContext(t, false)
	content := "token=stdin-secret\nsecond line"
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	output, err := executeRootWithInput(t, configPath, strings.NewReader(content),
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--reason", "update app file",
	)
	if err != nil {
		t.Fatalf("file write error = %v", err)
	}
	if runner.input != content {
		t.Fatalf("runner input = %q", runner.input)
	}
	digest := sha256.Sum256([]byte(content))
	wantSHA := "sha256:" + hex.EncodeToString(digest[:])
	events := readAuditEvents(t)
	intent, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeFileWrite), "dev", "R2")
	if intent.Metadata == nil || intent.Metadata.PayloadFingerprint == "" ||
		outcome.Outcome.PayloadBytes != int64(len(content)) ||
		outcome.Outcome.PayloadFingerprint != wantSHA {
		t.Fatalf("mutation events = %#v / %#v", intent, outcome)
	}
	raw := string(readAuditData(t))
	if strings.Contains(raw, "stdin-secret") || strings.Contains(output, "stdin-secret") {
		t.Fatalf("write content leaked; output = %s; audit = %s", output, raw)
	}
}

func TestFileWriteSensitiveAndProtectedRequireAllow(t *testing.T) {
	tests := []struct {
		name      string
		protected bool
		path      string
	}{
		{name: "sensitive path", path: "~/.ssh/authorized_keys"},
		{name: "protected context", protected: true, path: "/tmp/app"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath := prepareExecContext(t, tt.protected)
			runner := &scriptedStdinSSHRunner{}
			restore := replaceSSHStdinRunner(runner)
			t.Cleanup(restore)

			_, err := executeRoot(t, configPath,
				"--non-interactive", "--yes", "--ticket", "OPS-42",
				"file", "write", tt.path, "--content", "data", "--reason", "update file",
			)
			assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
			if runner.calls != 0 {
				t.Fatalf("runner calls = %d", runner.calls)
			}
		})
	}
}

func TestFileWriteResolvedSensitiveParentRequiresR3Allow(t *testing.T) {
	configPath := prepareExecContext(t, false)
	previous := resolveFileWriteTargetForCommand
	resolveFileWriteTargetForCommand = func(
		_ *cobra.Command,
		_ *cliFlags,
		_ srvgovctx.Context,
		_ string,
		_ string,
	) (fileWriteTargetBinding, error) {
		return fileWriteTargetBinding{
			ResolvedDirectory: "/etc",
			Base:              "passwd",
			DirectoryIdentity: "2049:42",
		}, nil
	}
	t.Cleanup(func() { resolveFileWriteTargetForCommand = previous })
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/link/etc/passwd", "--content", "data", "--reason", "update file",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
	events := readAuditEvents(t)
	if len(events) != 1 ||
		events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied ||
		events[0].RiskTier != "R3" {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestFileWriteDryRunResolvesParentBeforeClassifying(t *testing.T) {
	configPath := prepareExecContext(t, false)
	useRealFileWriteTargetResolution(t)
	target := "/tmp/link/passwd"
	resolveCommand := fileWriteResolveDirectoryCommand("/tmp/link")
	identityCommand := fileWriteDirectoryIdentityCommand("/etc")
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		resolveCommand:  {Stdout: "/etc\n"},
		identityCommand: {Stdout: "2049:42\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)
	stdinRunner := &scriptedStdinSSHRunner{}
	restoreStdin := replaceSSHStdinRunner(stdinRunner)
	t.Cleanup(restoreStdin)
	stdin := &failOnRead{}

	output, err := executeRootWithInput(t, configPath, stdin,
		"-o", "json", "file", "write", target, "--dry-run",
	)
	if err != nil {
		t.Fatalf("file write dry-run error = %v", err)
	}
	view := decodeJSONData[execDryRunView](t, output, "ExecDryRun")
	if !view.DryRun ||
		view.Command != fileWritePolicyCommand("/etc/passwd") ||
		view.RiskTier != "R3" ||
		view.EffectiveRiskTier != "R3" {
		t.Fatalf("dry-run view = %#v", view)
	}
	if len(view.RequiredAuthorization) != 3 ||
		view.RequiredAuthorization[2] != "--allow-destructive" {
		t.Fatalf("required authorization = %#v", view.RequiredAuthorization)
	}
	if len(runner.commands) != 2 ||
		runner.commands[0] != resolveCommand ||
		runner.commands[1] != identityCommand {
		t.Fatalf("preflight commands = %#v", runner.commands)
	}
	if stdin.reads != 0 || stdinRunner.calls != 0 {
		t.Fatalf("stdin reads = %d; mutation calls = %d", stdin.reads, stdinRunner.calls)
	}
	events := readAuditEvents(t)
	if len(events) != 2 {
		t.Fatalf("audit events = %#v", events)
	}
	for _, event := range events {
		if event.EventType != srvgovaudit.EventTypeFileStat || event.RiskTier != "R0" {
			t.Fatalf("preflight audit event = %#v", event)
		}
	}
}

func TestFileWriteFanoutDryRunShowsEachResolvedTargetRisk(t *testing.T) {
	configPath := prepareFanoutContextsWith(t, []fanoutContextSpec{{Name: "alpha"}, {Name: "bravo"}})
	useRealFileWriteTargetResolution(t)
	target := "/tmp/link/passwd"
	resolveCommand := fileWriteResolveDirectoryCommand("/tmp/link")
	alphaDirectory := "/srv/app"
	bravoDirectory := "/etc"
	runner := &targetSSHRunner{results: map[string]sshexec.Result{
		"alpha\x00" + resolveCommand:                                    {Stdout: alphaDirectory + "\n"},
		"alpha\x00" + fileWriteDirectoryIdentityCommand(alphaDirectory): {Stdout: "2049:41\n"},
		"bravo\x00" + resolveCommand:                                    {Stdout: bravoDirectory + "\n"},
		"bravo\x00" + fileWriteDirectoryIdentityCommand(bravoDirectory): {Stdout: "2049:42\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)
	stdin := &failOnRead{}

	output, err := executeRootWithInput(t, configPath, stdin,
		"-o", "json", "file", "write", target, "--targets", "bravo,alpha", "--dry-run",
	)
	if err != nil {
		t.Fatalf("file write fanout dry-run error = %v", err)
	}
	view := decodeJSONData[fanoutView](t, output, "FanoutResult")
	if view.MaxEffectiveRiskTier != "R3" || len(view.Results) != 2 {
		t.Fatalf("fanout dry-run view = %#v", view)
	}
	alpha, alphaOK := view.Results[0].Data.(map[string]any)
	bravo, bravoOK := view.Results[1].Data.(map[string]any)
	if !alphaOK || !bravoOK ||
		alpha["command"] != fileWritePolicyCommand("/srv/app/passwd") ||
		alpha["effectiveRiskTier"] != "R2" ||
		bravo["command"] != fileWritePolicyCommand("/etc/passwd") ||
		bravo["effectiveRiskTier"] != "R3" {
		t.Fatalf("per-target plans = %#v / %#v", alpha, bravo)
	}
	if len(runner.commands) != 4 || stdin.reads != 0 {
		t.Fatalf("preflight commands = %#v; stdin reads = %d", runner.commands, stdin.reads)
	}
	events := readAuditEvents(t)
	if len(events) != 4 {
		t.Fatalf("audit events = %#v", events)
	}
	for _, event := range events {
		if event.EventType != srvgovaudit.EventTypeFileStat || event.RiskTier != "R0" {
			t.Fatalf("preflight audit event = %#v", event)
		}
	}
}

func TestFileWriteSensitiveRunsWithAllowAndAuditsR3(t *testing.T) {
	configPath := prepareExecContext(t, false)
	path := "~/.ssh/authorized_keys"
	runner := &scriptedStdinSSHRunner{}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", path, "--content", "ssh-ed25519 test", "--reason", "rotate authorized key", "--allow-destructive",
	)
	if err != nil {
		t.Fatalf("file write error = %v", err)
	}
	if runner.calls != 1 ||
		runner.command != fileWriteCommand(testFileWriteTargetBinding(t, path), defaultFileReadMaxBytes, []byte("ssh-ed25519 test")) {
		t.Fatalf("runner = %#v", runner)
	}
	events := readAuditEvents(t)
	intent, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeFileWrite), "dev", "R3")
	if intent.Metadata == nil || intent.Metadata.TargetFingerprint == "" ||
		outcome.Status != srvgovaudit.StatusSucceeded {
		t.Fatalf("mutation events = %#v / %#v", intent, outcome)
	}
}

func TestFileWriteRemoteNonzeroReturnsStructuredBackendError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	content := "password=write-secret"
	runner := &scriptedStdinSSHRunner{result: sshexec.Result{
		Stderr:   "token=remote-secret",
		ExitCode: 66,
	}}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--content", content, "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	got := decodeJSONData[fileWriteView](t, output, "FileWrite")
	if got.Success || got.BytesWritten != int64(len(content)) {
		t.Fatalf("write = %#v", got)
	}
	raw := string(readAuditData(t))
	if strings.Contains(output, "write-secret") || strings.Contains(output, "remote-secret") ||
		strings.Contains(raw, "write-secret") || strings.Contains(raw, "remote-secret") {
		t.Fatalf("write failure leaked content; output = %s; audit = %s", output, raw)
	}
}

func TestFileWriteCommitWindowExitReportsUncertainState(t *testing.T) {
	configPath := prepareExecContext(t, false)
	content := "password=write-secret"
	runner := &scriptedStdinSSHRunner{result: sshexec.Result{
		Stderr:   "token=remote-secret",
		ExitCode: 70,
	}}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--content", content, "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	if !strings.Contains(apperrors.AsAppError(err).Suggestion, "before any retry") {
		t.Fatalf("suggestion = %q, want verify-before-retry guidance", apperrors.AsAppError(err).Suggestion)
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeFileWrite), "dev", "R2")
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Outcome == nil ||
		outcome.Outcome.Uncertain != 1 ||
		outcome.Outcome.Failed != 0 {
		t.Fatalf("file write outcome = %#v", outcome)
	}
	raw := string(readAuditData(t))
	if strings.Contains(output, "write-secret") || strings.Contains(output, "remote-secret") ||
		strings.Contains(raw, "write-secret") || strings.Contains(raw, "remote-secret") {
		t.Fatalf("uncertain write leaked content; output = %s; audit = %s", output, raw)
	}
}

func executeRootWithInput(t *testing.T, configPath string, input io.Reader, args ...string) (string, error) {
	t.Helper()
	root := NewRootCmd()
	var output strings.Builder
	root.SetOut(&output)
	root.SetErr(io.Discard)
	root.SetIn(input)
	root.SetArgs(append([]string{"--config", configPath}, args...))
	err := root.Execute()
	return output.String(), err
}

func replaceSSHStdinRunner(runner sshStdinRunner) func() {
	previous := newSSHStdinRunner
	newSSHStdinRunner = func(func(sshexec.Pin)) sshStdinRunner { return runner }
	return func() { newSSHStdinRunner = previous }
}

func stubFileWriteTargetResolution(t testing.TB) {
	t.Helper()
	previous := resolveFileWriteTargetForCommand
	resolveFileWriteTargetForCommand = func(
		_ *cobra.Command,
		_ *cliFlags,
		_ srvgovctx.Context,
		_ string,
		target string,
	) (fileWriteTargetBinding, error) {
		return testFileWriteTargetBinding(t, target), nil
	}
	t.Cleanup(func() { resolveFileWriteTargetForCommand = previous })
}

func useRealFileWriteTargetResolution(t testing.TB) {
	t.Helper()
	previous := resolveFileWriteTargetForCommand
	resolveFileWriteTargetForCommand = resolveFileWriteTarget
	t.Cleanup(func() { resolveFileWriteTargetForCommand = previous })
}

func testFileWriteTargetBinding(t testing.TB, target string) fileWriteTargetBinding {
	t.Helper()
	directory, base, err := splitRemoteFileWriteTarget(target)
	if err != nil {
		t.Fatalf("splitRemoteFileWriteTarget(%q) error = %v", target, err)
	}
	return fileWriteTargetBinding{
		ResolvedDirectory: directory,
		Base:              base,
		DirectoryIdentity: "1:1",
	}
}

func readAuditData(t *testing.T) []byte {
	t.Helper()
	result, err := coreaudit.QueryRaw(defaultAuditPath(t), coreaudit.Filter{})
	if err != nil {
		t.Fatalf("QueryRaw(audit) error = %v", err)
	}
	lines := make([]string, 0, len(result.Records))
	for _, record := range result.Records {
		lines = append(lines, record.Line)
	}
	return []byte(strings.Join(lines, "\n"))
}
