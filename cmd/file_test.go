package cmd

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

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
		{name: "write", command: fileWriteCommand(path), want: safety.R2},
		{name: "sensitive write", command: fileWriteCommand("~/.ssh/authorized_keys"), want: safety.R3},
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
	var got fileReadView
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal(read) error = %v; output = %q", err, output)
	}
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
	var stat fileStatView
	if err := json.Unmarshal([]byte(statOutput), &stat); err != nil {
		t.Fatalf("Unmarshal(stat) error = %v", err)
	}
	if stat.Type != "regular file" || stat.Size != 12 || stat.Mode != "640" || stat.Owner != "alice" {
		t.Fatalf("stat = %#v", stat)
	}

	listOutput, err := executeRoot(t, configPath, "-o", "json", "file", "list", "/tmp/app")
	if err != nil {
		t.Fatalf("file list error = %v", err)
	}
	var list []fileListItem
	if err := json.Unmarshal([]byte(listOutput), &list); err != nil {
		t.Fatalf("Unmarshal(list) error = %v; output = %q", err, listOutput)
	}
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
	if stdin.reads != 0 || runner.input != "password=write-secret" || runner.command != fileWriteCommand("/tmp/app") {
		t.Fatalf("stdin reads = %d; runner = %#v", stdin.reads, runner)
	}
	var got fileWriteView
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal(write) error = %v; output = %q", err, output)
	}
	if !got.Success || got.BytesWritten != int64(len("password=write-secret")) || strings.Contains(output, "write-secret") {
		t.Fatalf("write = %#v; output = %s", got, output)
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
	wantSHA := hex.EncodeToString(digest[:])
	events := readAuditEvents(t)
	if len(events) != 1 || events[0].EventType != srvgovaudit.EventTypeFileWrite || events[0].File == nil {
		t.Fatalf("audit events = %#v", events)
	}
	if events[0].File.BytesWritten != int64(len(content)) || events[0].File.SHA256 != wantSHA || events[0].Stdout != "" {
		t.Fatalf("audit event = %#v", events[0])
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
	if runner.calls != 1 || runner.command != fileWriteCommand(path) {
		t.Fatalf("runner = %#v", runner)
	}
	events := readAuditEvents(t)
	if len(events) != 1 || events[0].RiskTier != "R3" || events[0].EventType != srvgovaudit.EventTypeFileWrite {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestFileWriteRemoteNonzeroReturnsStructuredBackendError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	content := "password=write-secret"
	runner := &scriptedStdinSSHRunner{result: sshexec.Result{
		Stderr:   "token=remote-secret",
		ExitCode: 5,
	}}
	restore := replaceSSHStdinRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
		"file", "write", "/tmp/app", "--content", content, "--reason", "update app file",
	)
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	var got fileWriteView
	if jsonErr := json.Unmarshal([]byte(output), &got); jsonErr != nil {
		t.Fatalf("Unmarshal(write) error = %v; output = %q", jsonErr, output)
	}
	if got.Success || got.BytesWritten != int64(len(content)) {
		t.Fatalf("write = %#v", got)
	}
	raw := string(readAuditData(t))
	if strings.Contains(output, "write-secret") || strings.Contains(output, "remote-secret") ||
		strings.Contains(raw, "write-secret") || strings.Contains(raw, "remote-secret") {
		t.Fatalf("write failure leaked content; output = %s; audit = %s", output, raw)
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
	newSSHStdinRunner = func() sshStdinRunner { return runner }
	return func() { newSSHStdinRunner = previous }
}

func readAuditData(t *testing.T) []byte {
	t.Helper()
	data, err := os.ReadFile(defaultAuditPath(t))
	if err != nil {
		t.Fatalf("ReadFile(audit) error = %v", err)
	}
	return data
}
