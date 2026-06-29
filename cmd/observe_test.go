package cmd

import (
	"context"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type scriptedSSHRunner struct {
	results  map[string]sshexec.Result
	errors   map[string]error
	commands []string
}

func TestCommandUnavailableUsesExecutableMissingSignalsOnly(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		result sshexec.Result
		want   bool
	}{
		{name: "exit 127", result: sshexec.Result{ExitCode: 127}, want: true},
		{name: "command not found", result: sshexec.Result{ExitCode: 1, Stderr: "tail: command not found"}, want: true},
		{name: "target file missing", result: sshexec.Result{ExitCode: 1, Stderr: "No such file or directory"}, want: false},
		{name: "permission denied", result: sshexec.Result{ExitCode: 1, Stderr: "Permission denied"}, want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := commandUnavailable(tt.result); got != tt.want {
				t.Fatalf("commandUnavailable(%#v) = %v, want %v", tt.result, got, tt.want)
			}
		})
	}
}

func (s *scriptedSSHRunner) Run(_ context.Context, _ string, _ srvgovctx.Context, command string) (sshexec.Result, error) {
	s.commands = append(s.commands, command)
	return s.results[command], s.errors[command]
}

func TestStatusRunsIndependentGovernedProbesAndRedacts(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		"hostname":          {Stdout: "web-01\n"},
		"uname -srm":        {Stdout: "Linux 6.8.0 x86_64\n"},
		"cat /proc/uptime":  {Stdout: "123.5 10.0\n"},
		"cat /proc/loadavg": {Stdout: "0.1 0.2 0.3 1/10 2\n"},
		"cat /proc/cpuinfo": {Stdout: "processor: 0\nmodel name: CPU password=cpu-secret\n"},
		"cat /proc/meminfo": {Stdout: "MemTotal: 1000 kB\nMemAvailable: 400 kB\n"},
		"df -Pk":            {Stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda 1000 600 400 60% /\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "status")
	if err != nil {
		t.Fatalf("status error = %v", err)
	}
	got := decodeJSONData[observe.Status](t, output, "ServerStatus")
	if got.Hostname != "web-01" || got.Mem.Total != 1024000 || strings.Contains(output, "cpu-secret") {
		t.Fatalf("status = %#v; output = %s", got, output)
	}
	if len(runner.commands) != len(observe.StatusProbes()) {
		t.Fatalf("commands = %#v", runner.commands)
	}
	for _, command := range runner.commands {
		if cmdclass.Classify(command) != safety.R0 || strings.ContainsAny(command, "|;&") {
			t.Fatalf("unsafe status command = %q", command)
		}
	}
	events := readAuditEvents(t)
	if len(events) != len(runner.commands) {
		t.Fatalf("audit count = %d, want %d", len(events), len(runner.commands))
	}
	for _, event := range events {
		if event.EventType != srvgovaudit.EventTypeStatusObserve || event.RiskTier != "R0" {
			t.Fatalf("audit event = %#v", event)
		}
		if strings.Contains(event.Stdout, "cpu-secret") {
			t.Fatalf("audit leaked secret: %#v", event)
		}
	}
}

func TestStatusDegradesWhenOptionalProbeIsMissing(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		"hostname":          {Stdout: "web-01\n"},
		"uname -srm":        {ExitCode: 127, Stderr: "uname: command not found"},
		"cat /proc/uptime":  {ExitCode: 1, Stderr: "No such file or directory"},
		"cat /proc/loadavg": {Stdout: "malformed\n"},
		"cat /proc/cpuinfo": {},
		"cat /proc/meminfo": {},
		"df -Pk":            {},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "status")
	if err != nil {
		t.Fatalf("status error = %v", err)
	}
	got := decodeJSONData[observe.Status](t, output, "ServerStatus")
	if got.Hostname != "web-01" || got.Kernel != "" || got.Load.One != 0 {
		t.Fatalf("status = %#v", got)
	}
}

func TestStatusSkipsAnyRemoteNonzeroProbe(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		"hostname":          {Stdout: "web-01\n"},
		"uname -srm":        {Stdout: "Linux 6.8.0 x86_64\n"},
		"cat /proc/uptime":  {ExitCode: 1, Stderr: "Permission denied"},
		"cat /proc/loadavg": {Stdout: "0.1 0.2 0.3 1/10 2\n"},
		"cat /proc/cpuinfo": {},
		"cat /proc/meminfo": {},
		"df -Pk":            {ExitCode: 1, Stderr: "df: invalid option -- P"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "status")
	if err != nil {
		t.Fatalf("status error = %v", err)
	}
	got := decodeJSONData[observe.Status](t, output, "ServerStatus")
	if got.Hostname != "web-01" || got.Kernel == "" || got.Uptime != 0 || len(got.Disk) != 0 {
		t.Fatalf("status = %#v", got)
	}
}

func TestStatusTransportErrorIsFatal(t *testing.T) {
	configPath := prepareExecContext(t, false)
	transportErr := apperrors.New(apperrors.CodeNetworkError, "SSH command canceled", nil)
	runner := &scriptedSSHRunner{
		results: map[string]sshexec.Result{},
		errors:  map[string]error{"hostname": transportErr},
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "-o", "json", "status")
	assertAppError(t, err, apperrors.CodeNetworkError, 2)
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v, want stop after transport error", runner.commands)
	}
}

func TestStatusReturnsResourceNotFoundWhenAllProbesFailRemotely(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{}}
	for _, probe := range observe.StatusProbes() {
		runner.results[probe.Command] = sshexec.Result{ExitCode: 1, Stderr: "unavailable"}
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "-o", "json", "status")
	assertAppError(t, err, apperrors.CodeResourceNotFound, 4)
	if len(runner.commands) != len(observe.StatusProbes()) {
		t.Fatalf("commands = %#v, want all probes attempted", runner.commands)
	}
}

func TestPortsFallsBackToNetstatAndLeavesPrivilegedFieldsEmpty(t *testing.T) {
	configPath := prepareExecContext(t, false)
	ssCommand := observe.PortProbes()[0].Command
	netstatCommand := observe.PortProbes()[1].Command
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		ssCommand:      {ExitCode: 127, Stderr: "ss: command not found"},
		netstatCommand: {Stdout: "udp 0 0 0.0.0.0:53 0.0.0.0:* -\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "ports")
	if err != nil {
		t.Fatalf("ports error = %v", err)
	}
	got := decodeJSONList[observe.Port](t, output, "Ports").Items
	if len(got) != 1 || got[0].LocalPort != 53 || got[0].PID != 0 || got[0].Process != "" {
		t.Fatalf("ports = %#v", got)
	}
	if strings.Join(runner.commands, ",") != ssCommand+","+netstatCommand {
		t.Fatalf("commands = %#v", runner.commands)
	}
}

func TestPortsReturnsResourceNotFoundWhenBothToolsAreMissing(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{}}
	for _, probe := range observe.PortProbes() {
		runner.results[probe.Command] = sshexec.Result{ExitCode: 127, Stderr: probe.Name + ": command not found"}
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "-o", "json", "ports")
	assertAppError(t, err, apperrors.CodeResourceNotFound, 4)
}

func TestPortsFallsBackWhenSSOutputCannotBeParsed(t *testing.T) {
	configPath := prepareExecContext(t, false)
	ssCommand := observe.PortProbes()[0].Command
	netstatCommand := observe.PortProbes()[1].Command
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		ssCommand:      {Stdout: "unexpected ss output\n"},
		netstatCommand: {Stdout: "tcp 0 0 127.0.0.1:22 0.0.0.0:* LISTEN -\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "ports")
	if err != nil {
		t.Fatalf("ports error = %v", err)
	}
	got := decodeJSONList[observe.Port](t, output, "Ports").Items
	if len(got) != 1 || got[0].LocalPort != 22 {
		t.Fatalf("ports = %#v", got)
	}
}

func TestPortsPermissionErrorSurfacesBackendError(t *testing.T) {
	configPath := prepareExecContext(t, false)
	ssCommand := observe.PortProbes()[0].Command
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		ssCommand: {ExitCode: 1, Stderr: "permission denied"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "-o", "json", "ports")
	assertAppError(t, err, apperrors.CodeBackendError, 7)
	if len(runner.commands) != 1 {
		t.Fatalf("commands = %#v, want no fallback after permission error", runner.commands)
	}
}

func TestPortsReturnsValidationErrorWhenNoBackendOutputCanBeParsed(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{}}
	for _, probe := range observe.PortProbes() {
		runner.results[probe.Command] = sshexec.Result{Stdout: "unexpected output\n"}
	}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "-o", "json", "ports")
	assertAppError(t, err, apperrors.CodeValidationFailed, 9)
}

func TestLogsQuotesInjectionAndRedactsStructuredOutput(t *testing.T) {
	configPath := prepareExecContext(t, false)
	opts := observe.LogOptions{
		Unit:  "nginx; rm -rf /",
		Since: "today",
		Lines: 5,
		Grep:  "$(touch /tmp/pwned)",
	}
	command := observe.JournalCommand(opts)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stdout: `{"SYSLOG_IDENTIFIER":"api","MESSAGE":"password=log-secret"}` + "\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "logs",
		"--unit", opts.Unit,
		"--since", opts.Since,
		"--lines", "5",
		"--grep", opts.Grep,
	)
	if err != nil {
		t.Fatalf("logs error = %v", err)
	}
	got := decodeJSONData[logsView](t, output, "Logs")
	if runner.commands[0] != command || cmdclass.Classify(command) != safety.R0 {
		t.Fatalf("command = %q", runner.commands[0])
	}
	if len(got.Lines) != 1 || strings.Contains(output, "log-secret") {
		t.Fatalf("logs = %#v; output = %s", got, output)
	}
}

func TestFileLogsFilterLocallyWithoutShellPipeline(t *testing.T) {
	configPath := prepareExecContext(t, false)
	opts := observe.LogOptions{
		File:  "/var/log/app; rm -rf /",
		Lines: 10,
		Grep:  "ERROR; reboot",
	}
	command := observe.FileCommand(opts)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {Stdout: "INFO ok\nERROR; reboot token=file-secret\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath,
		"-o", "json", "logs",
		"--file", opts.File,
		"--lines", "10",
		"--grep", opts.Grep,
	)
	if err != nil {
		t.Fatalf("logs error = %v", err)
	}
	got := decodeJSONData[logsView](t, output, "Logs")
	if strings.Contains(command, "|") || cmdclass.Classify(command) != safety.R0 {
		t.Fatalf("file command = %q", command)
	}
	if len(got.Lines) != 1 || strings.Contains(output, "file-secret") {
		t.Fatalf("logs = %#v; output = %s", got, output)
	}
}

func TestFileLogsMissingFileIsNotReportedAsMissingTail(t *testing.T) {
	configPath := prepareExecContext(t, false)
	opts := observe.LogOptions{
		File:  "/var/log/password=private.log",
		Lines: 10,
	}
	command := observe.FileCommand(opts)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		command: {
			ExitCode: 1,
			Stderr:   "tail: cannot open '/var/log/password=private.log' for reading: No such file or directory",
		},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath, "-o", "json", "logs", "--file", opts.File, "--lines", "10")
	assertAppError(t, err, apperrors.CodeResourceNotFound, 4)
	appErr := apperrors.AsAppError(err)
	if strings.Contains(appErr.Message, "tail is not available") {
		t.Fatalf("error message = %q, incorrectly reports missing tail", appErr.Message)
	}
	if !strings.Contains(appErr.Message, "log file not found or unreadable") {
		t.Fatalf("error message = %q", appErr.Message)
	}
	if strings.Contains(appErr.Message, "private.log") {
		t.Fatalf("error message leaked path secret: %q", appErr.Message)
	}
}

func TestLogsFallsBackFromJournalctlToSystemctl(t *testing.T) {
	configPath := prepareExecContext(t, false)
	opts := observe.LogOptions{Unit: "nginx", Lines: 20}
	journalCommand := observe.JournalCommand(opts)
	systemctlCommand := observe.SystemctlCommand(opts)
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		journalCommand:   {ExitCode: 127, Stderr: "journalctl: command not found"},
		systemctlCommand: {Stdout: "Active: active (running)\n"},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)

	output, err := executeRoot(t, configPath, "-o", "json", "logs", "--unit", "nginx", "--lines", "20")
	if err != nil {
		t.Fatalf("logs error = %v", err)
	}
	got := decodeJSONData[logsView](t, output, "Logs")
	if got.Meta.Backend != "systemctl" || len(got.Lines) != 1 {
		t.Fatalf("logs = %#v", got)
	}
	for _, command := range runner.commands {
		if cmdclass.Classify(command) != safety.R0 || strings.Contains(command, "sudo") {
			t.Fatalf("fallback command = %q", command)
		}
	}
}
