package cmd

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

func TestExitCodeContract(t *testing.T) {
	t.Run("usage", func(t *testing.T) {
		configPath := prepareExecContext(t, false)
		_, err := executeRoot(t, configPath, "--yes", "exec", "touch ./ready")
		assertAppError(t, err, apperrors.CodeUsageError, 1)
	})

	t.Run("authorization denied", func(t *testing.T) {
		configPath := prepareExecContext(t, false)
		_, err := executeRoot(t, configPath,
			"--non-interactive",
			"exec", "--reason", "prepare deploy", "touch ./ready",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	})

	t.Run("remote nonzero", func(t *testing.T) {
		configPath := prepareExecContext(t, false)
		runner := &fakeSSHRunner{result: sshexec.Result{ExitCode: 19}}
		restore := replaceSSHRunner(runner)
		t.Cleanup(restore)
		_, err := executeRoot(t, configPath, "-o", "json", "exec", "pwd")
		assertAppError(t, err, apperrors.CodeBackendError, 7)
	})

	t.Run("observation resource not found", func(t *testing.T) {
		configPath := prepareExecContext(t, false)
		runner := &scriptedSSHRunner{results: map[string]sshexec.Result{}}
		for _, probe := range observe.PortProbes() {
			runner.results[probe.Command] = sshexec.Result{ExitCode: 127, Stderr: "command not found"}
		}
		restore := replaceSSHRunner(runner)
		t.Cleanup(restore)
		_, err := executeRoot(t, configPath, "-o", "json", "ports")
		assertAppError(t, err, apperrors.CodeResourceNotFound, 4)
	})
}

func TestJSONOutputContract(t *testing.T) {
	configPath := prepareExecContext(t, false)
	logOptions := observe.LogOptions{File: "/var/log/app.log", Lines: 2}
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		"hostname":                      {Stdout: "web-01\n"},
		"uname -srm":                    {Stdout: "Linux 6.8.0\n"},
		"cat /proc/uptime":              {Stdout: "1 1\n"},
		"cat /proc/loadavg":             {Stdout: "0 0 0 1/1 1\n"},
		"cat /proc/cpuinfo":             {},
		"cat /proc/meminfo":             {},
		"df -Pk":                        {},
		observe.PortProbes()[0].Command: {Stdout: ""},
		observe.FileCommand(logOptions): {Stdout: "line\n"},
		fileReadCommand("/tmp/app", defaultFileReadMaxBytes): {Stdout: "hello\n"},
		fileStatCommand("/tmp/app"): {
			Stdout: "regular file\t6\t640\talice\tstaff\t1710000000\n",
		},
		fileListCommand("/tmp/app"): {
			Stdout: "hello.txt\x00f\x006\x00640\x001710000000.0\x00",
		},
		dockerListCommand(): {
			Stdout: `{"ID":"abc","Names":"api","Image":"repo:tag","State":"running","Status":"Up","Ports":"80/tcp","CreatedAt":"now"}` + "\n",
		},
		dockerInspectCommand("api"): {
			Stdout: `{"id":"abc","name":"/api","image":"repo:tag","state":"running","status":"running","restartPolicy":"no","ports":{},"mounts":[],"createdAt":"now"}`,
		},
		dockerLogsCommand("api", defaultDockerLogTail): {Stdout: "ready\n"},
		dockerActionCommand("restart", "api"):          {},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)
	stdinRunner := &scriptedStdinSSHRunner{}
	restoreStdin := replaceSSHStdinRunner(stdinRunner)
	t.Cleanup(restoreStdin)
	cases := []struct {
		name     string
		args     []string
		wantKind string
		wantList bool
	}{
		{name: "exec dry-run object", args: []string{"-o", "json", "exec", "--dry-run", "pwd"}, wantKind: "ExecDryRun"},
		{name: "status object", args: []string{"-o", "json", "status"}, wantKind: "ServerStatus"},
		{name: "ports list", args: []string{"-o", "json", "ports"}, wantKind: "Ports", wantList: true},
		{name: "logs object", args: []string{"-o", "json", "logs", "--file", logOptions.File, "--lines", "2"}, wantKind: "Logs"},
		{name: "svc status object", args: []string{"-o", "json", "svc", "status", "nginx"}, wantKind: "ServiceStatus"},
		{name: "file read object", args: []string{"-o", "json", "file", "read", "/tmp/app"}, wantKind: "FileRead"},
		{name: "file stat object", args: []string{"-o", "json", "file", "stat", "/tmp/app"}, wantKind: "FileStat"},
		{name: "file list", args: []string{"-o", "json", "file", "list", "/tmp/app"}, wantKind: "FileList", wantList: true},
		{
			name:     "file write object",
			wantKind: "FileWrite",
			args: []string{
				"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
				"file", "write", "/tmp/app", "--content", "hello", "--reason", "update test file",
			},
		},
		{name: "docker list", args: []string{"-o", "json", "docker", "list"}, wantKind: "DockerList", wantList: true},
		{name: "docker inspect object", args: []string{"-o", "json", "docker", "inspect", "api"}, wantKind: "DockerInspect"},
		{name: "docker logs object", args: []string{"-o", "json", "docker", "logs", "api"}, wantKind: "DockerLogs"},
		{
			name:     "docker action object",
			wantKind: "DockerAction",
			args: []string{
				"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
				"docker", "restart", "api", "--reason", "restart test container",
			},
		},
		{name: "capabilities object", args: []string{"-o", "json", "capabilities"}, wantKind: "Capabilities"},
		{name: "ctx list", args: []string{"-o", "json", "ctx", "list"}, wantKind: "ContextList", wantList: true},
		{name: "ctx role list", args: []string{"-o", "json", "ctx", "role", "list", "dev"}, wantKind: "RoleList", wantList: true},
		{name: "audit query object", args: []string{"-o", "json", "audit", "query"}, wantKind: "AuditQueryResult"},
		{name: "audit verify object", args: []string{"-o", "json", "audit", "verify", "--path", "testdata/missing-audit.log"}, wantKind: "AuditVerifyResult"},
		{name: "audit prune object", args: []string{"-o", "json", "audit", "prune", "--path", "testdata/missing-audit.log", "--keep-last", "1"}, wantKind: "AuditPruneResult"},
		{name: "doctor object", args: []string{"-o", "json", "doctor"}, wantKind: "DoctorReport"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := executeRoot(t, configPath, tc.args...)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			raw := decodeJSONRawData(t, output, tc.wantKind)
			if tc.wantList {
				var list struct {
					Items []json.RawMessage `json:"items"`
				}
				if err := json.Unmarshal(raw, &list); err != nil {
					t.Fatalf("Unmarshal(list data) error = %v; output = %q", err, output)
				}
				if list.Items == nil {
					t.Fatalf("data.items = nil, want list envelope items; output = %q", output)
				}
			}
		})
	}
}

func TestVersionDefaultsRemainLocal(t *testing.T) {
	SetVersionInfo("dev", "", "")
	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "-o", "json", "version")
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	got := decodeJSONData[versionInfo](t, output, "VersionInfo")
	if got.Version != "dev" || got.Commit != unknownBuildValue || got.Built != unknownBuildValue {
		t.Fatalf("version defaults = %#v", got)
	}
}
