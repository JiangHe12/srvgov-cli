package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

func TestCommandGoldenOutputs(t *testing.T) {
	configPath := prepareExecContext(t, false)
	t.Setenv("SRVGOV_MASTER_PASSWORD", "golden-master-password")
	logOptions := observe.LogOptions{File: "/var/log/app.log", Lines: 2}
	runner := &scriptedSSHRunner{results: map[string]sshexec.Result{
		"hostname":                      {Stdout: "web-01\n"},
		"uname -srm":                    {Stdout: "Linux 6.8.0 x86_64\n"},
		"cat /proc/uptime":              {Stdout: "123.5 10.0\n"},
		"cat /proc/loadavg":             {Stdout: "0.1 0.2 0.3 1/10 2\n"},
		"cat /proc/cpuinfo":             {Stdout: "processor: 0\nmodel name: Example CPU\n"},
		"cat /proc/meminfo":             {Stdout: "MemTotal: 1000 kB\nMemAvailable: 400 kB\n"},
		"df -Pk":                        {Stdout: "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda 1000 600 400 60% /\n"},
		"ss -H -lntup":                  {Stdout: "tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:*\n"},
		observe.FileCommand(logOptions): {Stdout: "first line\nsecond line\n"},
		serviceStatusCommand("nginx"): {
			Stdout: "LoadState=loaded\nActiveState=active\nSubState=running\nUnitFileState=enabled\nDescription=nginx web server\nMainPID=123\n",
		},
		fileReadCommand("/tmp/app.txt", defaultFileReadMaxBytes): {
			Stdout: "hello\n",
		},
		fileStatCommand("/tmp/app.txt"): {
			Stdout: "regular file\t6\t640\talice\tstaff\t1710000000\n",
		},
		fileListCommand("/tmp"): {
			Stdout: "app.txt\x00f\x006\x00640\x001710000000.0\x00logs\x00d\x000\x00755\x001710000001.0\x00",
		},
		dockerListCommand(): {
			Stdout: `{"ID":"abc","Names":"api","Image":"repo:tag","State":"running","Status":"Up 2 hours","Ports":"0.0.0.0:8080->80/tcp","CreatedAt":"2026-06-11 10:00:00 +0000 UTC"}` + "\n",
		},
		dockerInspectCommand("api"): {
			Stdout: `{"id":"abc","name":"/api","image":"repo:tag","state":"running","status":"running","restartPolicy":"unless-stopped","ports":{"80/tcp":[{"HostIp":"0.0.0.0","HostPort":"8080"}]},"mounts":[{"Type":"bind","Source":"/srv/api","Destination":"/app","Mode":"ro","RW":false}],"createdAt":"2026-06-11T10:00:00Z"}`,
		},
		dockerLogsCommand("api", defaultDockerLogTail): {
			Stdout: "ready\nserving\n",
		},
		dockerActionCommand("restart", "api"): {},
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)
	stdinRunner := &scriptedStdinSSHRunner{}
	restoreStdin := replaceSSHStdinRunner(stdinRunner)
	t.Cleanup(restoreStdin)
	cases := []struct {
		name string
		args []string
	}{
		{name: "exec_dry_run_json", args: []string{"-o", "json", "exec", "--dry-run", "pwd"}},
		{name: "exec_dry_run_table", args: []string{"-o", "table", "exec", "--dry-run", "pwd"}},
		{name: "status_json", args: []string{"-o", "json", "status"}},
		{name: "status_table", args: []string{"-o", "table", "status"}},
		{name: "ports_json", args: []string{"-o", "json", "ports"}},
		{name: "ports_table", args: []string{"-o", "table", "ports"}},
		{name: "logs_json", args: []string{"-o", "json", "logs", "--file", logOptions.File, "--lines", "2"}},
		{name: "logs_table", args: []string{"-o", "table", "logs", "--file", logOptions.File, "--lines", "2"}},
		{name: "svc_status_json", args: []string{"-o", "json", "svc", "status", "nginx"}},
		{name: "svc_status_table", args: []string{"-o", "table", "svc", "status", "nginx"}},
		{name: "file_read_json", args: []string{"-o", "json", "file", "read", "/tmp/app.txt"}},
		{name: "file_read_table", args: []string{"-o", "table", "file", "read", "/tmp/app.txt"}},
		{name: "file_stat_json", args: []string{"-o", "json", "file", "stat", "/tmp/app.txt"}},
		{name: "file_stat_table", args: []string{"-o", "table", "file", "stat", "/tmp/app.txt"}},
		{name: "file_list_json", args: []string{"-o", "json", "file", "list", "/tmp"}},
		{name: "file_list_table", args: []string{"-o", "table", "file", "list", "/tmp"}},
		{
			name: "file_write_json",
			args: []string{
				"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
				"file", "write", "/tmp/app.txt", "--content", "hello\n", "--reason", "update test file",
			},
		},
		{
			name: "file_write_table",
			args: []string{
				"-o", "table", "--non-interactive", "--yes", "--ticket", "OPS-42",
				"file", "write", "/tmp/app.txt", "--content", "hello\n", "--reason", "update test file",
			},
		},
		{name: "docker_list_json", args: []string{"-o", "json", "docker", "list"}},
		{name: "docker_list_table", args: []string{"-o", "table", "docker", "list"}},
		{name: "docker_inspect_json", args: []string{"-o", "json", "docker", "inspect", "api"}},
		{name: "docker_inspect_table", args: []string{"-o", "table", "docker", "inspect", "api"}},
		{name: "docker_logs_json", args: []string{"-o", "json", "docker", "logs", "api"}},
		{name: "docker_logs_table", args: []string{"-o", "table", "docker", "logs", "api"}},
		{
			name: "docker_action_json",
			args: []string{
				"-o", "json", "--non-interactive", "--yes", "--ticket", "OPS-42",
				"docker", "restart", "api", "--reason", "restart test container",
			},
		},
		{
			name: "docker_action_table",
			args: []string{
				"-o", "table", "--non-interactive", "--yes", "--ticket", "OPS-42",
				"docker", "restart", "api", "--reason", "restart test container",
			},
		},
		{name: "capabilities_json", args: []string{"-o", "json", "capabilities"}},
		{name: "capabilities_table", args: []string{"-o", "table", "capabilities"}},
		{name: "ctx_list_json", args: []string{"-o", "json", "ctx", "list"}},
		{name: "ctx_list_table", args: []string{"-o", "table", "ctx", "list"}},
		{name: "ctx_role_list_json", args: []string{"-o", "json", "ctx", "role", "list", "dev"}},
		{name: "ctx_export", args: []string{"ctx", "export", "dev"}},
		{name: "ctx_migrate_credentials_json", args: []string{"-o", "json", "ctx", "migrate-credentials", "--to", "encrypted-file", "--context", "dev"}},
		{name: "audit_query_json", args: []string{"-o", "json", "audit", "query", "--path", "testdata/missing-audit.log"}},
		{name: "audit_query_table", args: []string{"-o", "table", "audit", "query", "--path", "testdata/missing-audit.log"}},
		{name: "audit_verify_json", args: []string{"-o", "json", "audit", "verify", "--path", "testdata/missing-audit.log"}},
		{name: "audit_prune_json", args: []string{"-o", "json", "audit", "prune", "--path", "testdata/missing-audit.log", "--keep-last", "1"}},
		{name: "doctor_json", args: []string{"-o", "json", "doctor"}},
		{name: "doctor_table", args: []string{"-o", "table", "doctor"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			output, err := executeRoot(t, configPath, tc.args...)
			if err != nil {
				t.Fatalf("Execute() error = %v", err)
			}
			actual := normalizeGolden(output)
			path := filepath.Join("testdata", "golden", tc.name+".golden")
			expected, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v\nactual:\n%s", path, err, actual)
			}
			if actual != normalizeGolden(string(expected)) {
				t.Fatalf("golden mismatch for %s\nactual:\n%s\nexpected:\n%s", tc.name, actual, expected)
			}
		})
	}
}

func normalizeGolden(value string) string {
	lines := strings.Split(strings.ReplaceAll(value, "\r\n", "\n"), "\n")
	for index := range lines {
		lines[index] = strings.TrimRight(lines[index], " \t")
	}
	return strings.Join(lines, "\n")
}
