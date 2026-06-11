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
	}}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)
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
