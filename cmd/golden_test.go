package cmd

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestCommandGoldenOutputs(t *testing.T) {
	configPath := prepareExecContext(t, false)
	t.Setenv("SRVGOV_MASTER_PASSWORD", "golden-master-password")
	cases := []struct {
		name string
		args []string
	}{
		{name: "exec_dry_run_json", args: []string{"-o", "json", "exec", "--dry-run", "pwd"}},
		{name: "exec_dry_run_table", args: []string{"-o", "table", "exec", "--dry-run", "pwd"}},
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
	return strings.ReplaceAll(value, "\r\n", "\n")
}
