package cmd

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
)

func TestCapabilitiesReflectSrvGovSurface(t *testing.T) {
	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "-o", "json", "capabilities")
	if err != nil {
		t.Fatalf("capabilities error = %v", err)
	}
	got := decodeJSONData[CapabilitiesData](t, output, "Capabilities")
	if got.Tool.Name != "srvgov" || strings.Join(got.Supported.ContextAPIVersions, ",") != "srvgov-cli.io/context/v1" {
		t.Fatalf("capabilities = %#v", got)
	}
	if strings.Join(got.Supported.AuditAPIVersions, ",") != "srvgov-cli.io/audit/v1" {
		t.Fatalf("audit API versions = %#v", got.Supported.AuditAPIVersions)
	}
	if strings.Join(got.Supported.AllowFlags, ",") != "--allow-destructive" {
		t.Fatalf("allow flags = %#v", got.Supported.AllowFlags)
	}
	if len(got.Supported.RiskModel) != 4 {
		t.Fatalf("risk model = %#v", got.Supported.RiskModel)
	}
	if !got.Supported.Governance.DryRun || got.Supported.Governance.TOFU == "" || got.Supported.Governance.Redaction == "" {
		t.Fatalf("governance = %#v", got.Supported.Governance)
	}
	if got.Supported.Governance.Fanout != "status, ports, and logs require R0 for every target; exec, svc, file, and docker authorize every target before any execution; --selector resolves targets by context labels" {
		t.Fatalf("fanout = %q", got.Supported.Governance.Fanout)
	}
	for _, command := range []string{"ctx", "exec", "status", "ports", "logs", "svc", "file", "docker", "audit", "doctor", "version", "install"} {
		if !containsString(got.Supported.Commands, command) {
			t.Fatalf("commands = %#v, want %q", got.Supported.Commands, command)
		}
	}
}

func TestCapabilitiesJSONFamilySchema(t *testing.T) {
	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "-o", "json", "capabilities")
	if err != nil {
		t.Fatalf("capabilities error = %v", err)
	}
	var env struct {
		Data struct {
			Supported struct {
				ContextAPIVersions []string `json:"contextApiVersions"`
				AuditAPIVersions   []string `json:"auditApiVersions"`
			} `json:"supported"`
			Domain json.RawMessage `json:"domain"`
		} `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &env); err != nil {
		t.Fatalf("capabilities output is not JSON: %v\n%s", err, output)
	}
	if strings.Join(env.Data.Supported.ContextAPIVersions, ",") != "srvgov-cli.io/context/v1" {
		t.Fatalf("context API versions = %#v", env.Data.Supported.ContextAPIVersions)
	}
	if strings.Join(env.Data.Supported.AuditAPIVersions, ",") != "srvgov-cli.io/audit/v1" {
		t.Fatalf("audit API versions = %#v", env.Data.Supported.AuditAPIVersions)
	}
	if len(env.Data.Domain) != 0 {
		t.Fatalf("domain = %s, want omitted", env.Data.Domain)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}
