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
	var got CapabilitiesData
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v; output = %q", err, output)
	}
	if got.Tool.Name != "srvgov" || got.Supported.ContextAPIVersion != "srvgov.io/context/v1" {
		t.Fatalf("capabilities = %#v", got)
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
	for _, command := range []string{"ctx", "exec", "status", "ports", "logs", "svc", "file", "audit", "doctor", "version", "install"} {
		if !containsString(got.Supported.Commands, command) {
			t.Fatalf("commands = %#v, want %q", got.Supported.Commands, command)
		}
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
