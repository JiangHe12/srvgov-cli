package cmd

import (
	"encoding/json"
	"path/filepath"
	"testing"
)

func TestDoctorReportsLocalChecks(t *testing.T) {
	configPath := prepareExecContext(t, false)
	output, err := executeRoot(t, configPath, "-o", "json", "doctor")
	if err != nil {
		t.Fatalf("doctor error = %v", err)
	}
	var report DoctorReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("Unmarshal() error = %v; output = %q", err, output)
	}
	if len(report.Checks) != 4 {
		t.Fatalf("checks = %#v", report.Checks)
	}
	wantNames := []string{"config", "current-context", "credential-store", "known-hosts"}
	for i, want := range wantNames {
		if report.Checks[i].Name != want || report.Checks[i].Status != "ok" {
			t.Fatalf("check[%d] = %#v", i, report.Checks[i])
		}
	}
}

func TestDoctorReportsMissingCurrentContext(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	output, err := executeRoot(t, configPath, "-o", "json", "doctor")
	if err != nil {
		t.Fatalf("doctor error = %v", err)
	}
	var report DoctorReport
	if err := json.Unmarshal([]byte(output), &report); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if report.Checks[1].Name != "current-context" || report.Checks[1].Status != "fail" {
		t.Fatalf("current-context check = %#v", report.Checks[1])
	}
}

func TestVersionOutput(t *testing.T) {
	SetVersionInfo("v3.0.0-test", "deadbeef", "2026-06-10")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })
	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "-o", "json", "version")
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	var got versionInfo
	if err := json.Unmarshal([]byte(output), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v; output = %q", err, output)
	}
	if got.Version != "v3.0.0-test" || got.Commit != "deadbeef" || got.Date != "2026-06-10" {
		t.Fatalf("version info = %#v", got)
	}
}
