package cmd

import (
	"path/filepath"
	"testing"
)

func TestDoctorReportsLocalChecks(t *testing.T) {
	configPath := prepareExecContext(t, false)
	output, err := executeRoot(t, configPath, "-o", "json", "doctor")
	if err != nil {
		t.Fatalf("doctor error = %v", err)
	}
	report := decodeJSONData[DoctorReport](t, output, "DoctorReport")
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
	report := decodeJSONData[DoctorReport](t, output, "DoctorReport")
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
	got := decodeJSONData[struct {
		Version string `json:"version"`
		Commit  string `json:"commit"`
		Built   string `json:"built"`
	}](t, output, "VersionInfo")
	if got.Version != "v3.0.0-test" || got.Commit != "deadbeef" || got.Built != "2026-06-10" {
		t.Fatalf("version info = %#v", got)
	}
}

func TestVersionTableOutput(t *testing.T) {
	SetVersionInfo("v3.0.0-test", "deadbeef", "2026-06-10")
	t.Cleanup(func() { SetVersionInfo("dev", "", "") })
	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "-o", "table", "version")
	if err != nil {
		t.Fatalf("version error = %v", err)
	}
	if want := "srvgov-cli v3.0.0-test (commit: deadbeef, built: 2026-06-10)\n"; output != want {
		t.Fatalf("version table = %q, want %q", output, want)
	}
}
