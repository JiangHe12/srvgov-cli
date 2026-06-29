package cmd

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/JiangHe12/opskit-core/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/audit"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
)

func TestAuditQueryRedactsLegacyRecords(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	event := srvgovaudit.Event{
		Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		EventType: srvgovaudit.EventTypeExecRun,
		Operator:  "alice",
		Context:   srvgovaudit.Context{Name: "dev"},
		Target:    srvgovaudit.Target{Host: "example.com:22"},
		Command:   "echo password=command-secret",
		RiskTier:  "R0",
		Status:    srvgovaudit.StatusSucceeded,
		Stdout:    "token=stdout-secret",
		Stderr:    "secretKey: stderr-secret",
		ExitCode:  0,
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	for _, format := range []string{"json", "table"} {
		output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
			"-o", format, "audit", "query", "--path", path,
		)
		if err != nil {
			t.Fatalf("audit -o %s error = %v", format, err)
		}
		for _, secret := range []string{"command-secret", "stdout-secret", "stderr-secret"} {
			if strings.Contains(output, secret) {
				t.Fatalf("audit -o %s leaked %q: %s", format, secret, output)
			}
		}
		if !strings.Contains(output, "[REDACTED]") {
			t.Fatalf("audit -o %s output = %q", format, output)
		}
	}
}

func TestAuditQueryFiltersEventType(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	records := []srvgovaudit.Event{
		{
			Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeExecRun,
			Context:   srvgovaudit.Context{Name: "dev"},
			Target:    srvgovaudit.Target{Host: "example.com:22"},
			RiskTier:  "R0",
			Status:    srvgovaudit.StatusSucceeded,
		},
		{
			Timestamp: time.Date(2026, 6, 10, 12, 1, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeAuthorizationDenied,
			Context:   srvgovaudit.Context{Name: "prod"},
			Target:    srvgovaudit.Target{Host: "prod.example.com:22"},
			RiskTier:  "R3",
			Status:    srvgovaudit.StatusDenied,
		},
	}
	var content strings.Builder
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		content.Write(data)
		content.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "query", "--path", path, "--type", "authorization.denied",
	)
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	got := decodeJSONData[auditQueryResult](t, output, "AuditQueryResult")
	if len(got.Events) != 1 || got.Events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied {
		t.Fatalf("events = %#v", got.Events)
	}
}

func TestAuditQueryReverseAndLimitAreAppliedAfterDecode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	records := []srvgovaudit.Event{
		{
			Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeExecRun,
			Operator:  "alice",
			Context:   srvgovaudit.Context{Name: "dev"},
			Target:    srvgovaudit.Target{Host: "example.com:22"},
			RiskTier:  "R0",
			Status:    srvgovaudit.StatusSucceeded,
		},
		{
			Timestamp: time.Date(2026, 6, 10, 12, 1, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeAuditVerify,
			Operator:  "alice",
			Context:   srvgovaudit.Context{Name: "dev"},
			Target:    srvgovaudit.Target{Host: "audit.verify"},
			RiskTier:  "R0",
			Status:    srvgovaudit.StatusSucceeded,
		},
	}
	var content strings.Builder
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		content.Write(data)
		content.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "query", "--path", path, "--reverse", "--limit", "1",
	)
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	got := decodeJSONData[auditQueryResult](t, output, "AuditQueryResult")
	if len(got.Events) != 1 || got.Events[0].EventType != srvgovaudit.EventTypeAuditVerify {
		t.Fatalf("events = %#v", got.Events)
	}
}

func TestAuditVerifyStrictReturnsValidationFailed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "verify", "--path", path, "--strict",
	)
	assertAppError(t, err, apperrors.CodeValidationFailed, 9)
	got := decodeJSONData[coreaudit.VerifyResult](t, output, "AuditVerifyResult")
	if got.Malformed != 1 {
		t.Fatalf("verify result = %#v", got)
	}
}

func TestAuditPruneDeletesRotatedLogsOnlyWithConfirm(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "audit.log")
	oldRotated := filepath.Join(dir, "audit.log.20260101-000000.log")
	newRotated := filepath.Join(dir, "audit.log.20260201-000000.log")
	for _, filePath := range []string{path, oldRotated, newRotated} {
		if err := os.WriteFile(filePath, []byte("{}\n"), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", filePath, err)
		}
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "prune", "--path", path, "--keep-last", "1",
	)
	if err != nil {
		t.Fatalf("audit prune dry-run error = %v", err)
	}
	preview := decodeJSONData[auditPruneResult](t, output, "AuditPruneResult")
	if !preview.DryRun || preview.Count != 1 || preview.Files[0] != oldRotated {
		t.Fatalf("preview = %#v", preview)
	}
	if _, err := os.Stat(oldRotated); err != nil {
		t.Fatalf("old rotated stat after dry-run = %v", err)
	}

	_, err = executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "prune", "--path", path, "--keep-last", "1", "--confirm",
	)
	if err != nil {
		t.Fatalf("audit prune confirm error = %v", err)
	}
	if _, err := os.Stat(oldRotated); !os.IsNotExist(err) {
		t.Fatalf("old rotated stat after confirm = %v", err)
	}
	if _, err := os.Stat(newRotated); err != nil {
		t.Fatalf("new rotated stat after confirm = %v", err)
	}
}
