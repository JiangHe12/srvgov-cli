package srvgovaudit

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
)

func TestAppendPersistsOnlyFingerprintsForSensitiveFields(t *testing.T) {
	path := privateAuditTestPath(t)
	event := Event{
		Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		EventType: EventTypeExecRun,
		Operator:  "alice",
		Context: Context{
			Name:      "prod",
			Env:       "production",
			Protected: true,
		},
		Ticket:   "OPS-1",
		Reason:   "rotate service",
		Target:   Target{Host: "server.example:22"},
		Command:  "deploy --password hunter2",
		RiskTier: "R3",
		Status:   StatusFailed,
		Stdout:   "token=stdout-secret",
		Stderr:   "secretKey: stderr-secret",
		ExitCode: 7,
		Error:    &ErrorInfo{Code: "BACKEND_ERROR", Message: "password=error-secret"},
		File:     &FileInfo{Path: "/tmp/password=path-secret", BytesWritten: 12, SHA256: "abc"},
	}

	if err := Append(path, event, coreaudit.Options{}); err != nil {
		t.Fatalf("Append() error = %v", err)
	}
	rawResult, err := coreaudit.QueryRaw(path, coreaudit.Filter{})
	if err != nil {
		t.Fatalf("QueryRaw() error = %v", err)
	}
	if len(rawResult.Records) != 1 {
		t.Fatalf("QueryRaw() records = %d, want 1", len(rawResult.Records))
	}
	raw := rawResult.Records[0].Line
	for _, secret := range []string{
		"OPS-1",
		"rotate service",
		"server.example:22",
		"deploy --password hunter2",
		"stdout-secret",
		"stderr-secret",
		"error-secret",
		"path-secret",
	} {
		if strings.Contains(raw, secret) {
			t.Fatalf("audit leaked %q:\n%s", secret, raw)
		}
	}

	var got Event
	if err := json.Unmarshal([]byte(raw), &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.EventType != EventTypeExecRun || got.RiskTier != "R3" || got.ExitCode != 7 {
		t.Fatalf("event = %#v", got)
	}
	if got.Ticket != "" || got.Reason != "" || got.Target.Host != "" ||
		got.Command != "" || got.Stdout != "" || got.Stderr != "" ||
		got.Error == nil || got.Error.Message != "" ||
		got.File == nil || got.File.Path != "" {
		t.Fatalf("raw fields persisted: %#v", got)
	}
	for name, value := range map[string]string{
		"ticket":    got.TicketFingerprint,
		"reason":    got.ReasonFingerprint,
		"target":    got.Target.Fingerprint,
		"command":   got.CommandFingerprint,
		"stdout":    got.StdoutFingerprint,
		"stderr":    got.StderrFingerprint,
		"file path": got.File.PathFingerprint,
	} {
		if !strings.HasPrefix(value, "sha256:") {
			t.Fatalf("%s fingerprint = %q", name, value)
		}
	}
}

func TestEventTypesAndStatuses(t *testing.T) {
	if EventTypeExecRun != "exec.run" || EventTypeAuthorizationDenied != "authorization.denied" {
		t.Fatalf("event types = %q/%q", EventTypeExecRun, EventTypeAuthorizationDenied)
	}
	if EventTypeContextSet != "context.set" ||
		EventTypeContextUse != "context.use" ||
		EventTypeContextDelete != "context.delete" {
		t.Fatalf("context event types = %q/%q/%q", EventTypeContextSet, EventTypeContextUse, EventTypeContextDelete)
	}
	if StatusSucceeded != "succeeded" || StatusFailed != "failed" || StatusDenied != "denied" {
		t.Fatalf("statuses = %q/%q/%q", StatusSucceeded, StatusFailed, StatusDenied)
	}
}

func TestSanitizeClearsForgedFingerprintFields(t *testing.T) {
	event := Sanitize(Event{
		TicketFingerprint:  "ticket=secret",
		TicketBytes:        13,
		ReasonFingerprint:  "sha256:ABC",
		ReasonBytes:        3,
		CommandFingerprint: "sha256:" + strings.Repeat("0", 64),
		CommandBytes:       -1,
		Target: Target{
			Fingerprint: "sha256:" + strings.Repeat("1", 64),
			Bytes:       4,
		},
		Metadata: &MutationMetadata{
			TargetFingerprint:  "raw-target-secret",
			TargetBytes:        17,
			PayloadFingerprint: "sha256:" + strings.Repeat("2", 64),
			PayloadBytes:       9,
			Items:              -1,
			Revision:           strings.Repeat("x", 257),
		},
		Outcome: &MutationOutcome{
			Status:             StatusFailed,
			PayloadFingerprint: "payload=secret",
			PayloadBytes:       14,
			Succeeded:          -1,
			Revision:           strings.Repeat("y", 257),
		},
	})
	if event.TicketFingerprint != "" || event.TicketBytes != 0 ||
		event.ReasonFingerprint != "" || event.ReasonBytes != 0 ||
		event.CommandFingerprint != "" || event.CommandBytes != 0 {
		t.Fatalf("forged top-level fingerprints survived: %#v", event)
	}
	if !ValidFingerprint(event.Target.Fingerprint, event.Target.Bytes) {
		t.Fatalf("canonical target fingerprint was removed: %#v", event.Target)
	}
	if event.Metadata == nil || event.Metadata.TargetFingerprint != "" ||
		event.Metadata.TargetBytes != 0 ||
		!ValidFingerprint(event.Metadata.PayloadFingerprint, event.Metadata.PayloadBytes) ||
		event.Metadata.Items != 0 || event.Metadata.Revision != "" {
		t.Fatalf("metadata sanitization = %#v", event.Metadata)
	}
	if event.Outcome == nil || event.Outcome.PayloadFingerprint != "" ||
		event.Outcome.PayloadBytes != 0 || event.Outcome.Succeeded != 0 ||
		event.Outcome.Revision != "" {
		t.Fatalf("outcome sanitization = %#v", event.Outcome)
	}
}

func TestAppendSerializesConcurrentRecordsInProcess(t *testing.T) {
	path := privateAuditTestPath(t)

	const count = 16
	start := make(chan struct{})
	errors := make(chan error, count)
	var workers sync.WaitGroup
	workers.Add(count)
	for index := range count {
		go func() {
			defer workers.Done()
			<-start
			errors <- Append(path, Event{
				EventType: EventTypeExecRun,
				Context:   Context{Name: "target"},
				Target:    Target{Host: "example.com:22"},
				Command:   "pwd",
				RiskTier:  "R0",
				Status:    StatusSucceeded,
				ExitCode:  index,
			}, coreaudit.Options{})
		}()
	}
	close(start)
	workers.Wait()
	close(errors)

	for err := range errors {
		if err != nil {
			t.Fatalf("Append() error = %v", err)
		}
	}
	result, err := coreaudit.QueryRaw(path, coreaudit.Filter{})
	if err != nil {
		t.Fatalf("QueryRaw() error = %v", err)
	}
	if len(result.Records) != count {
		t.Fatalf("audit records = %d, want %d", len(result.Records), count)
	}
}

func privateAuditTestPath(t *testing.T) string {
	t.Helper()
	tempDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks(test temp directory) error = %v", err)
	}
	directory := filepath.Join(tempDir, "private-audit")
	secureAuditTestDirectory(t, directory)
	return filepath.Join(directory, "audit.log")
}
