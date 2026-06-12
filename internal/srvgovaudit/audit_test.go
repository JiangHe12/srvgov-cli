package srvgovaudit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	coreaudit "github.com/JiangHe12/opskit-core/audit"
)

func TestAppendRedactsSensitiveFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
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
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	raw := string(data)
	for _, secret := range []string{"hunter2", "stdout-secret", "stderr-secret", "error-secret", "path-secret"} {
		if strings.Contains(raw, secret) {
			t.Fatalf("audit leaked %q:\n%s", secret, raw)
		}
	}

	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("Unmarshal() error = %v", err)
	}
	if got.EventType != EventTypeExecRun || got.RiskTier != "R3" || got.ExitCode != 7 {
		t.Fatalf("event = %#v", got)
	}
}

func TestEventTypesAndStatuses(t *testing.T) {
	if EventTypeExecRun != "exec.run" || EventTypeAuthorizationDenied != "authorization.denied" {
		t.Fatalf("event types = %q/%q", EventTypeExecRun, EventTypeAuthorizationDenied)
	}
	if StatusSucceeded != "succeeded" || StatusFailed != "failed" || StatusDenied != "denied" {
		t.Fatalf("statuses = %q/%q/%q", StatusSucceeded, StatusFailed, StatusDenied)
	}
}

func TestAppendSerializesConcurrentRecordsInProcess(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

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
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if lines := bytes.Count(bytes.TrimSpace(data), []byte("\n")) + 1; lines != count {
		t.Fatalf("audit lines = %d, want %d", lines, count)
	}
}
