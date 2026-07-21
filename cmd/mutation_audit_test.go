package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestMutationAuditWritesSanitizedIntentThenOutcome(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	var records []mutationAuditRecord
	runtime := &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ coreaudit.Options) error {
			records = append(records, record)
			return nil
		},
		now:    func() time.Time { return time.Unix(100, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x2a}, 16)),
	}
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit:   runtime,
	}
	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:      "exec.run",
		ContextName: "production",
		Context:     srvgovctx.Context{Host: "secret-host.example"},
		Target:      "secret-host.example:22",
		RiskTier:    "R3",
		Ticket:      "TICKET-SECRET",
		Reason:      "because secret",
		Metadata:    mutationPayloadMetadata("exec.run", []byte("printf SUPER-SECRET")),
		AuditPath:   filepath.Join(dir, "audit.log"),
	})
	if err != nil {
		t.Fatalf("beginMutationAudit() error = %v", err)
	}
	if len(records) != 1 || records[0].Phase != mutationAuditPhaseIntent {
		t.Fatalf("records after begin = %#v", records)
	}
	operationErr := apperrors.New(apperrors.CodeBackendError, "raw backend failure", nil)
	err = finishMutationAudit(handle, mutationAuditOutcome{Failed: 1}, operationErr)
	if !errors.Is(err, operationErr) {
		t.Fatalf("finishMutationAudit() error = %v, want operation error", err)
	}
	if len(records) != 2 || records[1].Phase != mutationAuditPhaseOutcome {
		t.Fatalf("records after finish = %#v", records)
	}
	if records[0].MutationID == "" || records[0].MutationID != records[1].MutationID {
		t.Fatalf("mutation IDs = %q, %q", records[0].MutationID, records[1].MutationID)
	}
	encoded, err := json.Marshal(records)
	if err != nil {
		t.Fatalf("Marshal(records) error = %v", err)
	}
	for _, secret := range []string{
		"TICKET-SECRET",
		"because secret",
		"printf SUPER-SECRET",
		"secret-host.example:22",
		"raw backend failure",
	} {
		if bytes.Contains(encoded, []byte(secret)) {
			t.Fatalf("mutation audit contains raw value %q: %s", secret, encoded)
		}
	}
	if !bytes.Contains(encoded, []byte(`"ticketFingerprint":"sha256:`)) ||
		!bytes.Contains(encoded, []byte(`"payloadFingerprint":"sha256:`)) ||
		!bytes.Contains(encoded, []byte(`"errorCode":"BACKEND_ERROR"`)) {
		t.Fatalf("mutation audit lacks sanitized metadata: %s", encoded)
	}
}

func TestMutationOutcomeFailureSpoolsAndNextBeginReplays(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	var calls int
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecordWithResult: func(
				_ string,
				_ mutationAuditRecord,
				_ coreaudit.Options,
			) (coreaudit.AppendResult, error) {
				calls++
				if calls == 1 {
					return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
				}
				return coreaudit.AppendResult{State: coreaudit.AppendCommitNotCommitted},
					errors.New("audit unavailable")
			},
			now:    func() time.Time { return time.Unix(200, 0).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x31}, 16)),
		},
	}
	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.set",
		Target:    "secret-context",
		Ticket:    "TICKET-SECRET",
		Reason:    "SECRET-REASON",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("beginMutationAudit() error = %v", err)
	}
	err = finishMutationAudit(handle, mutationAuditOutcome{Succeeded: 1}, nil)
	if code := apperrors.AsAppError(err).Code; code != codeAuditIncomplete {
		t.Fatalf("finish code = %s, want %s; err=%v", code, codeAuditIncomplete, err)
	}
	spoolPath := mutationAuditSpoolPath(auditPath)
	spooled := mutationSpoolJSONFiles(t, spoolPath)
	if len(spooled) != 1 {
		t.Fatalf("spooled files = %v, want one", spooled)
	}
	data, readErr := os.ReadFile(spooled[0])
	if readErr != nil {
		t.Fatalf("ReadFile(spool) error = %v", readErr)
	}
	for _, secret := range []string{"secret-context", "TICKET-SECRET", "SECRET-REASON"} {
		if bytes.Contains(data, []byte(secret)) {
			t.Fatalf("spool contains raw value %q: %s", secret, data)
		}
	}

	var replayed []mutationAuditRecord
	f.mutationAudit = &mutationAuditRuntime{
		appendRecordWithResult: func(
			_ string,
			record mutationAuditRecord,
			_ coreaudit.Options,
		) (coreaudit.AppendResult, error) {
			replayed = append(replayed, record)
			return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
		},
		now:    func() time.Time { return time.Unix(201, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x32}, 16)),
	}
	next, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.delete",
		Target:    "next-context",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatalf("next beginMutationAudit() error = %v", err)
	}
	if next == nil || len(replayed) != 2 {
		t.Fatalf("next handle = %#v, replayed = %#v", next, replayed)
	}
	if replayed[0].Phase != mutationAuditPhaseOutcome ||
		replayed[0].MutationID != handle.id ||
		replayed[1].Phase != mutationAuditPhaseIntent {
		t.Fatalf("replay order = %#v", replayed)
	}
	if got := mutationSpoolJSONFiles(t, spoolPath); len(got) != 0 {
		t.Fatalf("spool after replay = %v, want empty", got)
	}
}

func TestMutationOutcomeReplaysBeforeAlreadyStartedMutationOutcome(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	firstID := ""
	firstOutcomeFailed := false
	var records []mutationAuditRecord
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecord: func(_ string, record mutationAuditRecord, _ coreaudit.Options) error {
				if record.MutationID == firstID &&
					record.Phase == mutationAuditPhaseOutcome &&
					!firstOutcomeFailed {
					firstOutcomeFailed = true
					return errors.New("injected first outcome failure")
				}
				records = append(records, record)
				return nil
			},
			now: func() time.Time {
				return time.Unix(250, int64(len(records))).UTC()
			},
			random: bytes.NewReader(append(
				bytes.Repeat([]byte{0x41}, 16),
				bytes.Repeat([]byte{0x42}, 16)...,
			)),
		},
	}
	first, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.set",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	firstID = first.id
	second, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.delete",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	records = nil
	if err := finishMutationAudit(
		first,
		mutationAuditOutcome{Succeeded: 1},
		nil,
	); apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("first outcome error = %v, want %s", err, codeAuditIncomplete)
	}
	if err := finishMutationAudit(
		second,
		mutationAuditOutcome{Succeeded: 1},
		nil,
	); err != nil {
		t.Fatalf("second outcome error = %v", err)
	}
	if len(records) != 2 ||
		records[0].MutationID != first.id ||
		records[0].Phase != mutationAuditPhaseOutcome ||
		records[1].MutationID != second.id ||
		records[1].Phase != mutationAuditPhaseOutcome {
		t.Fatalf("outcome order = %#v, want first replay then second outcome", records)
	}
}

func TestQueuedAuditEventRefreshesTimestampInAppendOrder(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	var events []srvgovaudit.Event
	var tick int64
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendEvent: func(_ string, event srvgovaudit.Event, _ coreaudit.Options) error {
				events = append(events, event)
				return nil
			},
			now: func() time.Time {
				tick++
				return time.Unix(260, tick).UTC()
			},
		},
	}
	first := srvgovaudit.Event{EventType: "first", Status: srvgovaudit.StatusSucceeded}
	second := srvgovaudit.Event{EventType: "second", Status: srvgovaudit.StatusSucceeded}
	if err := appendQueuedAuditEvent(f, auditPath, second, coreaudit.Options{}); err != nil {
		t.Fatal(err)
	}
	if err := appendQueuedAuditEvent(f, auditPath, first, coreaudit.Options{}); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 || !events[0].Timestamp.Before(events[1].Timestamp) {
		t.Fatalf("queued audit events = %#v, want append-order timestamps", events)
	}
}

func TestQueuedAuditEventReplaysPendingOutcomeFirst(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	failOutcome := true
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecord: func(_ string, record mutationAuditRecord, _ coreaudit.Options) error {
				if failOutcome && record.Phase == mutationAuditPhaseOutcome {
					return errors.New("injected outcome failure")
				}
				return nil
			},
			now:    func() time.Time { return time.Unix(270, 0).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x43}, 16)),
		},
	}
	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.set",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := finishMutationAudit(
		handle,
		mutationAuditOutcome{Succeeded: 1},
		nil,
	); apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
	}

	var order []string
	failOutcome = false
	f.mutationAudit = &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ coreaudit.Options) error {
			order = append(order, record.Phase)
			return nil
		},
		appendEvent: func(_ string, _ srvgovaudit.Event, _ coreaudit.Options) error {
			order = append(order, "event")
			return nil
		},
		now: func() time.Time { return time.Unix(271, 0).UTC() },
	}
	if err := appendQueuedAuditEvent(
		f,
		auditPath,
		srvgovaudit.Event{EventType: "status.observe", Status: srvgovaudit.StatusSucceeded},
		coreaudit.Options{},
	); err != nil {
		t.Fatal(err)
	}
	if len(order) != 2 || order[0] != mutationAuditPhaseOutcome || order[1] != "event" {
		t.Fatalf("append order = %v, want pending outcome then ordinary event", order)
	}
}

func TestConcurrentMutationOutcomeSpoolingKeepsEveryRecord(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	const count = 8
	var wait sync.WaitGroup
	wait.Add(count)
	errs := make(chan error, count)
	for index := range count {
		go func() {
			defer wait.Done()
			id := fmt.Sprintf("%032x", index+1)
			handle := &mutationAuditHandle{
				f: &cliFlags{
					trustedOperator: "alice@workstation",
					mutationAudit: &mutationAuditRuntime{
						appendRecord: func(_ string, _ mutationAuditRecord, _ coreaudit.Options) error {
							return errors.New("audit unavailable")
						},
						now:    func() time.Time { return time.Unix(300+int64(index), 0).UTC() },
						random: bytes.NewReader(nil),
					},
				},
				id:   id,
				path: auditPath,
				spec: mutationAuditSpec{Action: "exec.run"},
			}
			outcome := mutationAuditOutcome{Status: srvgovaudit.StatusSucceeded, Succeeded: 1}
			errs <- spoolMutationAuditOutcome(handle.f, auditPath, handle.record(mutationAuditPhaseOutcome, &outcome))
		}()
	}
	wait.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("spoolMutationAuditOutcome() error = %v", err)
		}
	}
	if got := mutationSpoolJSONFiles(t, mutationAuditSpoolPath(auditPath)); len(got) != count {
		t.Fatalf("spooled files = %d, want %d: %v", len(got), count, got)
	}
}

func TestMutationSpoolSequencePreservesLockedWriteOrder(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			now: func() time.Time { return time.Unix(1, 0).UTC() },
		},
	}
	for index, id := range []string{
		"11111111111111111111111111111111",
		"22222222222222222222222222222222",
	} {
		handle := &mutationAuditHandle{
			f:    f,
			id:   id,
			path: auditPath,
			spec: mutationAuditSpec{Action: "exec.run"},
		}
		outcome := mutationAuditOutcome{Status: srvgovaudit.StatusSucceeded, Succeeded: 1}
		if err := spoolMutationAuditOutcome(f, auditPath, handle.record(mutationAuditPhaseOutcome, &outcome)); err != nil {
			t.Fatalf("spool write %d: %v", index, err)
		}
	}
	spooled := mutationSpoolJSONFiles(t, mutationAuditSpoolPath(auditPath))
	if len(spooled) != 2 ||
		!strings.HasPrefix(filepath.Base(spooled[0]), "00000000000000000001-1111") ||
		!strings.HasPrefix(filepath.Base(spooled[1]), "00000000000000000002-2222") {
		t.Fatalf("spool order = %v", spooled)
	}
}

func TestValidateMutationSpoolRecordRejectsForgedFields(t *testing.T) {
	handle := &mutationAuditHandle{
		f: &cliFlags{
			trustedOperator: "alice@workstation",
			mutationAudit: &mutationAuditRuntime{
				now: func() time.Time { return time.Unix(350, 0).UTC() },
			},
		},
		id: "11111111111111111111111111111111",
		spec: mutationAuditSpec{
			Action: "exec.run",
			Ticket: "OPS-1",
			Metadata: mutationAuditMetadata{
				Items: 1,
			},
		},
	}
	base := handle.record(
		mutationAuditPhaseOutcome,
		&mutationAuditOutcome{Status: srvgovaudit.StatusSucceeded, Succeeded: 1},
	)
	tests := []struct {
		name   string
		mutate func(*mutationAuditRecord)
	}{
		{
			name: "raw fingerprint",
			mutate: func(record *mutationAuditRecord) {
				record.TicketFingerprint = "ticket=secret"
			},
		},
		{
			name: "negative count",
			mutate: func(record *mutationAuditRecord) {
				record.Outcome.Succeeded = -1
			},
		},
		{
			name: "event type mismatch",
			mutate: func(record *mutationAuditRecord) {
				record.EventType = "other.outcome"
			},
		},
		{
			name: "status mismatch",
			mutate: func(record *mutationAuditRecord) {
				record.Status = srvgovaudit.StatusFailed
			},
		},
		{
			name: "failed without error code",
			mutate: func(record *mutationAuditRecord) {
				record.Status = srvgovaudit.StatusFailed
				record.Outcome.Status = srvgovaudit.StatusFailed
			},
		},
		{
			name: "outcome exceeds item count",
			mutate: func(record *mutationAuditRecord) {
				record.Outcome.Succeeded = 2
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			record := base
			outcome := *base.Outcome
			metadata := *base.Metadata
			record.Outcome = &outcome
			record.Metadata = &metadata
			tt.mutate(&record)
			if err := validateMutationSpoolRecord(record); err == nil {
				t.Fatal("validateMutationSpoolRecord() error = nil")
			}
		})
	}
}

func TestMutationSpoolRejectsFilenameAndNestedCaseFoldDuplicates(t *testing.T) {
	id := strings.Repeat("ab", 16)
	if err := validateMutationSpoolFilename(
		"00000000000000000001-"+strings.Repeat("cd", 16)+".json",
		id,
	); err == nil {
		t.Fatal("validateMutationSpoolFilename() accepted a mismatched mutation id")
	}
	for _, data := range [][]byte{
		[]byte(`{"outcome":{"status":"failed","Status":"succeeded"}}`),
		[]byte(`{"outcome":{"status":"failed","\u017ftatus":"succeeded"}}`),
	} {
		if !hasDuplicateJSONKeyFold(data) {
			t.Fatalf("case-fold duplicate JSON key accepted: %s", data)
		}
	}
	if validMutationSpoolName("00000000000000000000-" + id + ".json") {
		t.Fatal("validMutationSpoolName() accepted sequence zero")
	}
	if validMutationSpoolName("00000000000000000001-" + strings.ToUpper(id) + ".json") {
		t.Fatal("validMutationSpoolName() accepted uppercase mutation id")
	}
}

func TestMutationOutcomeFallbackPrecedesConcurrentIntent(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	const priorID = "11111111111111111111111111111111"

	outcomeAppendStarted := make(chan struct{})
	releaseOutcomeAppend := make(chan struct{})
	nextIntentAppended := make(chan struct{})
	var callsMu sync.Mutex
	var calls []string
	firstOutcomeAttempt := true
	runtime := &mutationAuditRuntime{
		appendRecord: func(_ string, record mutationAuditRecord, _ coreaudit.Options) error {
			callsMu.Lock()
			calls = append(calls, record.MutationID+"/"+record.Phase)
			blockOutcome := record.MutationID == priorID &&
				record.Phase == mutationAuditPhaseOutcome &&
				firstOutcomeAttempt
			if blockOutcome {
				firstOutcomeAttempt = false
			}
			callsMu.Unlock()
			if blockOutcome {
				close(outcomeAppendStarted)
				<-releaseOutcomeAppend
				return errors.New("injected outcome append failure")
			}
			if record.MutationID != priorID && record.Phase == mutationAuditPhaseIntent {
				close(nextIntentAppended)
			}
			return nil
		},
		now:    func() time.Time { return time.Unix(400, 0).UTC() },
		random: bytes.NewReader(bytes.Repeat([]byte{0x22}, 16)),
	}
	f := &cliFlags{trustedOperator: "alice@workstation", mutationAudit: runtime}
	prior := &mutationAuditHandle{
		f:       f,
		id:      priorID,
		path:    auditPath,
		spec:    mutationAuditSpec{Action: "exec.run"},
		options: coreaudit.Options{},
	}

	finishDone := make(chan error, 1)
	go func() {
		finishDone <- finishMutationAudit(
			prior,
			mutationAuditOutcome{Status: srvgovaudit.StatusSucceeded, Succeeded: 1},
			nil,
		)
	}()
	<-outcomeAppendStarted

	beginStarted := make(chan struct{})
	beginDone := make(chan error, 1)
	go func() {
		close(beginStarted)
		_, err := beginMutationAudit(f, mutationAuditSpec{
			Action:    "context.delete",
			AuditPath: auditPath,
		})
		beginDone <- err
	}()
	<-beginStarted

	intentRanEarly := false
	select {
	case <-nextIntentAppended:
		intentRanEarly = true
	case <-time.After(150 * time.Millisecond):
	}
	close(releaseOutcomeAppend)

	if err := <-finishDone; apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
	}
	if err := <-beginDone; err != nil {
		t.Fatalf("beginMutationAudit() error = %v", err)
	}
	if intentRanEarly {
		t.Fatal("concurrent intent appended before the prior failed outcome was durably spooled")
	}
	callsMu.Lock()
	gotCalls := append([]string(nil), calls...)
	callsMu.Unlock()
	if len(gotCalls) != 3 ||
		gotCalls[0] != priorID+"/"+mutationAuditPhaseOutcome ||
		gotCalls[1] != priorID+"/"+mutationAuditPhaseOutcome ||
		!strings.HasSuffix(gotCalls[2], "/"+mutationAuditPhaseIntent) {
		t.Fatalf("append order = %v, want failed outcome, replayed outcome, then next intent", gotCalls)
	}
}

func TestMutationIntentFailureBlocksRemoteRunner(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	runner := &fakeSSHRunner{}
	restore := replaceSSHRunner(runner)
	t.Cleanup(restore)
	f := &cliFlags{
		Yes:             true,
		NonInteractive:  true,
		Ticket:          "TEST-1",
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecord: func(_ string, _ mutationAuditRecord, _ coreaudit.Options) error {
				return errors.New("audit unavailable")
			},
			now:    time.Now,
			random: bytes.NewReader(bytes.Repeat([]byte{0x41}, 16)),
		},
	}
	item := srvgovctx.Context{Host: "example.com", Port: 22}
	result, _, err := runGovernedCommand(
		newRootCmdWith(f),
		f,
		item,
		"dev",
		"rm -- /tmp/example",
		"approved cleanup",
		true,
		srvgovaudit.EventTypeExecRun,
	)
	if err == nil || result.ExitCode != 0 {
		t.Fatalf("runGovernedCommand() result=%#v error=%v", result, err)
	}
	if runner.calls != 0 {
		t.Fatalf("runner calls = %d, want 0", runner.calls)
	}
}

func TestMutationIntentIndeterminateFailsClosedWithoutSpooling(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	var appended []mutationAuditRecord
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecordWithResult: func(
				_ string,
				record mutationAuditRecord,
				_ coreaudit.Options,
			) (coreaudit.AppendResult, error) {
				appended = append(appended, record)
				return coreaudit.AppendResult{State: coreaudit.AppendCommitIndeterminate},
					errors.New("injected indeterminate append")
			},
			now:    func() time.Time { return time.Unix(500, 0).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x43}, 16)),
		},
	}

	handle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.set",
		AuditPath: auditPath,
	})
	if handle != nil {
		t.Fatalf("beginMutationAudit() handle = %#v, want nil", handle)
	}
	if got := apperrors.AsAppError(err).Code; got != codeAuditIncomplete {
		t.Fatalf("beginMutationAudit() code = %s, want %s (err=%v)", got, codeAuditIncomplete, err)
	}
	if len(appended) != 1 || appended[0].Phase != mutationAuditPhaseIntent {
		t.Fatalf("appended records = %#v, want one intent", appended)
	}
	entries, readErr := os.ReadDir(mutationAuditSpoolPath(auditPath))
	if readErr != nil {
		t.Fatal(readErr)
	}
	for _, entry := range entries {
		if entry.Name() != mutationAuditSpoolLockBase+".lock" {
			t.Fatalf("unexpected intent spool entry %q", entry.Name())
		}
	}
}

func TestMutationSpoolReplayIndeterminateIsQuarantinedAndNeverRetried(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	appendCalls := 0
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecordWithResult: func(
				_ string,
				_ mutationAuditRecord,
				_ coreaudit.Options,
			) (coreaudit.AppendResult, error) {
				appendCalls++
				if appendCalls == 1 {
					return coreaudit.AppendResult{State: coreaudit.AppendCommitIndeterminate},
						errors.New("injected indeterminate replay")
				}
				return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
			},
			now: time.Now,
		},
	}
	handle := &mutationAuditHandle{
		f:    f,
		id:   strings.Repeat("a", 32),
		path: auditPath,
		spec: mutationAuditSpec{Action: "context.set"},
	}
	record := handle.record(mutationAuditPhaseOutcome, &mutationAuditOutcome{
		Status:    srvgovaudit.StatusFailed,
		ErrorCode: "TEST_FAILURE",
		Failed:    1,
	})
	if err := spoolMutationAuditOutcome(f, auditPath, record); err != nil {
		t.Fatal(err)
	}

	replay := func() error {
		return withMutationAuditQueue(auditPath, func(spoolPath string) error {
			return replayMutationAuditSpoolLocked(f, auditPath, spoolPath, coreaudit.Options{})
		})
	}
	if err := replay(); apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("first replay error = %v, want %s", err, codeAuditIncomplete)
	}
	entries, err := os.ReadDir(mutationAuditSpoolPath(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	indeterminate := 0
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), mutationAuditSpoolReadySuffix) {
			t.Fatalf("ready spool survived indeterminate append: %q", entry.Name())
		}
		if strings.HasSuffix(entry.Name(), mutationAuditSpoolIndeterminateSuffix) {
			indeterminate++
		}
	}
	if indeterminate != 1 {
		t.Fatalf("indeterminate spool entries = %d, want 1", indeterminate)
	}

	if err := replay(); apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("second replay error = %v, want %s", err, codeAuditIncomplete)
	}
	if appendCalls != 1 {
		t.Fatalf("append calls = %d, want 1; quarantined record was retried", appendCalls)
	}
}

func TestStartedMutationSpoolsOwnOutcomeAfterIndeterminateMarker(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	appendCalls := 0
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecordWithResult: func(
				_ string,
				_ mutationAuditRecord,
				_ coreaudit.Options,
			) (coreaudit.AppendResult, error) {
				appendCalls++
				return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
			},
			now:    time.Now,
			random: bytes.NewReader(bytes.Repeat([]byte{0xc1}, 16)),
		},
	}
	started, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.set",
		AuditPath: auditPath,
	})
	if err != nil {
		t.Fatal(err)
	}
	prior := &mutationAuditHandle{
		f:    f,
		id:   strings.Repeat("d", 32),
		path: auditPath,
		spec: mutationAuditSpec{Action: "context.delete"},
	}
	marker := prior.record(mutationAuditPhaseOutcome, &mutationAuditOutcome{
		Status:    srvgovaudit.StatusFailed,
		ErrorCode: "INDETERMINATE",
		Failed:    1,
	})
	if err := withMutationAuditQueue(auditPath, func(spoolPath string) error {
		return writeIndeterminateMutationSpoolRecord(f, spoolPath, marker)
	}); err != nil {
		t.Fatal(err)
	}

	err = finishMutationAudit(started, mutationAuditOutcome{Succeeded: 1}, nil)
	if apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("finishMutationAudit() error = %v, want %s", err, codeAuditIncomplete)
	}
	entries, err := os.ReadDir(mutationAuditSpoolPath(auditPath))
	if err != nil {
		t.Fatal(err)
	}
	spooled := make([]string, 0, 2)
	for _, entry := range entries {
		if entry.Name() != mutationAuditSpoolLockBase+".lock" {
			spooled = append(spooled, entry.Name())
		}
	}
	sort.Strings(spooled)
	if len(spooled) != 2 ||
		!strings.HasSuffix(spooled[0], mutationAuditSpoolIndeterminateSuffix) ||
		!strings.HasSuffix(spooled[1], mutationAuditSpoolReadySuffix) ||
		mutationSpoolNameMutationID(spooled[1]) != started.id {
		t.Fatalf("spool order = %v, want marker then started mutation outcome", spooled)
	}
	firstSequence, err := mutationSpoolNameSequence(spooled[0])
	if err != nil {
		t.Fatal(err)
	}
	secondSequence, err := mutationSpoolNameSequence(spooled[1])
	if err != nil {
		t.Fatal(err)
	}
	if secondSequence != firstSequence+1 {
		t.Fatalf("spool sequences = %d, %d; marker must precede outcome", firstSequence, secondSequence)
	}
	if appendCalls != 1 {
		t.Fatalf("append calls = %d, want only the already-started intent", appendCalls)
	}

	next, err := beginMutationAudit(f, mutationAuditSpec{
		Action:    "context.delete",
		AuditPath: auditPath,
	})
	if next != nil || apperrors.AsAppError(err).Code != codeAuditIncomplete {
		t.Fatalf("next begin = (%#v, %v), want marker to fail closed", next, err)
	}
	if appendCalls != 1 {
		t.Fatalf("append calls after blocked begin = %d, want 1", appendCalls)
	}
}

func TestMutationSpoolReplayCommittedPostCommitErrorIsNotReplayed(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	auditPath := filepath.Join(dir, "audit.log")
	appendCalls := 0
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecordWithResult: func(
				_ string,
				_ mutationAuditRecord,
				_ coreaudit.Options,
			) (coreaudit.AppendResult, error) {
				appendCalls++
				return coreaudit.AppendResult{State: coreaudit.AppendCommitCommittedPostCommitError},
					errors.New("injected post-commit cleanup failure")
			},
			now: time.Now,
		},
	}
	handle := &mutationAuditHandle{
		f:    f,
		id:   strings.Repeat("b", 32),
		path: auditPath,
		spec: mutationAuditSpec{Action: "context.set"},
	}
	record := handle.record(mutationAuditPhaseOutcome, &mutationAuditOutcome{
		Status:    srvgovaudit.StatusFailed,
		ErrorCode: "TEST_FAILURE",
		Failed:    1,
	})
	if err := spoolMutationAuditOutcome(f, auditPath, record); err != nil {
		t.Fatal(err)
	}
	replay := func() error {
		return withMutationAuditQueue(auditPath, func(spoolPath string) error {
			return replayMutationAuditSpoolLocked(f, auditPath, spoolPath, coreaudit.Options{})
		})
	}
	if err := replay(); err != nil {
		t.Fatalf("first replay error = %v", err)
	}
	if files := mutationSpoolJSONFiles(t, mutationAuditSpoolPath(auditPath)); len(files) != 0 {
		t.Fatalf("committed replay spool survived: %v", files)
	}
	if err := replay(); err != nil {
		t.Fatalf("second replay error = %v", err)
	}
	if appendCalls != 1 {
		t.Fatalf("append calls = %d, want 1", appendCalls)
	}
}

func TestInstallIntentFailureCreatesNoTarget(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	target := filepath.Join(t.TempDir(), "skills")
	previousFS := skillFS
	skillFS = fstest.MapFS{
		"skills/srvgov-cli/SKILL.md": {Data: []byte("secret-free skill")},
	}
	t.Cleanup(func() { skillFS = previousFS })
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecord: func(_ string, _ mutationAuditRecord, _ coreaudit.Options) error {
				return errors.New("audit unavailable")
			},
			now:    time.Now,
			random: bytes.NewReader(bytes.Repeat([]byte{0x42}, 16)),
		},
	}
	err := installSkills(f, target)
	if err == nil {
		t.Fatal("installSkills() error = nil, want audit failure")
	}
	if _, statErr := os.Stat(filepath.Join(target, "srvgov-cli")); !os.IsNotExist(statErr) {
		t.Fatalf("install target exists after intent failure: %v", statErr)
	}
}

func TestInstallPartialFailureReportsExactCounts(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	previousFS := skillFS
	skillFS = fstest.MapFS{
		"skills/srvgov-cli/a.md": {Data: []byte("a")},
		"skills/srvgov-cli/b.md": {Data: []byte("b")},
		"skills/srvgov-cli/c.md": {Data: []byte("c")},
	}
	previousWrite := writeEmbeddedSkillFile
	writeCalls := 0
	writeEmbeddedSkillFile = func(name string, data []byte, mode os.FileMode) error {
		writeCalls++
		if writeCalls == 2 {
			return os.ErrPermission
		}
		return os.WriteFile(name, data, mode)
	}
	t.Cleanup(func() {
		skillFS = previousFS
		writeEmbeddedSkillFile = previousWrite
	})

	var records []mutationAuditRecord
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecord: func(_ string, record mutationAuditRecord, _ coreaudit.Options) error {
				records = append(records, record)
				return nil
			},
			now:    func() time.Time { return time.Unix(550, int64(len(records))).UTC() },
			random: bytes.NewReader(bytes.Repeat([]byte{0x55}, 16)),
		},
	}
	err := installSkills(f, filepath.Join(dir, "skills"))
	if apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
		t.Fatalf("installSkills() error = %v, want LOCAL_IO_ERROR", err)
	}
	if len(records) != 2 || records[1].Outcome == nil {
		t.Fatalf("install audit records = %#v", records)
	}
	outcome := records[1].Outcome
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Succeeded != 1 ||
		outcome.Failed != 1 ||
		outcome.Skipped != 1 {
		t.Fatalf("partial install outcome = %#v, want 1 succeeded/1 failed/1 skipped", outcome)
	}
}

func TestFanoutOutcomePropagatesAuditIncomplete(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, dir)
	var records []mutationAuditRecord
	f := &cliFlags{
		trustedOperator: "alice@workstation",
		mutationAudit: &mutationAuditRuntime{
			appendRecord: func(_ string, record mutationAuditRecord, _ coreaudit.Options) error {
				records = append(records, record)
				return nil
			},
			now: time.Now,
		},
	}
	handle := &mutationAuditHandle{
		f:    f,
		id:   strings.Repeat("1", 32),
		path: filepath.Join(dir, "audit.log"),
		spec: mutationAuditSpec{
			Action:      "exec.run.batch",
			ContextName: "fanout",
			RiskTier:    "R2",
		},
	}
	incompleteErr := auditIncompleteError(strings.Repeat("2", 32), false)
	err := finishFanoutMutationAudit(handle, []fanout.Result{
		{Target: "alpha"},
		{Target: "bravo", Err: incompleteErr},
	})
	if code := apperrors.AsAppError(err).Code; code != codeAuditIncomplete {
		t.Fatalf("finishFanoutMutationAudit() code = %s, want %s", code, codeAuditIncomplete)
	}
	if len(records) != 1 || records[0].Outcome == nil ||
		records[0].Outcome.ErrorCode != string(codeAuditIncomplete) ||
		records[0].Outcome.Succeeded != 1 ||
		records[0].Outcome.Failed != 1 {
		t.Fatalf("fanout outcome record = %#v", records)
	}
}

func mutationSpoolJSONFiles(t *testing.T, spoolPath string) []string {
	t.Helper()
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		t.Fatalf("ReadDir(spool) error = %v", err)
	}
	out := []string{}
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			out = append(out, filepath.Join(spoolPath, entry.Name()))
		}
	}
	return out
}
