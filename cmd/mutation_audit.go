package cmd

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/lockfile"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

const (
	codeAuditIncomplete                   apperrors.ErrorCode = "AUDIT_INCOMPLETE"
	mutationAuditAPIVersion                                   = "srvgov-cli.io/mutation-audit/v1"
	mutationAuditKind                                         = "MutationAuditRecord"
	mutationAuditPhaseIntent                                  = "intent"
	mutationAuditPhaseOutcome                                 = "outcome"
	mutationAuditSpoolSuffix                                  = ".outcome-spool"
	mutationAuditSpoolLockBase                                = "queue"
	mutationAuditSpoolReadySuffix                             = ".json"
	mutationAuditSpoolIndeterminateSuffix                     = ".indeterminate"
	maxMutationSpoolRecordBytes                               = 1024 * 1024
)

type mutationAuditMetadata = srvgovaudit.MutationMetadata

type mutationAuditOutcome = srvgovaudit.MutationOutcome

type mutationAuditSpec struct {
	Action      string
	ContextName string
	Context     srvgovctx.Context
	Target      string
	RiskTier    string
	Ticket      string
	Reason      string
	Metadata    mutationAuditMetadata
	AuditPath   string
	Options     coreaudit.Options
}

type mutationAuditRecord struct {
	APIVersion string `json:"apiVersion"`
	Kind       string `json:"kind"`
	srvgovaudit.Event
}

type mutationAuditHandle struct {
	f       *cliFlags
	id      string
	path    string
	spec    mutationAuditSpec
	options coreaudit.Options
}

type mutationAuditRuntime struct {
	appendRecord           func(string, mutationAuditRecord, coreaudit.Options) error
	appendRecordWithResult func(string, mutationAuditRecord, coreaudit.Options) (coreaudit.AppendResult, error)
	appendEvent            func(string, srvgovaudit.Event, coreaudit.Options) error
	appendEventWithResult  func(string, srvgovaudit.Event, coreaudit.Options) (coreaudit.AppendResult, error)
	now                    func() time.Time
	random                 io.Reader
}

var productionMutationAuditRuntime = mutationAuditRuntime{
	appendRecordWithResult: func(path string, record mutationAuditRecord, options coreaudit.Options) (coreaudit.AppendResult, error) {
		record.Event = srvgovaudit.Sanitize(record.Event)
		return srvgovaudit.AppendRecordWithResult(path, record, options)
	},
	appendEventWithResult: srvgovaudit.AppendWithResult,
	now:                   func() time.Time { return time.Now().UTC() },
	random:                rand.Reader,
}

var mutationAuditSpoolMu sync.Mutex

//nolint:nestif // Intent durability and spool fallback stay visibly ordered.
func beginMutationAudit(f *cliFlags, spec mutationAuditSpec) (*mutationAuditHandle, error) {
	spec.Action = strings.TrimSpace(spec.Action)
	if spec.Action == "" {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "mutation audit action is required", nil)
	}
	path := strings.TrimSpace(spec.AuditPath)
	if path == "" {
		var err error
		path, err = coreaudit.DefaultPath()
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to resolve mutation audit path", nil)
		}
	}
	var handle *mutationAuditHandle
	err := withMutationAuditQueue(path, func(spoolPath string) error {
		if err := replayMutationAuditSpoolLocked(f, path, spoolPath, spec.Options); err != nil {
			return auditIncompleteError("", false)
		}
		id, err := newMutationID(mutationAuditRuntimeFor(f).random)
		if err != nil {
			return err
		}
		handle = &mutationAuditHandle{
			f:       f,
			id:      id,
			path:    path,
			spec:    spec,
			options: spec.Options,
		}
		result, appendErr := appendMutationAuditRecord(
			f,
			path,
			handle.record(mutationAuditPhaseIntent, nil),
			spec.Options,
		)
		if appendErr != nil {
			if result.State == coreaudit.AppendCommitIndeterminate || result.State == "" {
				return auditIndeterminateError(handle.id, mutationAuditPhaseIntent)
			}
			return appendErr
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return handle, nil
}

//nolint:gocyclo // Outcome append, durable fallback, and operation-error precedence form one transaction boundary.
func finishMutationAudit(
	handle *mutationAuditHandle,
	outcome mutationAuditOutcome,
	operationErr error,
) error {
	if handle == nil {
		return apperrors.New(apperrors.CodeValidationFailed, "mutation audit handle is required", nil)
	}
	if outcome.Status == "" {
		if operationErr == nil {
			outcome.Status = srvgovaudit.StatusSucceeded
		} else {
			outcome.Status = srvgovaudit.StatusFailed
		}
	}
	if operationErr != nil && outcome.ErrorCode == "" {
		outcome.ErrorCode = string(apperrors.AsAppError(operationErr).Code)
	}
	if operationErr == nil && outcome.Status == srvgovaudit.StatusSucceeded &&
		outcome.Succeeded == 0 &&
		outcome.Failed == 0 &&
		outcome.Skipped == 0 &&
		outcome.Uncertain == 0 {
		outcome.Succeeded = 1
	}
	appendFailed := false
	appendIndeterminate := false
	var committedAppendErr error
	err := withMutationAuditQueue(handle.path, func(spoolPath string) error {
		if err := replayMutationAuditSpoolLocked(
			handle.f,
			handle.path,
			spoolPath,
			handle.options,
		); err != nil {
			record := handle.record(mutationAuditPhaseOutcome, &outcome)
			if spoolErr := writeMutationSpoolRecord(handle.f, spoolPath, record); spoolErr != nil {
				return spoolErr
			}
			appendFailed = true
			return nil
		}
		record := handle.record(mutationAuditPhaseOutcome, &outcome)
		result, appendErr := appendMutationAuditRecord(handle.f, handle.path, record, handle.options)
		if appendErr != nil {
			switch {
			case result.IsCommitted():
				committedAppendErr = appendErr
				return nil
			case result.State == coreaudit.AppendCommitNotCommitted:
				appendFailed = true
				return writeMutationSpoolRecord(handle.f, spoolPath, record)
			default:
				appendIndeterminate = true
				return writeIndeterminateMutationSpoolRecord(handle.f, spoolPath, record)
			}
		}
		return nil
	})
	if err != nil {
		return auditIncompleteError(handle.id, true)
	}
	if appendFailed {
		return auditIncompleteError(handle.id, false)
	}
	if appendIndeterminate {
		return auditIndeterminateError(handle.id, mutationAuditPhaseOutcome)
	}
	if committedAppendErr != nil {
		return committedAppendErr
	}
	return operationErr
}

func appendQueuedAuditEvent(
	f *cliFlags,
	path string,
	event srvgovaudit.Event,
	options coreaudit.Options,
) error {
	return withMutationAuditQueue(path, func(spoolPath string) error {
		if err := replayMutationAuditSpoolLocked(f, path, spoolPath, options); err != nil {
			return auditIncompleteError("", false)
		}
		runtime := mutationAuditRuntimeFor(f)
		event.Timestamp = runtime.now().UTC()
		result, appendErr := appendMutationAuditEvent(runtime, path, srvgovaudit.Sanitize(event), options)
		if appendErr != nil {
			if result.State == coreaudit.AppendCommitIndeterminate || result.State == "" {
				return auditIndeterminateError("", "event")
			}
			return appendErr
		}
		return nil
	})
}

func (handle *mutationAuditHandle) record(phase string, outcome *mutationAuditOutcome) mutationAuditRecord {
	ticketFingerprint, ticketBytes := srvgovaudit.Fingerprint("ticket", handle.spec.Ticket)
	reasonFingerprint, reasonBytes := srvgovaudit.Fingerprint("reason", handle.spec.Reason)
	metadata := handle.spec.Metadata
	if metadata.TargetFingerprint == "" && handle.spec.Target != "" {
		metadata.TargetFingerprint, metadata.TargetBytes = srvgovaudit.Fingerprint("target", handle.spec.Target)
	}
	status := "pending"
	if outcome != nil {
		status = outcome.Status
	}
	riskTier := handle.spec.RiskTier
	if riskTier == "" {
		riskTier = "R3"
	}
	return mutationAuditRecord{
		APIVersion: mutationAuditAPIVersion,
		Kind:       mutationAuditKind,
		Event: srvgovaudit.Event{
			Timestamp: mutationAuditRuntimeFor(handle.f).now().UTC(),
			EventType: srvgovaudit.EventType(handle.spec.Action + "." + phase),
			Operator:  currentOperator(handle.f),
			Context: srvgovaudit.Context{
				Name:      handle.spec.ContextName,
				Env:       handle.spec.Context.Env,
				Protected: handle.spec.Context.Protected,
			},
			RiskTier:          riskTier,
			Status:            status,
			MutationID:        handle.id,
			Phase:             phase,
			Action:            handle.spec.Action,
			TicketFingerprint: ticketFingerprint,
			TicketBytes:       ticketBytes,
			ReasonFingerprint: reasonFingerprint,
			ReasonBytes:       reasonBytes,
			Metadata:          &metadata,
			Outcome:           outcome,
		},
	}
}

func mutationPayloadMetadata(action string, payload []byte) mutationAuditMetadata {
	fingerprint, size := srvgovaudit.Fingerprint("payload:"+action, string(payload))
	return mutationAuditMetadata{PayloadFingerprint: fingerprint, PayloadBytes: size}
}

func newMutationID(random io.Reader) (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to generate mutation id", nil)
	}
	return hex.EncodeToString(value), nil
}

func mutationAuditRuntimeFor(f *cliFlags) *mutationAuditRuntime {
	if f != nil && f.mutationAudit != nil {
		return f.mutationAudit
	}
	return &productionMutationAuditRuntime
}

func appendMutationAuditRecord(
	f *cliFlags,
	path string,
	record mutationAuditRecord,
	options coreaudit.Options,
) (coreaudit.AppendResult, error) {
	runtime := mutationAuditRuntimeFor(f)
	if runtime.appendRecordWithResult != nil {
		result, err := runtime.appendRecordWithResult(path, record, options)
		return validateMutationAppendResult(result, err)
	}
	if runtime.appendRecord == nil {
		result, err := productionMutationAuditRuntime.appendRecordWithResult(path, record, options)
		return validateMutationAppendResult(result, err)
	}
	err := runtime.appendRecord(path, record, options)
	if err != nil {
		return coreaudit.AppendResult{State: coreaudit.AppendCommitNotCommitted}, err
	}
	return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
}

func appendMutationAuditEvent(
	runtime *mutationAuditRuntime,
	path string,
	event srvgovaudit.Event,
	options coreaudit.Options,
) (coreaudit.AppendResult, error) {
	if runtime.appendEventWithResult != nil {
		result, err := runtime.appendEventWithResult(path, event, options)
		return validateMutationAppendResult(result, err)
	}
	if runtime.appendEvent == nil {
		result, err := productionMutationAuditRuntime.appendEventWithResult(path, event, options)
		return validateMutationAppendResult(result, err)
	}
	err := runtime.appendEvent(path, event, options)
	if err != nil {
		return coreaudit.AppendResult{State: coreaudit.AppendCommitNotCommitted}, err
	}
	return coreaudit.AppendResult{State: coreaudit.AppendCommitCommitted}, nil
}

func validateMutationAppendResult(
	result coreaudit.AppendResult,
	err error,
) (coreaudit.AppendResult, error) {
	if err == nil && !result.IsCommitted() {
		return result, apperrors.New(
			apperrors.CodeLocalIOError,
			"audit append returned without a committed durability state",
			nil,
		)
	}
	return result, err
}

func mutationAuditSpoolPath(auditPath string) string {
	return auditPath + mutationAuditSpoolSuffix
}

func withMutationAuditQueue(auditPath string, fn func(spoolPath string) error) (retErr error) {
	mutationAuditSpoolMu.Lock()
	defer mutationAuditSpoolMu.Unlock()

	if err := ensureMutationAuditDirectory(filepath.Dir(auditPath)); err != nil {
		return err
	}
	spoolPath := mutationAuditSpoolPath(auditPath)
	if err := ensureMutationSpoolDirectory(spoolPath); err != nil {
		return err
	}
	lockBase := filepath.Join(spoolPath, mutationAuditSpoolLockBase)
	lock := lockfile.New(lockBase)
	if err := lock.Acquire(); err != nil {
		return err
	}
	if err := secureMutationSpoolFile(lockBase + ".lock"); err != nil {
		_ = lock.Release()
		return err
	}
	defer func() {
		if err := lock.Release(); err != nil && retErr == nil {
			retErr = apperrors.New(apperrors.CodeLocalIOError, "failed to release mutation outcome spool lock", nil)
		}
	}()
	if err := verifyMutationSpoolDirectory(spoolPath); err != nil {
		return err
	}
	return fn(spoolPath)
}

func ensureMutationAuditDirectory(path string) error {
	info, err := os.Lstat(path)
	if err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() {
			return apperrors.New(apperrors.CodeLocalIOError, "mutation audit directory must be a real directory", nil)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect mutation audit directory", nil)
	}
	parent := filepath.Dir(path)
	if parent == path {
		return apperrors.New(apperrors.CodeLocalIOError, "mutation audit directory has no existing ancestor", nil)
	}
	if err := ensureMutationAuditDirectory(parent); err != nil {
		return err
	}
	return createPrivateMutationAuditDirectory(path)
}

func spoolMutationAuditOutcome(f *cliFlags, auditPath string, record mutationAuditRecord) error {
	return withMutationAuditQueue(auditPath, func(spoolPath string) error {
		return writeMutationSpoolRecord(f, spoolPath, record)
	})
}

func writeMutationSpoolRecord(_ *cliFlags, spoolPath string, record mutationAuditRecord) error {
	return writeMutationSpoolRecordWithSuffix(spoolPath, record, mutationAuditSpoolReadySuffix)
}

func writeIndeterminateMutationSpoolRecord(
	_ *cliFlags,
	spoolPath string,
	record mutationAuditRecord,
) error {
	return writeMutationSpoolRecordWithSuffix(spoolPath, record, mutationAuditSpoolIndeterminateSuffix)
}

func writeMutationSpoolRecordWithSuffix(
	spoolPath string,
	record mutationAuditRecord,
	suffix string,
) error {
	data, err := json.Marshal(record)
	if err != nil || len(data) > maxMutationSpoolRecordBytes {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to encode mutation outcome spool", nil)
	}
	sequence, err := nextMutationSpoolSequence(spoolPath)
	if err != nil {
		return err
	}
	name := fmt.Sprintf("%020d-%s%s", sequence, record.MutationID, suffix)
	finalPath := filepath.Join(spoolPath, name)
	tempPath := finalPath + ".tmp"
	file, err := os.OpenFile(tempPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600) //nolint:gosec // Path is inside the validated private spool.
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create mutation outcome spool", nil)
	}
	complete := false
	defer func() {
		_ = file.Close()
		if !complete {
			_ = os.Remove(tempPath)
		}
	}()
	if err := secureMutationSpoolFile(tempPath); err != nil {
		return err
	}
	if _, err := file.Write(append(data, '\n')); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write mutation outcome spool", nil)
	}
	if err := file.Sync(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync mutation outcome spool", nil)
	}
	if err := file.Close(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close mutation outcome spool", nil)
	}
	if err := commitMutationSpoolFile(tempPath, finalPath); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to commit mutation outcome spool", nil)
	}
	if err := syncMutationSpoolDirectory(spoolPath); err != nil {
		return err
	}
	complete = true
	return nil
}

func nextMutationSpoolSequence(spoolPath string) (uint64, error) {
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "failed to list mutation outcome spool for sequencing", nil)
	}
	var maximum uint64
	for _, entry := range entries {
		name := entry.Name()
		if name == mutationAuditSpoolLockBase+".lock" {
			continue
		}
		if entry.IsDir() || !validMutationSpoolName(name) {
			return 0, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool contains an unexpected entry", nil)
		}
		separator := strings.IndexByte(name, '-')
		sequence, err := strconv.ParseUint(name[:separator], 10, 64)
		if err != nil {
			return 0, apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool sequence", nil)
		}
		if sequence > maximum {
			maximum = sequence
		}
	}
	if maximum == ^uint64(0) {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool sequence is exhausted", nil)
	}
	return maximum + 1, nil
}

//nolint:gocyclo // Strict validation, ordered replay, removal, and durability stay together.
func replayMutationAuditSpoolLocked(
	f *cliFlags,
	auditPath string,
	spoolPath string,
	options coreaudit.Options,
) error {
	entries, err := os.ReadDir(spoolPath)
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to list mutation outcome spool", nil)
	}
	names := make([]string, 0, len(entries))
	sequences := make(map[uint64]struct{}, len(entries))
	blockedMutationID := ""
	for _, entry := range entries {
		name := entry.Name()
		if name == mutationAuditSpoolLockBase+".lock" {
			continue
		}
		if entry.IsDir() || !validMutationSpoolName(name) {
			return apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool contains an unexpected entry", nil)
		}
		sequence, err := mutationSpoolNameSequence(name)
		if err != nil {
			return err
		}
		if _, duplicate := sequences[sequence]; duplicate {
			return apperrors.New(apperrors.CodeLocalIOError, "duplicate mutation outcome spool sequence", nil)
		}
		sequences[sequence] = struct{}{}
		names = append(names, name)
		if strings.HasSuffix(name, mutationAuditSpoolIndeterminateSuffix) {
			blockedMutationID = mutationSpoolNameMutationID(name)
		}
	}
	if blockedMutationID != "" {
		return auditIndeterminateError(blockedMutationID, mutationAuditPhaseOutcome)
	}
	sort.Strings(names)
	for _, name := range names {
		path := filepath.Join(spoolPath, name)
		record, err := readMutationSpoolRecord(path)
		if err != nil {
			return err
		}
		result, appendErr := appendMutationAuditRecord(f, auditPath, record, options)
		if appendErr != nil {
			switch {
			case result.IsCommitted():
				// The audit record is durable; remove the queue entry below even
				// when post-commit cleanup returned an error.
			case result.State == coreaudit.AppendCommitNotCommitted:
				return appendErr
			default:
				if err := quarantineIndeterminateMutationSpool(path); err != nil {
					return err
				}
				return auditIndeterminateError(record.MutationID, mutationAuditPhaseOutcome)
			}
		}
		if err := os.Remove(path); err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to remove replayed mutation outcome spool", nil)
		}
		if err := syncMutationSpoolDirectory(spoolPath); err != nil {
			return err
		}
	}
	return nil
}

func validMutationSpoolName(name string) bool {
	suffix := mutationAuditSpoolSuffixForName(name)
	if suffix == "" {
		return false
	}
	parts := strings.Split(strings.TrimSuffix(name, suffix), "-")
	if len(parts) != 2 || len(parts[0]) != 20 || len(parts[1]) != 32 {
		return false
	}
	sequence, err := strconv.ParseUint(parts[0], 10, 64)
	if err != nil || sequence == 0 || parts[1] != strings.ToLower(parts[1]) {
		return false
	}
	_, err = hex.DecodeString(parts[1])
	return err == nil
}

func mutationAuditSpoolSuffixForName(name string) string {
	for _, suffix := range []string{
		mutationAuditSpoolReadySuffix,
		mutationAuditSpoolIndeterminateSuffix,
	} {
		if strings.HasSuffix(name, suffix) {
			return suffix
		}
	}
	return ""
}

func mutationSpoolNameMutationID(name string) string {
	suffix := mutationAuditSpoolSuffixForName(name)
	base := strings.TrimSuffix(name, suffix)
	separator := strings.IndexByte(base, '-')
	if separator < 0 {
		return ""
	}
	return base[separator+1:]
}

func mutationSpoolNameSequence(name string) (uint64, error) {
	separator := strings.IndexByte(name, '-')
	if separator != 20 {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool sequence", nil)
	}
	sequence, err := strconv.ParseUint(name[:separator], 10, 64)
	if err != nil || sequence == 0 {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool sequence", nil)
	}
	return sequence, nil
}

func quarantineIndeterminateMutationSpool(path string) error {
	if !strings.HasSuffix(path, mutationAuditSpoolReadySuffix) {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool quarantine source", nil)
	}
	destination := strings.TrimSuffix(path, mutationAuditSpoolReadySuffix) + mutationAuditSpoolIndeterminateSuffix
	if err := commitMutationSpoolFile(path, destination); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to quarantine indeterminate mutation outcome spool", nil)
	}
	if err := syncMutationSpoolDirectory(filepath.Dir(path)); err != nil {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"failed to durably quarantine indeterminate mutation outcome spool",
			nil,
		)
	}
	return nil
}

func readMutationSpoolRecord(path string) (mutationAuditRecord, error) {
	var record mutationAuditRecord
	if err := verifyMutationSpoolFile(path); err != nil {
		return record, err
	}
	before, err := os.Lstat(path)
	if err != nil {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect mutation outcome spool file", nil)
	}
	// Force lazy file identity loading on Windows before opening the path.
	if !os.SameFile(before, before) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to identify mutation outcome spool file", nil)
	}
	file, err := os.Open(path) //nolint:gosec // Strict name and private parent were already validated.
	if err != nil {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to open mutation outcome spool file", nil)
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil || !opened.Mode().IsRegular() || !os.SameFile(before, opened) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool file changed while opening", nil)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxMutationSpoolRecordBytes+1))
	if err != nil || len(data) > maxMutationSpoolRecordBytes {
		return record, apperrors.New(apperrors.CodeLocalIOError, "failed to read mutation outcome spool file", nil)
	}
	if hasDuplicateJSONKeyFold(bytes.TrimSpace(data)) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool has duplicate fields", nil)
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&record); err != nil {
		return record, apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool record", nil)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		return record, apperrors.New(apperrors.CodeLocalIOError, "mutation outcome spool contains trailing data", nil)
	}
	if err := validateMutationSpoolRecord(record); err != nil {
		return mutationAuditRecord{}, err
	}
	if err := validateMutationSpoolFilename(filepath.Base(path), record.MutationID); err != nil {
		return mutationAuditRecord{}, err
	}
	return record, nil
}

func validateMutationSpoolFilename(name, mutationID string) error {
	if !validMutationSpoolName(name) ||
		!strings.HasSuffix(strings.TrimSuffix(name, mutationAuditSpoolSuffixForName(name)), "-"+mutationID) {
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"mutation outcome spool filename does not match its record",
			nil,
		)
	}
	return nil
}

func validateMutationSpoolRecord(record mutationAuditRecord) error { //nolint:gocyclo // The complete fail-closed record shape is checked in one predicate.
	if record.APIVersion != mutationAuditAPIVersion ||
		record.Kind != mutationAuditKind ||
		record.Phase != mutationAuditPhaseOutcome ||
		record.Action == "" ||
		len(record.Action) > 256 ||
		len(record.MutationID) != 32 ||
		record.Outcome == nil ||
		record.Metadata == nil ||
		record.Timestamp.IsZero() ||
		record.EventType != srvgovaudit.EventType(record.Action+"."+mutationAuditPhaseOutcome) ||
		record.Status != record.Outcome.Status ||
		record.Ticket != "" ||
		record.Reason != "" ||
		record.Command != "" ||
		record.Stdout != "" ||
		record.Stderr != "" ||
		record.Target.Host != "" ||
		record.Error != nil ||
		record.File != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool record", nil)
	}
	if record.MutationID != strings.ToLower(record.MutationID) {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool mutation id", nil)
	}
	if _, err := hex.DecodeString(record.MutationID); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool mutation id", nil)
	}
	if record.Outcome.Status != srvgovaudit.StatusSucceeded &&
		record.Outcome.Status != srvgovaudit.StatusFailed {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool status", nil)
	}
	if !validOptionalMutationFingerprint(record.TicketFingerprint, record.TicketBytes) ||
		!validOptionalMutationFingerprint(record.ReasonFingerprint, record.ReasonBytes) ||
		!validOptionalMutationFingerprint(record.CommandFingerprint, record.CommandBytes) ||
		!validOptionalMutationFingerprint(record.StdoutFingerprint, record.StdoutBytes) ||
		!validOptionalMutationFingerprint(record.StderrFingerprint, record.StderrBytes) ||
		!validOptionalMutationFingerprint(record.Target.Fingerprint, record.Target.Bytes) ||
		!validOptionalMutationFingerprint(record.Metadata.TargetFingerprint, record.Metadata.TargetBytes) ||
		!validOptionalMutationFingerprint(record.Metadata.PayloadFingerprint, record.Metadata.PayloadBytes) ||
		!validOptionalMutationFingerprint64(record.Outcome.PayloadFingerprint, record.Outcome.PayloadBytes) {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool fingerprint", nil)
	}
	if record.Metadata.Items < 0 ||
		record.Metadata.Creates < 0 ||
		record.Metadata.Updates < 0 ||
		record.Metadata.Deletes < 0 ||
		record.Outcome.Succeeded < 0 ||
		record.Outcome.Failed < 0 ||
		record.Outcome.Skipped < 0 ||
		record.Outcome.Uncertain < 0 ||
		len(record.Metadata.Revision) > 256 ||
		len(record.Outcome.Revision) > 256 ||
		len(record.Outcome.ErrorCode) > 128 {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool counts", nil)
	}
	total := uint64(record.Outcome.Succeeded) +
		uint64(record.Outcome.Failed) +
		uint64(record.Outcome.Skipped) +
		uint64(record.Outcome.Uncertain)
	if total > 1_000_000_000 ||
		(record.Metadata.Items > 0 && total != uint64(record.Metadata.Items)) ||
		(record.Outcome.Status == srvgovaudit.StatusSucceeded && record.Outcome.Failed != 0) ||
		(record.Outcome.Status == srvgovaudit.StatusSucceeded && record.Outcome.Uncertain != 0) ||
		(record.Outcome.Status == srvgovaudit.StatusFailed && record.Outcome.ErrorCode == "") {
		return apperrors.New(apperrors.CodeLocalIOError, "invalid mutation outcome spool outcome", nil)
	}
	return nil
}

func hasDuplicateJSONKeyFold(data []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(data))
	duplicate, err := jsonValueHasDuplicateKeyFold(decoder)
	if err != nil {
		return false
	}
	var extra any
	return duplicate || !errors.Is(decoder.Decode(&extra), io.EOF)
}

func jsonValueHasDuplicateKeyFold(decoder *json.Decoder) (bool, error) {
	token, err := decoder.Token()
	if err != nil {
		return false, err
	}
	delim, isDelim := token.(json.Delim)
	if !isDelim {
		return false, nil
	}
	switch delim {
	case '{':
		keys := make([]string, 0)
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return false, err
			}
			key, ok := keyToken.(string)
			if !ok {
				return false, apperrors.New(apperrors.CodeValidationFailed, "JSON object key is not a string", nil)
			}
			for _, existing := range keys {
				if strings.EqualFold(existing, key) {
					return true, nil
				}
			}
			keys = append(keys, key)
			duplicate, err := jsonValueHasDuplicateKeyFold(decoder)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
	case '[':
		for decoder.More() {
			duplicate, err := jsonValueHasDuplicateKeyFold(decoder)
			if err != nil || duplicate {
				return duplicate, err
			}
		}
	default:
		return false, apperrors.New(apperrors.CodeValidationFailed, "unexpected JSON delimiter", nil)
	}
	_, err = decoder.Token()
	return false, err
}

func validOptionalMutationFingerprint(fingerprint string, size int) bool {
	if fingerprint == "" || size == 0 {
		return fingerprint == "" && size == 0
	}
	return srvgovaudit.ValidFingerprint(fingerprint, size)
}

func validOptionalMutationFingerprint64(fingerprint string, size int64) bool {
	if fingerprint == "" || size == 0 {
		return fingerprint == "" && size == 0
	}
	return srvgovaudit.ValidFingerprint64(fingerprint, size)
}

func auditIncompleteError(mutationID string, spoolFailed bool) error {
	message := "mutation outcome audit is incomplete"
	if spoolFailed {
		message = "mutation outcome audit is incomplete and durable spooling failed"
	}
	suggestion := "Resolve audit storage before another mutation; a later mutation replays durable outcomes automatically."
	if mutationID != "" {
		suggestion = fmt.Sprintf(
			"Do not retry blindly. Check mutationId %s, resolve audit storage, then run a mutation to replay durable outcomes.",
			mutationID,
		)
	}
	return apperrors.New(codeAuditIncomplete, message, nil).WithSuggestion(suggestion)
}

func auditIndeterminateError(mutationID, phase string) error {
	message := "mutation audit commit state is indeterminate"
	suggestion := "Do not replay or retry automatically; inspect the audit log and durable spool before continuing."
	if mutationID != "" {
		suggestion = fmt.Sprintf(
			"Do not replay or retry automatically. Reconcile mutationId %s phase %s against the audit log and .indeterminate spool entry.",
			mutationID,
			phase,
		)
	}
	return apperrors.New(codeAuditIncomplete, message, nil).WithSuggestion(suggestion)
}
