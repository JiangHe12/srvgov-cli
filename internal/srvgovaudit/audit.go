// Package srvgovaudit defines srvgov audit records.
package srvgovaudit

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"strings"
	"time"

	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
)

// EventType identifies an srvgov audit event.
type EventType string

const (
	EventTypeExecRun             EventType = "exec.run"
	EventTypeAuthorizationDenied EventType = "authorization.denied"
	EventTypeAuditQuery          EventType = "audit.query"
	EventTypeAuditVerify         EventType = "audit.verify"
	EventTypeAuditPrune          EventType = "audit.prune"
	EventTypeRoleAssign          EventType = "role.assign"
	EventTypeRoleRevoke          EventType = "role.revoke"
	EventTypeContextSet          EventType = "context.set"
	EventTypeContextUse          EventType = "context.use"
	EventTypeContextDelete       EventType = "context.delete"
	EventTypeContextExport       EventType = "context.export"
	EventTypeContextImport       EventType = "context.import"
	EventTypeCredentialMigrate   EventType = "credential.migrate" //nolint:gosec // Event type name, not a credential value.
	EventTypeStatusObserve       EventType = "status.observe"
	EventTypePortsObserve        EventType = "ports.observe"
	EventTypeLogsObserve         EventType = "logs.observe"
	EventTypeSvcStatus           EventType = "svc.status"
	EventTypeSvcAction           EventType = "svc.action"
	EventTypeFileRead            EventType = "file.read"
	EventTypeFileStat            EventType = "file.stat"
	EventTypeFileList            EventType = "file.list"
	EventTypeFileWrite           EventType = "file.write"
	EventTypeDockerList          EventType = "docker.list"
	EventTypeDockerInspect       EventType = "docker.inspect"
	EventTypeDockerLogs          EventType = "docker.logs"
	EventTypeDockerAction        EventType = "docker.action"
)

const (
	StatusSucceeded = "succeeded"
	StatusFailed    = "failed"
	StatusDenied    = "denied"
)

// Event is one governed execution audit record.
type Event struct {
	Timestamp          time.Time         `json:"timestamp"`
	EventType          EventType         `json:"eventType"`
	Operator           string            `json:"operator"`
	Context            Context           `json:"context"`
	Ticket             string            `json:"ticket,omitempty"` // Legacy read compatibility; cleared before persistence/output.
	TicketFingerprint  string            `json:"ticketFingerprint,omitempty"`
	TicketBytes        int               `json:"ticketBytes,omitempty"`
	Reason             string            `json:"reason,omitempty"` // Legacy read compatibility; cleared before persistence/output.
	ReasonFingerprint  string            `json:"reasonFingerprint,omitempty"`
	ReasonBytes        int               `json:"reasonBytes,omitempty"`
	Target             Target            `json:"target"`
	Command            string            `json:"command,omitempty"` // Legacy read compatibility; cleared before persistence/output.
	CommandFingerprint string            `json:"commandFingerprint,omitempty"`
	CommandBytes       int               `json:"commandBytes,omitempty"`
	RiskTier           string            `json:"riskTier"`
	Status             string            `json:"status"`
	Stdout             string            `json:"stdout,omitempty"` // Legacy read compatibility; cleared before persistence/output.
	StdoutFingerprint  string            `json:"stdoutFingerprint,omitempty"`
	StdoutBytes        int               `json:"stdoutBytes,omitempty"`
	Stderr             string            `json:"stderr,omitempty"` // Legacy read compatibility; cleared before persistence/output.
	StderrFingerprint  string            `json:"stderrFingerprint,omitempty"`
	StderrBytes        int               `json:"stderrBytes,omitempty"`
	OutputIncomplete   bool              `json:"outputIncomplete,omitempty"`
	ExitCode           int               `json:"exitCode"`
	Error              *ErrorInfo        `json:"error,omitempty"`
	File               *FileInfo         `json:"file,omitempty"`
	MutationID         string            `json:"mutationId,omitempty"`
	OperationID        string            `json:"operationId,omitempty"`
	Phase              string            `json:"phase,omitempty"`
	Action             string            `json:"action,omitempty"`
	Metadata           *MutationMetadata `json:"metadata,omitempty"`
	Outcome            *MutationOutcome  `json:"outcome,omitempty"`
	ReadOutcome        *ReadOutcome      `json:"readOutcome,omitempty"`
}

// Context identifies the governed server context.
type Context struct {
	Name      string `json:"name"`
	Env       string `json:"env,omitempty"`
	Protected bool   `json:"protected"`
}

// Target identifies the SSH target.
type Target struct {
	Host        string `json:"host,omitempty"` // Legacy read compatibility; cleared before persistence/output.
	Fingerprint string `json:"fingerprint,omitempty"`
	Bytes       int    `json:"bytes,omitempty"`
}

// ErrorInfo is the stable audit error shape.
type ErrorInfo struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message,omitempty"` // Legacy read compatibility; cleared before persistence/output.
}

// FileInfo records file-write metadata without persisting file content.
type FileInfo struct {
	Path            string `json:"path,omitempty"` // Legacy read compatibility; cleared before persistence/output.
	PathFingerprint string `json:"pathFingerprint,omitempty"`
	PathBytes       int    `json:"pathBytes,omitempty"`
	BytesWritten    int64  `json:"bytesWritten"`
	SHA256          string `json:"sha256"`
}

// MutationMetadata records bounded, non-secret mutation descriptors.
type MutationMetadata struct {
	TargetFingerprint  string `json:"targetFingerprint,omitempty"`
	TargetBytes        int    `json:"targetBytes,omitempty"`
	PayloadFingerprint string `json:"payloadFingerprint,omitempty"`
	PayloadBytes       int    `json:"payloadBytes,omitempty"`
	Revision           string `json:"revision,omitempty"`
	Items              int    `json:"items,omitempty"`
	Creates            int    `json:"creates,omitempty"`
	Updates            int    `json:"updates,omitempty"`
	Deletes            int    `json:"deletes,omitempty"`
}

// MutationOutcome records a bounded mutation result without raw backend text.
type MutationOutcome struct {
	Status             string `json:"status"`
	ErrorCode          string `json:"errorCode,omitempty"`
	Succeeded          int    `json:"succeeded,omitempty"`
	Failed             int    `json:"failed,omitempty"`
	Skipped            int    `json:"skipped,omitempty"`
	Uncertain          int    `json:"uncertain,omitempty"`
	OutputIncomplete   bool   `json:"outputIncomplete,omitempty"`
	Revision           string `json:"revision,omitempty"`
	PayloadFingerprint string `json:"payloadFingerprint,omitempty"`
	PayloadBytes       int64  `json:"payloadBytes,omitempty"`
}

// ReadOutcome records whether a required audited read completed without
// persisting backend response bodies.
type ReadOutcome struct {
	Status           string `json:"status"`
	ErrorCode        string `json:"errorCode,omitempty"`
	OutputIncomplete bool   `json:"outputIncomplete,omitempty"`
}

// Append redacts sensitive fields and writes through the shared audit engine.
func Append(path string, event Event, opts coreaudit.Options) error {
	_, err := AppendWithResult(path, event, opts)
	return err
}

// AppendWithResult redacts sensitive fields and reports the durable commit
// state returned by the shared audit engine.
func AppendWithResult(path string, event Event, opts coreaudit.Options) (coreaudit.AppendResult, error) {
	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event = Sanitize(event)
	return coreaudit.AppendRecordWithResult(path, event, opts)
}

// AppendRecord serializes a caller-sanitized record with all other srvgov
// audit writes in this process.
func AppendRecord(path string, record any, opts coreaudit.Options) error {
	_, err := AppendRecordWithResult(path, record, opts)
	return err
}

// AppendRecordWithResult serializes a caller-sanitized record and reports its
// durable commit state. Cross-process serialization is owned by opskit-core.
func AppendRecordWithResult(path string, record any, opts coreaudit.Options) (coreaudit.AppendResult, error) {
	return coreaudit.AppendRecordWithResult(path, record, opts)
}

// Sanitize replaces raw free text with domain-separated fingerprints and byte
// lengths. Fingerprints are correlation aids, not secret storage.
func Sanitize(event Event) Event {
	event.TicketFingerprint, event.TicketBytes = mergeFingerprint(
		"ticket", event.Ticket, event.TicketFingerprint, event.TicketBytes,
	)
	event.Ticket = ""
	event.ReasonFingerprint, event.ReasonBytes = mergeFingerprint(
		"reason", event.Reason, event.ReasonFingerprint, event.ReasonBytes,
	)
	event.Reason = ""
	event.CommandFingerprint, event.CommandBytes = mergeFingerprint(
		"command", event.Command, event.CommandFingerprint, event.CommandBytes,
	)
	event.Command = ""
	event.StdoutFingerprint, event.StdoutBytes = mergeFingerprint(
		"stdout", event.Stdout, event.StdoutFingerprint, event.StdoutBytes,
	)
	event.Stdout = ""
	event.StderrFingerprint, event.StderrBytes = mergeFingerprint(
		"stderr", event.Stderr, event.StderrFingerprint, event.StderrBytes,
	)
	event.Stderr = ""
	event.Target.Fingerprint, event.Target.Bytes = mergeFingerprint(
		"target", event.Target.Host, event.Target.Fingerprint, event.Target.Bytes,
	)
	event.Target.Host = ""
	if event.File != nil {
		cloned := *event.File
		cloned.PathFingerprint, cloned.PathBytes = mergeFingerprint(
			"file-path", cloned.Path, cloned.PathFingerprint, cloned.PathBytes,
		)
		cloned.Path = ""
		if cloned.BytesWritten < 0 {
			cloned.BytesWritten = 0
		}
		if !validBareSHA256(cloned.SHA256) {
			cloned.SHA256 = ""
		}
		event.File = &cloned
	}
	if event.Error != nil {
		cloned := *event.Error
		cloned.Message = ""
		event.Error = &cloned
	}
	if event.Metadata != nil {
		cloned := *event.Metadata
		cloned.TargetFingerprint, cloned.TargetBytes = normalizeFingerprint(
			cloned.TargetFingerprint,
			cloned.TargetBytes,
		)
		cloned.PayloadFingerprint, cloned.PayloadBytes = normalizeFingerprint(
			cloned.PayloadFingerprint,
			cloned.PayloadBytes,
		)
		cloned.Items = max(0, cloned.Items)
		cloned.Creates = max(0, cloned.Creates)
		cloned.Updates = max(0, cloned.Updates)
		cloned.Deletes = max(0, cloned.Deletes)
		if len([]byte(cloned.Revision)) > 256 {
			cloned.Revision = ""
		}
		event.Metadata = &cloned
	}
	if event.Outcome != nil {
		cloned := *event.Outcome
		cloned.Succeeded = max(0, cloned.Succeeded)
		cloned.Failed = max(0, cloned.Failed)
		cloned.Skipped = max(0, cloned.Skipped)
		if !ValidFingerprint64(cloned.PayloadFingerprint, cloned.PayloadBytes) {
			cloned.PayloadFingerprint = ""
			cloned.PayloadBytes = 0
		}
		if len([]byte(cloned.Revision)) > 256 {
			cloned.Revision = ""
		}
		event.Outcome = &cloned
	}
	return event
}

// Fingerprint returns a deterministic, domain-separated digest and byte length.
func Fingerprint(domain, value string) (string, int) {
	if value == "" {
		return "", 0
	}
	hash := sha256.New()
	_, _ = io.WriteString(hash, "srvgov-cli.io/audit-fingerprint/v1")
	_, _ = hash.Write([]byte{0})
	_, _ = io.WriteString(hash, domain)
	_, _ = hash.Write([]byte{0})
	_, _ = io.WriteString(hash, value)
	return "sha256:" + hex.EncodeToString(hash.Sum(nil)), len([]byte(value))
}

func mergeFingerprint(domain, raw, fingerprint string, size int) (string, int) {
	if raw != "" {
		return Fingerprint(domain, raw)
	}
	return normalizeFingerprint(fingerprint, size)
}

func normalizeFingerprint(fingerprint string, size int) (string, int) {
	if !ValidFingerprint(fingerprint, size) {
		return "", 0
	}
	return fingerprint, size
}

// ValidFingerprint reports whether a persisted correlation fingerprint has the
// canonical bounded shape emitted by Fingerprint.
func ValidFingerprint(fingerprint string, size int) bool {
	return size > 0 && validFingerprintText(fingerprint)
}

// ValidFingerprint64 is the int64 byte-count variant used by outcome payloads.
func ValidFingerprint64(fingerprint string, size int64) bool {
	return size > 0 && validFingerprintText(fingerprint)
}

func validFingerprintText(fingerprint string) bool {
	if len(fingerprint) != len("sha256:")+sha256.Size*2 ||
		!strings.HasPrefix(fingerprint, "sha256:") {
		return false
	}
	encoded := strings.TrimPrefix(fingerprint, "sha256:")
	if encoded != strings.ToLower(encoded) {
		return false
	}
	decoded, err := hex.DecodeString(encoded)
	return err == nil && len(decoded) == sha256.Size
}

func validBareSHA256(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != sha256.Size*2 || value != strings.ToLower(value) {
		return false
	}
	decoded, err := hex.DecodeString(value)
	return err == nil && len(decoded) == sha256.Size
}
