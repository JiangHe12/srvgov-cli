// Package srvgovaudit defines srvgov audit records.
package srvgovaudit

import (
	"sync"
	"time"

	coreaudit "github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/redact"
)

var appendMu sync.Mutex

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
	Timestamp time.Time  `json:"timestamp"`
	EventType EventType  `json:"eventType"`
	Operator  string     `json:"operator"`
	Context   Context    `json:"context"`
	Ticket    string     `json:"ticket,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Target    Target     `json:"target"`
	Command   string     `json:"command"`
	RiskTier  string     `json:"riskTier"`
	Status    string     `json:"status"`
	Stdout    string     `json:"stdout,omitempty"`
	Stderr    string     `json:"stderr,omitempty"`
	ExitCode  int        `json:"exitCode"`
	Error     *ErrorInfo `json:"error,omitempty"`
	File      *FileInfo  `json:"file,omitempty"`
}

// Context identifies the governed server context.
type Context struct {
	Name      string `json:"name"`
	Env       string `json:"env,omitempty"`
	Protected bool   `json:"protected"`
}

// Target identifies the SSH target.
type Target struct {
	Host string `json:"host"`
}

// ErrorInfo is the stable audit error shape.
type ErrorInfo struct {
	Code    string `json:"code,omitempty"`
	Message string `json:"message"`
}

// FileInfo records file-write metadata without persisting file content.
type FileInfo struct {
	Path         string `json:"path"`
	BytesWritten int64  `json:"bytesWritten"`
	SHA256       string `json:"sha256"`
}

// Append redacts sensitive fields and writes through the shared audit engine.
func Append(path string, event Event, opts coreaudit.Options) error {
	appendMu.Lock()
	defer appendMu.Unlock()

	if event.Timestamp.IsZero() {
		event.Timestamp = time.Now().UTC()
	}
	event = Sanitize(event)
	return coreaudit.AppendRecord(path, event, opts)
}

// Sanitize redacts all free-text fields that can contain command output or credentials.
func Sanitize(event Event) Event {
	event.Command = redact.String(event.Command)
	event.Stdout = redact.String(event.Stdout)
	event.Stderr = redact.String(event.Stderr)
	if event.File != nil {
		cloned := *event.File
		cloned.Path = redact.String(cloned.Path)
		event.File = &cloned
	}
	if event.Error != nil {
		cloned := *event.Error
		cloned.Message = redact.String(cloned.Message)
		event.Error = &cloned
	}
	return event
}
