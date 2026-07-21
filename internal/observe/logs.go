package observe

import (
	"bufio"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/JiangHe12/opskit-core/v2/redact"
)

// LogOptions controls journal or file observation.
type LogOptions struct {
	Unit     string
	File     string
	Since    string
	Lines    int
	Priority string
	Grep     string
}

// LogLine is one normalized journal or file log line.
type LogLine struct {
	Timestamp string `json:"timestamp"`
	Hostname  string `json:"hostname"`
	Unit      string `json:"unit"`
	Priority  string `json:"priority"`
	Message   string `json:"message"`
}

// JournalCommand builds a shell-safe, pipe-free journalctl command.
func JournalCommand(opts LogOptions) string {
	parts := []string{"journalctl", "--no-pager", "--output=json", "--lines", strconv.Itoa(opts.Lines)}
	appendQuotedOption := func(name, value string) {
		if value != "" {
			parts = append(parts, name, ShellQuote(value))
		}
	}
	appendQuotedOption("--unit", opts.Unit)
	appendQuotedOption("--since", opts.Since)
	appendQuotedOption("--priority", opts.Priority)
	appendQuotedOption("--grep", opts.Grep)
	return strings.Join(parts, " ")
}

// FileCommand builds a shell-safe tail command. Grep filtering is local.
func FileCommand(opts LogOptions) string {
	return fmt.Sprintf("tail -n %d -- %s", opts.Lines, ShellQuote(opts.File))
}

// SystemctlCommand provides a journal fallback for one unit.
func SystemctlCommand(opts LogOptions) string {
	return fmt.Sprintf("systemctl status --no-pager --lines %d -- %s", opts.Lines, ShellQuote(opts.Unit))
}

// ShellQuote returns one POSIX shell word with all input treated literally.
func ShellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", `'"'"'`) + "'"
}

// ParseJournal parses journalctl JSON lines and skips malformed records.
func ParseJournal(value string) []LogLine {
	result := make([]LogLine, 0)
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		var record map[string]any
		if err := json.Unmarshal(scanner.Bytes(), &record); err != nil {
			continue
		}
		result = append(result, LogLine{
			Timestamp: journalTimestamp(stringValue(record["__REALTIME_TIMESTAMP"])),
			Hostname:  redact.String(stringValue(record["_HOSTNAME"])),
			Unit:      redact.String(firstValue(record, "_SYSTEMD_UNIT", "SYSLOG_IDENTIFIER")),
			Priority:  redact.String(stringValue(record["PRIORITY"])),
			Message:   redact.String(stringValue(record["MESSAGE"])),
		})
	}
	return result
}

// ParseFileLines normalizes file lines, optionally filtering by literal text.
func ParseFileLines(value, grep string) []LogLine {
	result := make([]LogLine, 0)
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		line := scanner.Text()
		if grep != "" && !strings.Contains(line, grep) {
			continue
		}
		result = append(result, LogLine{Message: redact.String(line)})
	}
	return result
}

// ParseDockerLines normalizes --timestamps output and preserves malformed lines.
func ParseDockerLines(values ...string) []LogLine {
	result := make([]LogLine, 0)
	for _, value := range values {
		scanner := bufio.NewScanner(strings.NewReader(value))
		for scanner.Scan() {
			line := scanner.Text()
			timestamp, message, ok := strings.Cut(line, " ")
			parsed, err := time.Parse(time.RFC3339Nano, timestamp)
			if !ok || err != nil {
				result = append(result, LogLine{Message: redact.String(line)})
				continue
			}
			result = append(result, LogLine{
				Timestamp: parsed.UTC().Format(time.RFC3339Nano),
				Message:   redact.String(message),
			})
		}
	}
	return result
}

func firstValue(record map[string]any, names ...string) string {
	for _, name := range names {
		if value := stringValue(record[name]); value != "" {
			return value
		}
	}
	return ""
}

func stringValue(value any) string {
	switch typed := value.(type) {
	case string:
		return typed
	case json.Number:
		return typed.String()
	case float64:
		return strconv.FormatFloat(typed, 'f', -1, 64)
	default:
		return ""
	}
}

func journalTimestamp(value string) string {
	micros, err := strconv.ParseInt(value, 10, 64)
	if err != nil {
		return redact.String(value)
	}
	return time.UnixMicro(micros).UTC().Format(time.RFC3339Nano)
}
