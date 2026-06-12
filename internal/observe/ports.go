package observe

import (
	"bufio"
	"regexp"
	"strconv"
	"strings"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/redact"
)

var ssProcessPattern = regexp.MustCompile(`\("([^"]*)",pid=([0-9]+)`)

// Port is one listening local socket.
type Port struct {
	Proto     string `json:"proto"`
	LocalAddr string `json:"localAddr"`
	LocalPort int    `json:"localPort"`
	State     string `json:"state"`
	PID       int    `json:"pid,omitempty"`
	Process   string `json:"process,omitempty"`
}

// PortProbes returns preferred and fallback socket-listing commands.
func PortProbes() []Probe {
	return []Probe{
		{Name: "ss", Command: "ss -H -lntup"},
		{Name: "netstat", Command: "netstat -lntup"},
	}
}

// ParsePorts parses output from ss or netstat and skips malformed rows.
func ParsePorts(backend, value string) ([]Port, error) {
	switch backend {
	case "ss":
		return parseSS(value), nil
	case "netstat":
		return parseNetstat(value), nil
	default:
		return nil, apperrors.New(apperrors.CodeValidationFailed, "unsupported ports backend", nil)
	}
}

func parseSS(value string) []Port {
	result := make([]Port, 0)
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 {
			continue
		}
		address, port, ok := splitEndpoint(fields[4])
		if !ok {
			continue
		}
		item := Port{
			Proto:     redact.String(fields[0]),
			State:     redact.String(fields[1]),
			LocalAddr: redact.String(address),
			LocalPort: port,
		}
		if match := ssProcessPattern.FindStringSubmatch(scanner.Text()); len(match) == 3 {
			item.Process = redact.String(match[1])
			item.PID, _ = strconv.Atoi(match[2])
		}
		result = append(result, item)
	}
	return result
}

func parseNetstat(value string) []Port {
	result := make([]Port, 0)
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 5 || fields[0] == "Proto" || strings.HasPrefix(fields[0], "Active") {
			continue
		}
		address, port, ok := splitEndpoint(fields[3])
		if !ok {
			continue
		}
		item := Port{
			Proto:     redact.String(fields[0]),
			LocalAddr: redact.String(address),
			LocalPort: port,
		}
		processIndex := 5
		if strings.HasPrefix(strings.ToLower(fields[0]), "tcp") && len(fields) > 5 {
			item.State = redact.String(fields[5])
			processIndex = 6
		}
		if len(fields) > processIndex {
			item.PID, item.Process = parsePIDProcess(fields[processIndex])
		}
		result = append(result, item)
	}
	return result
}

func splitEndpoint(value string) (string, int, bool) {
	pos := strings.LastIndex(value, ":")
	if pos < 0 || pos == len(value)-1 {
		return "", 0, false
	}
	port, err := strconv.Atoi(value[pos+1:])
	if err != nil {
		return "", 0, false
	}
	address := strings.Trim(value[:pos], "[]")
	return address, port, true
}

func parsePIDProcess(value string) (int, string) {
	if value == "-" {
		return 0, ""
	}
	pidText, process, ok := strings.Cut(value, "/")
	if !ok {
		return 0, redact.String(value)
	}
	pid, _ := strconv.Atoi(pidText)
	return pid, redact.String(process)
}
