package observe

import (
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
)

func TestGeneratedCommandsAreReadOnlyAndInjectionSafe(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		command string
	}{
		{name: "status hostname", command: StatusProbes()[0].Command},
		{name: "ports ss", command: PortProbes()[0].Command},
		{name: "ports netstat", command: PortProbes()[1].Command},
		{
			name: "journal unit injection is literal",
			command: JournalCommand(LogOptions{
				Unit:     "nginx; rm -rf /",
				Since:    "1 hour ago",
				Lines:    20,
				Priority: "warning",
				Grep:     "$(touch /tmp/pwned)",
			}),
		},
		{
			name: "file path injection is literal",
			command: FileCommand(LogOptions{
				File:  "/var/log/app'; rm -rf /; echo '",
				Lines: 20,
			}),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := cmdclass.Classify(tt.command); got != safety.R0 {
				t.Fatalf("Classify(%q) = R%d, want R0", tt.command, got)
			}
		})
	}
}

func TestJournalCommandKeepsFreeTextInsideSingleQuotedArguments(t *testing.T) {
	t.Parallel()

	command := JournalCommand(LogOptions{
		Unit:  "nginx; rm -rf /",
		Since: "today' or yesterday",
		Lines: 5,
		Grep:  "`reboot`",
	})
	for _, want := range []string{
		`--unit 'nginx; rm -rf /'`,
		`--since 'today'"'"' or yesterday'`,
		`--grep '` + "`reboot`" + `'`,
	} {
		if !strings.Contains(command, want) {
			t.Fatalf("JournalCommand() = %q, want fragment %q", command, want)
		}
	}
}

func TestParseStatusAllowsPartialData(t *testing.T) {
	t.Parallel()

	got := ParseStatus(map[string]string{
		"hostname": "web-01\n",
		"kernel":   "Linux 6.8.0 x86_64\n",
		"uptime":   "1234.50 77.00\n",
		"load":     "0.10 0.20 0.30 1/100 42\n",
		"cpu":      "processor : 0\nmodel name : Example CPU password=cpu-secret\nprocessor : 1\n",
		"mem":      "MemTotal: 1000 kB\nMemFree: 200 kB\nMemAvailable: 300 kB\nBuffers: 100 kB\nCached: 150 kB\n",
		"disk":     "Filesystem 1024-blocks Used Available Capacity Mounted on\n/dev/sda1 1000 400 600 40% /\n",
	})

	if got.Hostname != "web-01" || got.Uptime != 1234.5 {
		t.Fatalf("status identity = %#v", got)
	}
	if got.Load.One != 0.1 || got.Load.Five != 0.2 || got.Load.Fifteen != 0.3 {
		t.Fatalf("load = %#v", got.Load)
	}
	if got.CPU.Cores != 2 || strings.Contains(got.CPU.Model, "cpu-secret") {
		t.Fatalf("cpu = %#v", got.CPU)
	}
	if got.Mem.Total != 1024000 || got.Mem.Free != 307200 || got.Mem.Used != 716800 {
		t.Fatalf("mem = %#v", got.Mem)
	}
	if len(got.Disk) != 1 || got.Disk[0].Mount != "/" || got.Disk[0].UsePct != 40 {
		t.Fatalf("disk = %#v", got.Disk)
	}
}

func TestParseStatusKeepsUniqueBlockDevicesOnly(t *testing.T) {
	t.Parallel()

	got := ParseStatus(map[string]string{
		"disk": "Filesystem 1024-blocks Used Available Capacity Mounted on\n" +
			"overlay 1000 400 600 40% /var/lib/docker/overlay2/abc/merged\n" +
			"tmpfs 100 1 99 1% /run\n" +
			"/dev/mapper/centos-root 2000 1000 1000 50% /\n" +
			"/dev/mapper/centos-root 2000 1000 1000 50% /var/lib/docker/bind\n" +
			"/dev/sdb1 3000 1000 2000 33% /data\n",
	})

	if len(got.Disk) != 2 {
		t.Fatalf("disk = %#v, want two unique block devices", got.Disk)
	}
	if got.Disk[0].Mount != "/" || got.Disk[1].Mount != "/data" {
		t.Fatalf("disk = %#v", got.Disk)
	}
}

func TestParsePortsSupportsSSAndNetstat(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		backend string
		input   string
		want    Port
	}{
		{
			name:    "ss with process",
			backend: "ss",
			input:   `tcp LISTEN 0 4096 127.0.0.1:8080 0.0.0.0:* users:(("api password=port-secret",pid=321,fd=7))`,
			want:    Port{Proto: "tcp", LocalAddr: "127.0.0.1", LocalPort: 8080, State: "LISTEN", PID: 321, Process: `api password=[REDACTED]`},
		},
		{
			name:    "netstat without process permission",
			backend: "netstat",
			input:   "udp 0 0 0.0.0.0:53 0.0.0.0:* -\n",
			want:    Port{Proto: "udp", LocalAddr: "0.0.0.0", LocalPort: 53},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ParsePorts(tt.backend, tt.input)
			if err != nil {
				t.Fatalf("ParsePorts() error = %v", err)
			}
			if len(got) != 1 || got[0] != tt.want {
				t.Fatalf("ParsePorts() = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestParsePortsSkipsMalformedRows(t *testing.T) {
	t.Parallel()

	got, err := ParsePorts("ss", "not enough columns\nudp UNCONN 0 0 [::]:5353 [::]:*\n")
	if err != nil {
		t.Fatalf("ParsePorts() error = %v", err)
	}
	if len(got) != 1 || got[0].LocalPort != 5353 {
		t.Fatalf("ParsePorts() = %#v", got)
	}
}

func TestParseLogsRedactsStructuredFields(t *testing.T) {
	t.Parallel()

	journal := `{"__REALTIME_TIMESTAMP":"1710000000000000","_HOSTNAME":"web-01","SYSLOG_IDENTIFIER":"api token=unit-secret","PRIORITY":"3","MESSAGE":"password=journal-secret"}` + "\n"
	lines := ParseJournal(journal)
	if len(lines) != 1 {
		t.Fatalf("ParseJournal() = %#v", lines)
	}
	if strings.Contains(lines[0].Unit, "unit-secret") || strings.Contains(lines[0].Message, "journal-secret") {
		t.Fatalf("journal line leaked secret: %#v", lines[0])
	}

	fileLines := ParseFileLines("user=bob password=file-secret\nnormal line\n", "password")
	if len(fileLines) != 1 || strings.Contains(fileLines[0].Message, "file-secret") {
		t.Fatalf("ParseFileLines() = %#v", fileLines)
	}
}

func TestParseDockerLogsUsesTimestampAndFallsBackForMalformedLines(t *testing.T) {
	t.Parallel()

	lines := ParseDockerLines(
		"2026-06-12T08:15:30.123456789Z ready password=docker-secret\n" +
			"not-a-timestamp whole line\n",
	)
	if len(lines) != 2 {
		t.Fatalf("ParseDockerLines() = %#v", lines)
	}
	if lines[0].Timestamp != "2026-06-12T08:15:30.123456789Z" ||
		lines[0].Message != "ready password=[REDACTED]" {
		t.Fatalf("timestamped line = %#v", lines[0])
	}
	if lines[1].Timestamp != "" || lines[1].Message != "not-a-timestamp whole line" {
		t.Fatalf("fallback line = %#v", lines[1])
	}
}
