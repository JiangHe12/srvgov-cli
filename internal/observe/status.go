// Package observe builds and parses read-only server observation commands.
package observe

import (
	"bufio"
	"strconv"
	"strings"

	"github.com/JiangHe12/opskit-core/redact"
)

// Probe is one independent read-only remote observation.
type Probe struct {
	Name    string
	Command string
}

// Status is the stable structured server status response.
type Status struct {
	Hostname string  `json:"hostname"`
	Uptime   float64 `json:"uptime"`
	Load     Load    `json:"load"`
	CPU      CPU     `json:"cpu"`
	Mem      Memory  `json:"mem"`
	Disk     []Disk  `json:"disk"`
	Kernel   string  `json:"kernel"`
}

// Load contains the standard one, five, and fifteen minute load averages.
type Load struct {
	One     float64 `json:"1"`
	Five    float64 `json:"5"`
	Fifteen float64 `json:"15"`
}

// CPU summarizes the detected processor model and logical core count.
type CPU struct {
	Model string `json:"model"`
	Cores int    `json:"cores"`
}

// Memory contains byte counts.
type Memory struct {
	Total int64 `json:"total"`
	Used  int64 `json:"used"`
	Free  int64 `json:"free"`
}

// Disk contains byte counts for one mounted filesystem.
type Disk struct {
	Mount  string `json:"mount"`
	Size   int64  `json:"size"`
	Used   int64  `json:"used"`
	Avail  int64  `json:"avail"`
	UsePct int    `json:"usePct"`
}

// StatusProbes returns independent commands so governance classifies each one.
func StatusProbes() []Probe {
	return []Probe{
		{Name: "hostname", Command: "hostname"},
		{Name: "kernel", Command: "uname -srm"},
		{Name: "uptime", Command: "cat /proc/uptime"},
		{Name: "load", Command: "cat /proc/loadavg"},
		{Name: "cpu", Command: "cat /proc/cpuinfo"},
		{Name: "mem", Command: "cat /proc/meminfo"},
		{Name: "disk", Command: "df -Pk"},
	}
}

// ParseStatus builds a partial status response from successful probe output.
func ParseStatus(values map[string]string) Status {
	result := Status{
		Hostname: redact.String(strings.TrimSpace(values["hostname"])),
		Kernel:   redact.String(strings.TrimSpace(values["kernel"])),
		Disk:     []Disk{},
	}
	if fields := strings.Fields(values["uptime"]); len(fields) > 0 {
		result.Uptime, _ = strconv.ParseFloat(fields[0], 64)
	}
	if fields := strings.Fields(values["load"]); len(fields) >= 3 {
		result.Load.One, _ = strconv.ParseFloat(fields[0], 64)
		result.Load.Five, _ = strconv.ParseFloat(fields[1], 64)
		result.Load.Fifteen, _ = strconv.ParseFloat(fields[2], 64)
	}
	result.CPU = parseCPU(values["cpu"])
	result.Mem = parseMemory(values["mem"])
	result.Disk = parseDisk(values["disk"])
	return result
}

func parseCPU(value string) CPU {
	var result CPU
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		line := scanner.Text()
		key, data, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(key) {
		case "processor":
			result.Cores++
		case "model name", "Hardware":
			if result.Model == "" {
				result.Model = redact.String(strings.TrimSpace(data))
			}
		}
	}
	return result
}

func parseMemory(value string) Memory {
	fields := make(map[string]int64)
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		line := scanner.Text()
		key, data, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		parts := strings.Fields(data)
		if len(parts) == 0 {
			continue
		}
		number, err := strconv.ParseInt(parts[0], 10, 64)
		if err == nil {
			fields[strings.TrimSpace(key)] = number * 1024
		}
	}
	total := fields["MemTotal"]
	free := fields["MemAvailable"]
	if free == 0 {
		free = fields["MemFree"] + fields["Buffers"] + fields["Cached"]
	}
	used := total - free
	if used < 0 {
		used = 0
	}
	return Memory{Total: total, Used: used, Free: free}
}

func parseDisk(value string) []Disk {
	var result []Disk
	seenDevices := make(map[string]bool)
	scanner := bufio.NewScanner(strings.NewReader(value))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 6 || fields[0] == "Filesystem" {
			continue
		}
		device := fields[0]
		if !strings.HasPrefix(device, "/dev/") || seenDevices[device] {
			continue
		}
		size, sizeErr := strconv.ParseInt(fields[1], 10, 64)
		used, usedErr := strconv.ParseInt(fields[2], 10, 64)
		avail, availErr := strconv.ParseInt(fields[3], 10, 64)
		usePct, pctErr := strconv.Atoi(strings.TrimSuffix(fields[4], "%"))
		if sizeErr != nil || usedErr != nil || availErr != nil || pctErr != nil {
			continue
		}
		seenDevices[device] = true
		result = append(result, Disk{
			Mount:  redact.String(strings.Join(fields[5:], " ")),
			Size:   size * 1024,
			Used:   used * 1024,
			Avail:  avail * 1024,
			UsePct: usePct,
		})
	}
	if result == nil {
		return []Disk{}
	}
	return result
}
