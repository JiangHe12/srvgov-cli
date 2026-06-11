package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = ""
	date    = ""
)

type versionInfo struct {
	Version string `json:"version"`
	Commit  string `json:"commit,omitempty"`
	Date    string `json:"date,omitempty"`
}

// SetVersionInfo supplies build metadata from main.
func SetVersionInfo(nextVersion, nextCommit, nextDate string) {
	if nextVersion != "" {
		version = nextVersion
	}
	commit = nextCommit
	date = nextDate
}

func newVersionCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := versionInfo{Version: version, Commit: commit, Date: date}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONData("VersionInfo", info)
			}
			if f.Output == "plain" {
				_, _ = fmt.Fprintln(p.Out, info.Version)
				return nil
			}
			rows := [][2]string{{"version", info.Version}}
			if info.Commit != "" {
				rows = append(rows, [2]string{"commit", info.Commit})
			}
			if info.Date != "" {
				rows = append(rows, [2]string{"date", info.Date})
			}
			p.KV(rows)
			return nil
		},
	}
}

type CapabilitiesData struct {
	Tool      CapTool      `json:"tool"`
	Supported CapSupported `json:"supported"`
}

type CapTool struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CapSupported struct {
	ContextAPIVersion string        `json:"contextApiVersion"`
	AuditAPIVersion   string        `json:"auditApiVersion"`
	RiskModel         []CapRisk     `json:"riskModel"`
	AllowFlags        []string      `json:"allowFlags"`
	Governance        CapGovernance `json:"governance"`
	Commands          []string      `json:"commands"`
}

type CapRisk struct {
	Level         string `json:"level"`
	Authorization string `json:"authorization"`
}

type CapGovernance struct {
	Audit     string `json:"audit"`
	RBAC      string `json:"rbac"`
	DryRun    bool   `json:"dryRun"`
	TOFU      string `json:"tofu"`
	Redaction string `json:"redaction"`
}

func capabilitiesData() CapabilitiesData {
	return CapabilitiesData{
		Tool: CapTool{Name: "srvgov", Version: version},
		Supported: CapSupported{
			ContextAPIVersion: "srvgov.io/context/v1",
			AuditAPIVersion:   "srvgov.io/audit/v1",
			RiskModel: []CapRisk{
				{Level: "R0", Authorization: "free"},
				{Level: "R1", Authorization: "--reason plus --yes or interactive confirmation"},
				{Level: "R2", Authorization: "--reason plus --yes plus --ticket"},
				{Level: "R3", Authorization: "--reason plus --yes plus --ticket plus --allow-destructive"},
			},
			AllowFlags: []string{"--allow-destructive"},
			Governance: CapGovernance{
				Audit:     "append-only JSONL with optional age encryption",
				RBAC:      "opt-in roles reader/writer/admin",
				DryRun:    true,
				TOFU:      "strict SSH host-key fingerprint pinning",
				Redaction: "command, stdout, stderr, and audit fields are redacted",
			},
			Commands: []string{
				"ctx",
				"exec",
				"status",
				"ports",
				"logs",
				"audit",
				"doctor",
				"version",
				"capabilities",
				"install",
			},
		},
	}
}

func newCapabilitiesCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "capabilities",
		Short: "Show static srvgov capabilities",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			data := capabilitiesData()
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONData("Capabilities", data)
			}
			if f.Output == "plain" {
				for _, command := range data.Supported.Commands {
					_, _ = fmt.Fprintln(p.Out, command)
				}
				return nil
			}
			rows := [][]string{
				{"contextApiVersion", data.Supported.ContextAPIVersion},
				{"auditApiVersion", data.Supported.AuditAPIVersion},
				{"authorization", "R1 requires --reason/--yes; R2 adds --ticket; R3 adds --allow-destructive"},
				{"governance", "audit, RBAC, dry-run, strict TOFU, redaction"},
				{"commands", "ctx, exec, status, ports, logs, audit, doctor, version, capabilities, install"},
			}
			p.Table([]string{"KEY", "VALUE"}, rows)
			return nil
		},
	}
}
