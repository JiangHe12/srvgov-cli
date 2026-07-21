package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

var (
	version = "dev"
	commit  = unknownBuildValue
	built   = unknownBuildValue
)

const unknownBuildValue = "unknown"

type versionInfo struct {
	Built   string `json:"built"`
	Commit  string `json:"commit"`
	Version string `json:"version"`
}

// SetVersionInfo supplies build metadata from main.
func SetVersionInfo(nextVersion, nextCommit, nextBuilt string) {
	if nextVersion != "" {
		version = nextVersion
	}
	commit = buildMetadataValue(nextCommit)
	built = buildMetadataValue(nextBuilt)
}

func buildMetadataValue(value string) string {
	if value == "" {
		return unknownBuildValue
	}
	return value
}

func newVersionCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			info := versionInfo{Built: built, Commit: commit, Version: version}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONData("VersionInfo", info)
			}
			if f.Output == "plain" {
				return p.Info(info.Version)
			}
			return p.Info(fmt.Sprintf(
				"srvgov-cli %s (commit: %s, built: %s)",
				info.Version,
				info.Commit,
				info.Built,
			))
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
	ContextAPIVersions       []string      `json:"contextApiVersions"`
	AuditAPIVersions         []string      `json:"auditApiVersions"`
	MutationAuditAPIVersions []string      `json:"mutationAuditApiVersions"`
	ErrorCodes               []string      `json:"errorCodes"`
	RiskModel                []CapRisk     `json:"riskModel"`
	AllowFlags               []string      `json:"allowFlags"`
	Governance               CapGovernance `json:"governance"`
	Commands                 []string      `json:"commands"`
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
	Fanout    string `json:"fanout"`
}

func capabilitiesData() CapabilitiesData {
	return CapabilitiesData{
		Tool: CapTool{Name: "srvgov", Version: version},
		Supported: CapSupported{
			ContextAPIVersions:       []string{"srvgov-cli.io/context/v1"},
			AuditAPIVersions:         []string{"opskit-core.io/audit/v2", "srvgov-cli.io/audit/v1"},
			MutationAuditAPIVersions: []string{mutationAuditAPIVersion},
			ErrorCodes:               []string{string(codeAuditIncomplete)},
			RiskModel: []CapRisk{
				{Level: "R0", Authorization: "free"},
				{Level: "R1", Authorization: "--reason plus --yes or interactive confirmation"},
				{Level: "R2", Authorization: "--reason plus --yes plus --ticket"},
				{Level: "R3", Authorization: "--yes plus --ticket plus the operation-specific --allow-* flag; remote changes also require --reason"},
			},
			AllowFlags: []string{
				"--allow-destructive",
				"--allow-context-change",
				"--allow-context-delete",
				"--allow-role-change",
				"--allow-audit-prune",
			},
			Governance: CapGovernance{
				Audit:     "authenticated v2 envelopes use commit-aware mutation audit; not-committed outcomes enter a private replay spool, indeterminate appends are quarantined while already-started outcomes queue behind the marker, and confirmed checkpoint-aware prune is R3 with sibling control evidence, --confirm, --yes, a ticket, and --allow-audit-prune",
				RBAC:      "opt-in roles reader/writer/admin",
				DryRun:    true,
				TOFU:      "strict SSH host-key fingerprint pinning",
				Redaction: "audit persistence omits raw tickets, reasons, commands, targets, output, and error messages; bounded SHA-256 fingerprints and byte lengths are stored",
				Fanout:    "status, ports, and logs require R0 for every target; exec, svc, file, and docker authorize every target and persist a batch intent before any execution; --selector resolves targets by context labels",
			},
			Commands: []string{
				"ctx",
				"exec",
				"status",
				"ports",
				"logs",
				"svc",
				"file",
				"docker",
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
					if err := p.Info(command); err != nil {
						return err
					}
				}
				return nil
			}
			rows := [][]string{
				{"contextApiVersions", strings.Join(data.Supported.ContextAPIVersions, ", ")},
				{"auditApiVersions", strings.Join(data.Supported.AuditAPIVersions, ", ")},
				{"mutationAuditApiVersions", strings.Join(data.Supported.MutationAuditAPIVersions, ", ")},
				{"errorCodes", strings.Join(data.Supported.ErrorCodes, ", ")},
				{"authorization", "R1 requires --reason/--yes; R2 adds --ticket; R3 requires an operation-specific --allow-*"},
				{"governance", "audit, RBAC, dry-run, strict TOFU, redaction, authorize-all governed fanout"},
				{"commands", "ctx, exec, status, ports, logs, svc, file, docker, audit, doctor, version, capabilities, install"},
			}
			return p.Table([]string{"KEY", "VALUE"}, rows)
		},
	}
}
