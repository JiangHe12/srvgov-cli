package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

// DoctorReport is the stable local health-check result.
type DoctorReport struct {
	Checks []DoctorCheck `json:"checks"`
}

// DoctorCheck is one read-only diagnostic.
type DoctorCheck struct {
	Name    string `json:"name"`
	Status  string `json:"status"`
	Message string `json:"message,omitempty"`
}

func newDoctorCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "doctor",
		Short: "Run local srvgov diagnostics",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runDoctor(f)
		},
	}
}

func runDoctor(f *cliFlags) error {
	report := DoctorReport{Checks: make([]DoctorCheck, 0, 4)}
	cfg, configErr := srvgovctx.Load()
	report.Checks = append(report.Checks, doctorCheck("config", configErr, ""))

	current, currentErr := doctorCurrentContext(cfg, configErr, f.Context)
	report.Checks = append(report.Checks, doctorCheck("current-context", currentErr, ""))

	backendName := ""
	var credentialErr error
	if current != nil {
		backendName = current.CredentialBackend
		if backendName == "" {
			backendName = "plain-yaml"
		}
		var backend credstore.Backend
		backend, credentialErr = credstore.New(backendName)
		if credentialErr == nil {
			credentialErr = backend.Available()
		}
	} else if len(credstore.Available()) == 0 {
		credentialErr = apperrors.New(apperrors.CodeCredentialStoreMissing, "no credential backend is available", nil)
	}
	report.Checks = append(report.Checks, doctorCheck("credential-store", credentialErr, backendName))

	knownHostsPath, pathErr := sshexec.KnownHostsPath()
	exists := false
	knownHostsErr := pathErr
	if knownHostsErr == nil {
		exists, knownHostsErr = sshexec.CheckKnownHostsPermissions(knownHostsPath)
	}
	message := ""
	if knownHostsErr == nil && !exists {
		message = "not initialized"
	}
	report.Checks = append(report.Checks, doctorCheck("known-hosts", knownHostsErr, message))

	return printDoctorReport(f, report)
}

func doctorCurrentContext(cfg *srvgovctx.Config, configErr error, contextName string) (*srvgovctx.Context, error) {
	if configErr != nil {
		return nil, configErr
	}
	if contextName == "" {
		contextName = cfg.CurrentContext
	}
	if contextName == "" {
		return nil, apperrors.New(apperrors.CodeUsageError, "no current context set", nil)
	}
	item, ok := cfg.Contexts[contextName]
	if !ok {
		return nil, apperrors.New(apperrors.CodeResourceNotFound, fmt.Sprintf("context %q not found", contextName), nil)
	}
	if err := item.Normalize(); err != nil {
		return nil, err
	}
	return &item, nil
}

func doctorCheck(name string, err error, successMessage string) DoctorCheck {
	if err != nil {
		return DoctorCheck{Name: name, Status: "fail", Message: err.Error()}
	}
	return DoctorCheck{Name: name, Status: "ok", Message: successMessage}
}

func printDoctorReport(f *cliFlags, report DoctorReport) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("DoctorReport", report)
	}
	rows := make([][]string, 0, len(report.Checks))
	for _, check := range report.Checks {
		rows = append(rows, []string{check.Name, check.Status, check.Message})
	}
	return p.Table([]string{"CHECK", "STATUS", "MESSAGE"}, rows)
}
