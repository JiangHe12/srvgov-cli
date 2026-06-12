package cmd

import (
	"bufio"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/redact"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
)

var serviceActions = map[string]bool{
	"start":   true,
	"stop":    true,
	"restart": true,
	"reload":  true,
	"enable":  true,
	"disable": true,
}

type serviceStatusView struct {
	Unit          string `json:"unit"`
	LoadState     string `json:"loadState"`
	ActiveState   string `json:"activeState"`
	SubState      string `json:"subState"`
	UnitFileState string `json:"unitFileState"`
	Description   string `json:"description"`
	MainPID       int    `json:"mainPID,omitempty"`
}

type serviceActionView struct {
	Unit     string `json:"unit"`
	Action   string `json:"action"`
	Success  bool   `json:"success"`
	ExitCode int    `json:"exitCode"`
	Message  string `json:"message,omitempty"`
}

func newSvcCmd(f *cliFlags) *cobra.Command {
	var reason string
	var allow bool
	command := &cobra.Command{
		Use:   "svc <action> <unit>",
		Short: "Inspect or control one systemd service",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return apperrors.New(apperrors.CodeUsageError, "svc requires an action and one unit", nil)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			action := strings.ToLower(args[0])
			if action == "status" {
				return runServiceStatus(cmd, f, args[1])
			}
			if !serviceActions[action] {
				return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("unsupported svc action %q", args[0]), nil)
			}
			return runServiceAction(cmd, f, action, args[1], reason, allow)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed service change")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 service change")
	return command
}

func runServiceStatus(cmd *cobra.Command, f *cliFlags, unit string) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	command := serviceStatusCommand(unit)
	result, _, err := runGovernedCommand(cmd, f, *item, contextName, command, "", false, srvgovaudit.EventTypeSvcStatus)
	if err != nil {
		return err
	}
	return printServiceStatus(f, parseServiceStatus(unit, result.Stdout))
}

func runServiceAction(cmd *cobra.Command, f *cliFlags, action, unit, reason string, allow bool) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	command := serviceActionCommand(action, unit)
	result, _, runErr := runGovernedCommand(cmd, f, *item, contextName, command, reason, allow, srvgovaudit.EventTypeSvcAction)
	if runErr != nil && result.ExitCode == 0 {
		return runErr
	}
	message := strings.TrimSpace(result.Stdout)
	if message == "" {
		message = strings.TrimSpace(result.Stderr)
	}
	view := serviceActionView{
		Unit:     redact.String(unit),
		Action:   action,
		Success:  runErr == nil,
		ExitCode: result.ExitCode,
		Message:  redact.String(message),
	}
	if err := printServiceAction(f, view); err != nil {
		return err
	}
	return runErr
}

func serviceStatusCommand(unit string) string {
	return "systemctl show " + observe.ShellQuote(unit) +
		" --property=LoadState,ActiveState,SubState,UnitFileState,Description,MainPID --no-pager"
}

func serviceActionCommand(action, unit string) string {
	return "systemctl " + action + " " + observe.ShellQuote(unit)
}

func parseServiceStatus(unit, output string) serviceStatusView {
	view := serviceStatusView{Unit: redact.String(unit)}
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		key, value, ok := strings.Cut(scanner.Text(), "=")
		if !ok {
			continue
		}
		value = redact.String(value)
		switch key {
		case "LoadState":
			view.LoadState = value
		case "ActiveState":
			view.ActiveState = value
		case "SubState":
			view.SubState = value
		case "UnitFileState":
			view.UnitFileState = value
		case "Description":
			view.Description = value
		case "MainPID":
			view.MainPID, _ = strconv.Atoi(value)
		}
	}
	return view
}

func printServiceStatus(f *cliFlags, value serviceStatusView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ServiceStatus", value)
	}
	p.KV([][2]string{
		{"Unit", value.Unit},
		{"Load State", value.LoadState},
		{"Active State", value.ActiveState},
		{"Sub State", value.SubState},
		{"Unit File State", value.UnitFileState},
		{"Description", value.Description},
		{"Main PID", strconv.Itoa(value.MainPID)},
	})
	return nil
}

func printServiceAction(f *cliFlags, value serviceActionView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ServiceAction", value)
	}
	p.KV([][2]string{
		{"Unit", value.Unit},
		{"Action", value.Action},
		{"Success", strconv.FormatBool(value.Success)},
		{"Exit Code", strconv.Itoa(value.ExitCode)},
		{"Message", value.Message},
	})
	return nil
}
