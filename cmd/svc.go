package cmd

import (
	"bufio"
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/redact"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
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
	var dryRun bool
	var fanoutFlags fanoutFlags
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
				if cmd.Flags().Changed("targets") {
					return runServiceFanout(cmd, f, fanoutFlags, action, args[1], "", false, dryRun)
				}
				if dryRun {
					return runServiceDryRun(cmd, f, serviceStatusCommand(args[1]))
				}
				return runServiceStatus(cmd, f, args[1])
			}
			if !serviceActions[action] {
				return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("unsupported svc action %q", args[0]), nil)
			}
			if cmd.Flags().Changed("targets") {
				return runServiceFanout(cmd, f, fanoutFlags, action, args[1], reason, allow, dryRun)
			}
			if dryRun {
				return runServiceDryRun(cmd, f, serviceActionCommand(action, args[1]))
			}
			return runServiceAction(cmd, f, action, args[1], reason, allow)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed service change")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 service change")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Classify and show required authorization without connecting")
	bindFanoutFlags(command, &fanoutFlags)
	return command
}

func runServiceDryRun(_ *cobra.Command, f *cliFlags, command string) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	risk := classifyGovernedCommand(*item, contextName, command)
	return printExecDryRun(f, contextName, *item, command, risk.Base, risk.Effective)
}

func runServiceFanout(
	cmd *cobra.Command,
	f *cliFlags,
	flags fanoutFlags,
	action, unit, reason string,
	allow, dryRun bool,
) error {
	targets, err := loadFanoutTargets(flags.Targets, cmd.Flags().Changed("context"), flags.Concurrency)
	if err != nil {
		return err
	}
	command := serviceActionCommand(action, unit)
	eventType := srvgovaudit.EventTypeSvcAction
	if action == "status" {
		command = serviceStatusCommand(unit)
		eventType = srvgovaudit.EventTypeSvcStatus
	}
	plans, maxEffective := planGovernedFanout(targets, command)
	if dryRun {
		return printFanoutDryRun(cmd, f, targets, flags.Concurrency, plans, command, maxEffective)
	}
	if err := authorizeGovernedFanout(cmd, f, plans, command, reason, allow, maxEffective); err != nil {
		return err
	}
	results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
		targetFlags := *f
		targetFlags.NonInteractive = true
		if action == "status" {
			return runServiceStatusTarget(cmd, &targetFlags, target.Value, target.Name, unit)
		}
		return runServiceActionTarget(cmd, &targetFlags, target.Value, target.Name, action, unit, reason, allow, eventType)
	})
	return printFanout(cmd, f, buildFanoutView(targets, flags.Concurrency, results))
}

func runServiceStatus(cmd *cobra.Command, f *cliFlags, unit string) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	value, err := runServiceStatusTarget(cmd, f, *item, contextName, unit)
	if err != nil {
		return err
	}
	return printServiceStatus(f, value)
}

func runServiceStatusTarget(cmd *cobra.Command, f *cliFlags, item srvgovctx.Context, contextName, unit string) (serviceStatusView, error) {
	command := serviceStatusCommand(unit)
	result, _, err := runGovernedCommand(cmd, f, item, contextName, command, "", false, srvgovaudit.EventTypeSvcStatus)
	if err != nil {
		return serviceStatusView{}, err
	}
	return parseServiceStatus(unit, result.Stdout), nil
}

func runServiceAction(cmd *cobra.Command, f *cliFlags, action, unit, reason string, allow bool) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	view, runErr := runServiceActionTarget(cmd, f, *item, contextName, action, unit, reason, allow, srvgovaudit.EventTypeSvcAction)
	if runErr != nil && view.ExitCode == 0 {
		return runErr
	}
	if err := printServiceAction(f, view); err != nil {
		return err
	}
	return runErr
}

func runServiceActionTarget(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName, action, unit, reason string,
	allow bool,
	eventType srvgovaudit.EventType,
) (serviceActionView, error) {
	command := serviceActionCommand(action, unit)
	result, _, runErr := runGovernedCommand(cmd, f, item, contextName, command, reason, allow, eventType)
	if runErr != nil && result.ExitCode == 0 {
		return serviceActionView{}, runErr
	}
	message := strings.TrimSpace(result.Stdout)
	if message == "" {
		message = strings.TrimSpace(result.Stderr)
	}
	return serviceActionView{
		Unit:     redact.String(unit),
		Action:   action,
		Success:  runErr == nil,
		ExitCode: result.ExitCode,
		Message:  redact.String(message),
	}, runErr
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
