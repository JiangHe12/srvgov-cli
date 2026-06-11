package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
	"github.com/JiangHe12/srvgov-cli/internal/redact"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

const allowDestructive safety.AllowFlag = "allow-destructive"

type sshRunner interface {
	Run(context.Context, string, srvgovctx.Context, string) (sshexec.Result, error)
}

type sshStdinRunner interface {
	RunWithStdin(context.Context, string, srvgovctx.Context, string, io.Reader) (sshexec.Result, error)
}

var (
	newSSHRunner      = func() sshRunner { return sshexec.Client{} }
	newSSHStdinRunner = func() sshStdinRunner { return sshexec.Client{} }
)

type execDryRunView struct {
	Context               string   `json:"context"`
	Host                  string   `json:"host"`
	Command               string   `json:"command"`
	RiskTier              string   `json:"riskTier"`
	EffectiveRiskTier     string   `json:"effectiveRiskTier"`
	RequiredAuthorization []string `json:"requiredAuthorization"`
	DryRun                bool     `json:"dryRun"`
}

type execResultView struct {
	Context  string `json:"context"`
	Host     string `json:"host"`
	Command  string `json:"command"`
	RiskTier string `json:"riskTier"`
	Stdout   string `json:"stdout"`
	Stderr   string `json:"stderr"`
	ExitCode int    `json:"exitCode"`
}

func newExecCmd(f *cliFlags) *cobra.Command {
	var reason string
	var allow bool
	var dryRun bool
	var targets string
	var concurrency int
	command := &cobra.Command{
		Use:   "exec <command>",
		Short: "Run one governed remote command",
		Args:  requireExactArgs("exec"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExec(cmd, f, args[0], reason, allow, dryRun, targets, concurrency, cmd.Flags().Changed("targets"))
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed change")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 command")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Classify and show required authorization without connecting")
	command.Flags().StringVar(&targets, "targets", "", "Comma-separated server context names")
	command.Flags().IntVar(&concurrency, "concurrency", defaultFanoutConcurrency, "Maximum concurrent targets")
	return command
}

func runExec(
	cmd *cobra.Command,
	f *cliFlags,
	command, reason string,
	allow, dryRun bool,
	rawTargets string,
	concurrency int,
	targetsSet bool,
) error {
	if targetsSet {
		targets, err := loadFanoutTargets(rawTargets, cmd.Flags().Changed("context"), concurrency)
		if err != nil {
			return err
		}
		if err := requireFanoutR0(targets, []string{command}); err != nil {
			return err
		}
		if dryRun {
			results := make([]fanout.Result, 0, len(targets))
			for _, target := range targets {
				risk := classifyGovernedCommand(target.Value, target.Name, command)
				results = append(results, fanout.Result{
					Target: target.Name,
					Host:   target.Host,
					Data: execDryRunView{
						Context:               target.Name,
						Host:                  target.Host,
						Command:               redact.String(command),
						RiskTier:              riskName(risk.Base),
						EffectiveRiskTier:     riskName(risk.Effective),
						RequiredAuthorization: requiredAuthorization(risk.Effective),
						DryRun:                true,
					},
				})
			}
			return printFanout(cmd, f, buildFanoutView(targets, concurrency, results))
		}
		results := fanout.Run(cmd.Context(), targets, concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
			result, risk, resultErr := runGovernedCommand(
				cmd,
				f,
				target.Value,
				target.Name,
				command,
				reason,
				allow,
				srvgovaudit.EventTypeExecRun,
			)
			if resultErr != nil {
				return nil, resultErr
			}
			return execResultView{
				Context:  target.Name,
				Host:     target.Host,
				Command:  redact.String(command),
				RiskTier: riskName(risk.Effective),
				Stdout:   redact.String(result.Stdout),
				Stderr:   redact.String(result.Stderr),
				ExitCode: result.ExitCode,
			}, nil
		})
		return printFanout(cmd, f, buildFanoutView(targets, concurrency, results))
	}
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	risk := classifyGovernedCommand(*item, contextName, command)
	if dryRun {
		return printExecDryRun(f, contextName, *item, command, risk.Base, risk.Effective)
	}

	result, risk, resultErr := runGovernedCommand(cmd, f, *item, contextName, command, reason, allow, srvgovaudit.EventTypeExecRun)
	view := execResultView{
		Context:  contextName,
		Host:     item.Address(),
		Command:  redact.String(command),
		RiskTier: riskName(risk.Effective),
		Stdout:   redact.String(result.Stdout),
		Stderr:   redact.String(result.Stderr),
		ExitCode: result.ExitCode,
	}
	if resultErr != nil && result.ExitCode == 0 {
		return resultErr
	}
	if err := printExecResult(f, view); err != nil {
		return err
	}
	if resultErr != nil {
		return resultErr
	}
	return nil
}

func loadSelectedContext(name string) (*srvgovctx.Context, string, error) {
	cfg, err := srvgovctx.Load()
	if err != nil {
		return nil, "", err
	}
	if name == "" {
		name = cfg.CurrentContext
	}
	if name == "" {
		return nil, "", apperrors.New(apperrors.CodeUsageError, "no current context set; use --context or srvgov ctx use", nil)
	}
	item, ok := cfg.Contexts[name]
	if !ok {
		return nil, "", apperrors.New(apperrors.CodeResourceNotFound, fmt.Sprintf("context %q not found", name), nil)
	}
	if err := item.Normalize(); err != nil {
		return nil, "", err
	}
	return &item, name, nil
}

func printExecDryRun(f *cliFlags, contextName string, item srvgovctx.Context, command string, base, effective safety.Risk) error {
	view := execDryRunView{
		Context:               contextName,
		Host:                  item.Address(),
		Command:               redact.String(command),
		RiskTier:              riskName(base),
		EffectiveRiskTier:     riskName(effective),
		RequiredAuthorization: requiredAuthorization(effective),
		DryRun:                true,
	}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ExecDryRun", view)
	}
	p.KV([][2]string{
		{"Context", view.Context},
		{"Host", view.Host},
		{"Command", view.Command},
		{"Risk Tier", view.RiskTier},
		{"Effective Risk Tier", view.EffectiveRiskTier},
		{"Required Authorization", strings.Join(view.RequiredAuthorization, ", ")},
		{"Dry Run", "true"},
	})
	return nil
}

func printExecResult(f *cliFlags, view execResultView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ExecResult", view)
	}
	p.KV([][2]string{
		{"Context", view.Context},
		{"Host", view.Host},
		{"Command", view.Command},
		{"Risk Tier", view.RiskTier},
		{"Exit Code", fmt.Sprintf("%d", view.ExitCode)},
		{"Stdout", view.Stdout},
		{"Stderr", view.Stderr},
	})
	return nil
}

func appendExecAudit(
	item srvgovctx.Context,
	contextName, operator, ticket, reason, command string,
	risk safety.Risk,
	status string,
	exitCode int,
	stdout, stderr string,
	eventErr error,
	eventType srvgovaudit.EventType,
) {
	path, err := coreaudit.DefaultPath()
	if err != nil {
		return
	}
	var errorInfo *srvgovaudit.ErrorInfo
	if eventErr != nil {
		appErr := apperrors.AsAppError(eventErr)
		errorInfo = &srvgovaudit.ErrorInfo{Code: string(appErr.Code), Message: appErr.Message}
	}
	_ = srvgovaudit.Append(path, srvgovaudit.Event{
		EventType: eventType,
		Operator:  operator,
		Context: srvgovaudit.Context{
			Name:      contextName,
			Env:       item.Env,
			Protected: item.Protected,
		},
		Ticket:   ticket,
		Reason:   reason,
		Target:   srvgovaudit.Target{Host: item.Address()},
		Command:  command,
		RiskTier: riskName(risk),
		Status:   status,
		Stdout:   stdout,
		Stderr:   stderr,
		ExitCode: exitCode,
		Error:    errorInfo,
	}, coreaudit.Options{
		MaxSizeBytes:         item.AuditMaxSize,
		EncryptPublicKeyPath: item.AuditEncryptKey,
	})
}

func appendFileWriteAudit(
	item srvgovctx.Context,
	contextName, operator, ticket, reason, command string,
	risk safety.Risk,
	status string,
	exitCode int,
	stderr string,
	eventErr error,
	fileInfo *srvgovaudit.FileInfo,
) {
	path, err := coreaudit.DefaultPath()
	if err != nil {
		return
	}
	var errorInfo *srvgovaudit.ErrorInfo
	if eventErr != nil {
		appErr := apperrors.AsAppError(eventErr)
		errorInfo = &srvgovaudit.ErrorInfo{Code: string(appErr.Code), Message: appErr.Message}
	}
	_ = srvgovaudit.Append(path, srvgovaudit.Event{
		EventType: srvgovaudit.EventTypeFileWrite,
		Operator:  operator,
		Context: srvgovaudit.Context{
			Name:      contextName,
			Env:       item.Env,
			Protected: item.Protected,
		},
		Ticket:   ticket,
		Reason:   reason,
		Target:   srvgovaudit.Target{Host: item.Address()},
		Command:  command,
		RiskTier: riskName(risk),
		Status:   status,
		Stderr:   stderr,
		ExitCode: exitCode,
		Error:    errorInfo,
		File:     fileInfo,
	}, coreaudit.Options{
		MaxSizeBytes:         item.AuditMaxSize,
		EncryptPublicKeyPath: item.AuditEncryptKey,
	})
}

func requiredAllowFlags(risk safety.Risk) []safety.AllowFlag {
	if risk == safety.R3 {
		return []safety.AllowFlag{allowDestructive}
	}
	return nil
}

func requiredAuthorization(risk safety.Risk) []string {
	switch risk {
	case safety.R0:
		return []string{}
	case safety.R1:
		return []string{"--yes"}
	case safety.R2:
		return []string{"--yes", "--ticket"}
	case safety.R3:
		return []string{"--yes", "--ticket", "--allow-destructive"}
	default:
		return []string{"--yes", "--ticket", "--allow-destructive"}
	}
}

func riskName(risk safety.Risk) string {
	switch risk {
	case safety.R0:
		return "R0"
	case safety.R1:
		return "R1"
	case safety.R2:
		return "R2"
	case safety.R3:
		return "R3"
	default:
		return "R3"
	}
}

func resolveOperator(flagValue string) string {
	if value := strings.TrimSpace(flagValue); value != "" {
		return value
	}
	if value := strings.TrimSpace(os.Getenv("SRVGOV_OPERATOR")); value != "" {
		return value
	}
	return "unknown"
}
