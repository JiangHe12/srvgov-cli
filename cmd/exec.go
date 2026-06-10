package cmd

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
	"github.com/JiangHe12/srvgov-cli/internal/redact"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

const allowDestructive safety.AllowFlag = "allow-destructive"

type sshRunner interface {
	Run(context.Context, string, srvgovctx.Context, string) (sshexec.Result, error)
}

var newSSHRunner = func() sshRunner { return sshexec.Client{} }

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
	command := &cobra.Command{
		Use:   "exec <command>",
		Short: "Run one governed remote command",
		Args:  requireExactArgs("exec"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExec(cmd, f, args[0], reason, allow, dryRun)
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed change")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 command")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Classify and show required authorization without connecting")
	return command
}

func runExec(cmd *cobra.Command, f *cliFlags, command, reason string, allow, dryRun bool) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	baseRisk := cmdclass.Classify(command)
	meta := safety.ContextMeta{
		Name:          contextName,
		Env:           item.Env,
		Protected:     item.Protected,
		TicketPattern: item.TicketPattern,
		Roles:         item.Roles,
	}
	effectiveRisk := safety.EffectiveRisk(baseRisk, meta)
	if dryRun {
		return printExecDryRun(f, contextName, *item, command, baseRisk, effectiveRisk)
	}
	if effectiveRisk >= safety.R1 && strings.TrimSpace(reason) == "" {
		return apperrors.New(apperrors.CodeUsageError, "--reason is required for R1-R3 commands", nil)
	}

	requiredAllow := requiredAllowFlags(effectiveRisk)
	grantedAllow := map[safety.AllowFlag]bool{allowDestructive: allow}
	operator := resolveOperator(f.Operator)
	authErr := safety.Authorize(effectiveRisk, safety.Options{
		Yes:                f.Yes,
		NonInteractive:     f.NonInteractive,
		Ticket:             f.Ticket,
		TicketPattern:      item.TicketPattern,
		RequiredAllowFlags: requiredAllow,
		GrantedAllowFlags:  grantedAllow,
		Stdin:              cmd.InOrStdin(),
		Stdout:             cmd.OutOrStdout(),
		Roles:              item.Roles,
		Operator:           operator,
	})
	if authErr != nil {
		appendExecAudit(*item, contextName, operator, f.Ticket, reason, command, effectiveRisk, srvgovaudit.StatusDenied, 0, "", "", authErr, srvgovaudit.EventTypeAuthorizationDenied)
		return authErr
	}

	result, runErr := newSSHRunner().Run(cmd.Context(), contextName, *item, command)
	if runErr != nil {
		appendExecAudit(*item, contextName, operator, f.Ticket, reason, command, effectiveRisk, srvgovaudit.StatusFailed, 0, "", "", runErr, srvgovaudit.EventTypeExecRun)
		return runErr
	}
	view := execResultView{
		Context:  contextName,
		Host:     item.Address(),
		Command:  redact.String(command),
		RiskTier: riskName(effectiveRisk),
		Stdout:   redact.String(result.Stdout),
		Stderr:   redact.String(result.Stderr),
		ExitCode: result.ExitCode,
	}
	status := srvgovaudit.StatusSucceeded
	var resultErr error
	if result.ExitCode != 0 {
		status = srvgovaudit.StatusFailed
		resultErr = apperrors.New(
			apperrors.CodeBackendError,
			fmt.Sprintf("remote command exited with status %d", result.ExitCode),
			nil,
		)
	}
	appendExecAudit(*item, contextName, operator, f.Ticket, reason, command, effectiveRisk, status, result.ExitCode, result.Stdout, result.Stderr, resultErr, srvgovaudit.EventTypeExecRun)
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
