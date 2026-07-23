package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/redact"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
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
	tofuNoticeMu sync.Mutex

	newSSHRunner = func(onTOFU func(sshexec.Pin)) sshRunner {
		return sshexec.Client{OnTOFU: onTOFU}
	}
	newSSHStdinRunner = func(onTOFU func(sshexec.Pin)) sshStdinRunner {
		return sshexec.Client{OnTOFU: onTOFU}
	}
)

const maxDeferredTOFUNotices = 32

type deferredTOFUNotices struct {
	f    *cliFlags
	mu   sync.Mutex
	pins []sshexec.Pin
}

func newDeferredTOFUNotices(f *cliFlags) *deferredTOFUNotices {
	return &deferredTOFUNotices{
		f:    f,
		pins: make([]sshexec.Pin, 0, 1),
	}
}

func governedTOFUNotifier(
	f *cliFlags,
	mutation bool,
) (func(sshexec.Pin), *deferredTOFUNotices) {
	if mutation {
		return tofuNotice(f), nil
	}
	notices := newDeferredTOFUNotices(f)
	return notices.notify, notices
}

func (notices *deferredTOFUNotices) notify(pin sshexec.Pin) {
	if notices == nil {
		return
	}
	notices.mu.Lock()
	defer notices.mu.Unlock()
	if len(notices.pins) < maxDeferredTOFUNotices {
		notices.pins = append(notices.pins, pin)
	}
}

func (notices *deferredTOFUNotices) flush() {
	if notices == nil {
		return
	}
	notices.mu.Lock()
	pins := append([]sshexec.Pin(nil), notices.pins...)
	notices.pins = nil
	notices.mu.Unlock()
	notify := tofuNotice(notices.f)
	for _, pin := range pins {
		notify(pin)
	}
}

func tofuNotice(f *cliFlags) func(sshexec.Pin) {
	return func(pin sshexec.Pin) {
		writer := io.Writer(os.Stderr)
		if f != nil && f.Err != nil {
			writer = f.Err
		}
		tofuNoticeMu.Lock()
		defer tofuNoticeMu.Unlock()
		_, _ = fmt.Fprintf(
			writer,
			"notice: pinned SSH host key for %q (%s %s); future key changes will be rejected\n",
			pin.Address,
			pin.KeyType,
			pin.Fingerprint,
		)
	}
}

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

type governedFanoutPlan struct {
	Target        fanout.Target[srvgovctx.Context]
	Risk          governedRisk
	PolicyCommand string
}

type execFanoutPlan = governedFanoutPlan

func newExecCmd(f *cliFlags) *cobra.Command {
	var reason string
	var allow bool
	var dryRun bool
	flags := fanoutFlags{Concurrency: defaultFanoutConcurrency}
	command := &cobra.Command{
		Use:   "exec <command>",
		Short: "Run one governed remote command",
		Args:  requireExactArgs("exec"),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExec(cmd, f, args[0], reason, allow, dryRun, flags, fanoutRequested(cmd))
		},
	}
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed change")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 command")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Classify and show required authorization without connecting")
	bindFanoutFlags(command, &flags)
	return command
}

//nolint:gocyclo,nestif // Fanout authorization, audit, execution, and printing stay visibly ordered.
func runExec(
	cmd *cobra.Command,
	f *cliFlags,
	command, reason string,
	allow, dryRun bool,
	flags fanoutFlags,
	fanoutSet bool,
) error {
	if fanoutSet {
		targets, err := loadFanoutTargetsForCommand(cmd, flags)
		if err != nil {
			return err
		}
		plans, maxEffective := planExecFanout(targets, command)
		if dryRun {
			results := make([]fanout.Result, 0, len(plans))
			for _, plan := range plans {
				results = append(results, fanout.Result{
					Target: plan.Target.Name,
					Host:   plan.Target.Host,
					Data: execDryRunView{
						Context:               plan.Target.Name,
						Host:                  plan.Target.Host,
						Command:               redact.String(command),
						RiskTier:              riskName(plan.Risk.Base),
						EffectiveRiskTier:     riskName(plan.Risk.Effective),
						RequiredAuthorization: requiredAuthorization(plan.Risk.Effective),
						DryRun:                true,
					},
				})
			}
			view := buildFanoutView(targets, flags.Concurrency, results)
			view.MaxEffectiveRiskTier = riskName(maxEffective)
			return printFanout(cmd, f, view)
		}
		if err := authorizeExecFanout(cmd, f, plans, command, reason, allow, maxEffective); err != nil {
			return err
		}
		var batchAudit *mutationAuditHandle
		if fanoutPlansContainMutation(plans, srvgovaudit.EventTypeExecRun) {
			batchAudit, err = beginFanoutMutationAudit(
				f,
				targets,
				string(srvgovaudit.EventTypeExecRun),
				command,
				reason,
				maxEffective,
			)
			if err != nil {
				return err
			}
		}
		results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
			targetFlags := *f
			targetFlags.NonInteractive = true
			result, risk, resultErr := runGovernedCommand(
				cmd,
				&targetFlags,
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
		if err := finishFanoutMutationAudit(batchAudit, results); err != nil {
			return err
		}
		return printFanout(cmd, f, buildFanoutView(targets, flags.Concurrency, results))
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

func planExecFanout(targets []fanout.Target[srvgovctx.Context], command string) ([]execFanoutPlan, safety.Risk) {
	return planGovernedFanout(targets, command)
}

func planGovernedFanout(targets []fanout.Target[srvgovctx.Context], command string) ([]governedFanoutPlan, safety.Risk) {
	plans := make([]governedFanoutPlan, 0, len(targets))
	maxEffective := safety.R0
	for _, target := range targets {
		risk := classifyGovernedCommand(target.Value, target.Name, command)
		if risk.Effective > maxEffective {
			maxEffective = risk.Effective
		}
		plans = append(plans, governedFanoutPlan{Target: target, Risk: risk, PolicyCommand: command})
	}
	return plans, maxEffective
}

func fanoutPlansContainMutation(plans []governedFanoutPlan, eventType srvgovaudit.EventType) bool {
	for _, plan := range plans {
		if isRemoteMutation(eventType, plan.Risk.Base) {
			return true
		}
	}
	return false
}

func authorizeExecFanout(
	cmd *cobra.Command,
	f *cliFlags,
	plans []execFanoutPlan,
	command, reason string,
	allow bool,
	maxEffective safety.Risk,
) error {
	return authorizeGovernedFanout(cmd, f, plans, command, reason, allow, maxEffective)
}

func authorizeGovernedFanout(
	cmd *cobra.Command,
	f *cliFlags,
	plans []governedFanoutPlan,
	command, reason string,
	allow bool,
	maxEffective safety.Risk,
) error {
	operator, err := trustedOperator(f)
	if err != nil {
		return err
	}
	if maxEffective >= safety.R1 && strings.TrimSpace(reason) == "" {
		reasonErr := missingReasonError(maxEffective)
		for _, plan := range plans {
			if plan.Risk.Effective != maxEffective {
				continue
			}
			appendExecDeniedAudit(
				f,
				plan.Target.Value,
				plan.Target.Name,
				operator,
				f.Ticket,
				reason,
				planPolicyCommand(plan, command),
				plan.Risk.Effective,
				reasonErr,
			)
			break
		}
		return reasonErr
	}

	for _, plan := range plans {
		authErr := safety.Authorize(plan.Risk.Effective, safety.Options{
			Yes:                f.Yes,
			NonInteractive:     true,
			Ticket:             f.Ticket,
			TicketPattern:      plan.Target.Value.TicketPattern,
			RequiredAllowFlags: requiredAllowFlags(plan.Risk.Effective),
			GrantedAllowFlags:  map[safety.AllowFlag]bool{allowDestructive: allow},
			Stdin:              cmd.InOrStdin(),
			Stdout:             cmd.OutOrStdout(),
			Roles:              plan.Target.Value.Roles,
			Operator:           operator,
		})
		if authErr == nil {
			continue
		}
		appendExecDeniedAudit(
			f,
			plan.Target.Value,
			plan.Target.Name,
			operator,
			f.Ticket,
			reason,
			planPolicyCommand(plan, command),
			plan.Risk.Effective,
			authErr,
		)
		return apperrors.New(
			apperrors.CodeAuthorizationRequired,
			fmt.Sprintf(
				"target %q (%s) authorization denied: %s",
				redact.String(plan.Target.Name),
				riskName(plan.Risk.Effective),
				apperrors.AsAppError(authErr).Message,
			),
			authErr,
		)
	}
	return nil
}

func planPolicyCommand(plan governedFanoutPlan, fallback string) string {
	if plan.PolicyCommand != "" {
		return plan.PolicyCommand
	}
	return fallback
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
	return p.KV([][2]string{
		{"Context", view.Context},
		{"Host", view.Host},
		{"Command", view.Command},
		{"Risk Tier", view.RiskTier},
		{"Effective Risk Tier", view.EffectiveRiskTier},
		{"Required Authorization", strings.Join(view.RequiredAuthorization, ", ")},
		{"Dry Run", "true"},
	})
}

func printExecResult(f *cliFlags, view execResultView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ExecResult", view)
	}
	return p.KV([][2]string{
		{"Context", view.Context},
		{"Host", view.Host},
		{"Command", view.Command},
		{"Risk Tier", view.RiskTier},
		{"Exit Code", fmt.Sprintf("%d", view.ExitCode)},
		{"Stdout", view.Stdout},
		{"Stderr", view.Stderr},
	})
}

func appendExecDeniedAudit(
	f *cliFlags,
	item srvgovctx.Context,
	contextName, operator, ticket, reason, command string,
	risk safety.Risk,
	eventErr error,
) {
	path, err := coreaudit.DefaultPath()
	if err != nil {
		warnAuditFailure(f, err)
		return
	}
	var errorInfo *srvgovaudit.ErrorInfo
	if eventErr != nil {
		appErr := apperrors.AsAppError(eventErr)
		errorInfo = &srvgovaudit.ErrorInfo{Code: string(appErr.Code), Message: appErr.Message}
	}
	if err := appendQueuedAuditEvent(f, path, srvgovaudit.Event{
		EventType: srvgovaudit.EventTypeAuthorizationDenied,
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
		Status:   srvgovaudit.StatusDenied,
		Error:    errorInfo,
	}, coreaudit.Options{
		MaxSizeBytes:         item.AuditMaxSize,
		EncryptPublicKeyPath: item.AuditEncryptKey,
	}); err != nil {
		warnAuditFailure(f, err)
	}
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

func missingReasonError(risk safety.Risk) error {
	requirements := append([]string{"--reason"}, requiredAuthorization(risk)...)
	return apperrors.New(
		apperrors.CodeUsageError,
		fmt.Sprintf("%s authorization requires %s", riskName(risk), strings.Join(requirements, ", ")),
		nil,
	)
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
