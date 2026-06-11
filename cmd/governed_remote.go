package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type governedRisk struct {
	Base      safety.Risk
	Effective safety.Risk
}

func classifyGovernedCommand(item srvgovctx.Context, contextName, command string) governedRisk {
	base := cmdclass.Classify(command)
	return governedRisk{
		Base: base,
		Effective: safety.EffectiveRisk(base, safety.ContextMeta{
			Name:          contextName,
			Env:           item.Env,
			Protected:     item.Protected,
			TicketPattern: item.TicketPattern,
			Roles:         item.Roles,
		}),
	}
}

func runGovernedCommand(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName, command, reason string,
	allow bool,
	eventType srvgovaudit.EventType,
) (sshexec.Result, governedRisk, error) {
	risk := classifyGovernedCommand(item, contextName, command)
	if risk.Effective >= safety.R1 && strings.TrimSpace(reason) == "" {
		return sshexec.Result{}, risk, apperrors.New(apperrors.CodeUsageError, "--reason is required for R1-R3 commands", nil)
	}

	operator := resolveOperator(f.Operator)
	authErr := safety.Authorize(risk.Effective, safety.Options{
		Yes:                f.Yes,
		NonInteractive:     f.NonInteractive,
		Ticket:             f.Ticket,
		TicketPattern:      item.TicketPattern,
		RequiredAllowFlags: requiredAllowFlags(risk.Effective),
		GrantedAllowFlags:  map[safety.AllowFlag]bool{allowDestructive: allow},
		Stdin:              cmd.InOrStdin(),
		Stdout:             cmd.OutOrStdout(),
		Roles:              item.Roles,
		Operator:           operator,
	})
	if authErr != nil {
		appendExecAudit(item, contextName, operator, f.Ticket, reason, command, risk.Effective, srvgovaudit.StatusDenied, 0, "", "", authErr, srvgovaudit.EventTypeAuthorizationDenied)
		return sshexec.Result{}, risk, authErr
	}

	result, runErr := newSSHRunner().Run(cmd.Context(), contextName, item, command)
	if runErr != nil {
		appendExecAudit(item, contextName, operator, f.Ticket, reason, command, risk.Effective, srvgovaudit.StatusFailed, 0, "", "", runErr, eventType)
		return sshexec.Result{}, risk, runErr
	}

	if result.ExitCode != 0 {
		resultErr := apperrors.New(
			apperrors.CodeBackendError,
			fmt.Sprintf("remote command exited with status %d", result.ExitCode),
			nil,
		)
		appendExecAudit(item, contextName, operator, f.Ticket, reason, command, risk.Effective, srvgovaudit.StatusFailed, result.ExitCode, result.Stdout, result.Stderr, resultErr, eventType)
		return result, risk, resultErr
	}

	appendExecAudit(item, contextName, operator, f.Ticket, reason, command, risk.Effective, srvgovaudit.StatusSucceeded, result.ExitCode, result.Stdout, result.Stderr, nil, eventType)
	return result, risk, nil
}
