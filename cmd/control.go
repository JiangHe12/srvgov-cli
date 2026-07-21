package cmd

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

const (
	allowContextChange safety.AllowFlag = "allow-context-change"
	allowContextDelete safety.AllowFlag = "allow-context-delete"
	allowRoleChange    safety.AllowFlag = "allow-role-change"
	allowAuditPrune    safety.AllowFlag = "allow-audit-prune"
)

func contextPreChangePolicy(cfg *srvgovctx.Config, targetName string) (srvgovctx.Context, error) {
	if item, ok := cfg.Contexts[targetName]; ok {
		return item, nil
	}
	if cfg.CurrentContext == "" {
		return srvgovctx.Context{}, nil
	}
	item, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok {
		return srvgovctx.Context{}, apperrors.New(
			apperrors.CodeValidationFailed,
			fmt.Sprintf("current context %q does not exist; refusing bootstrap authorization", cfg.CurrentContext),
			nil,
		)
	}
	return item, nil
}

func contextUsePreChangePolicy(
	cfg *srvgovctx.Config,
	target srvgovctx.Context,
) (srvgovctx.Context, error) {
	if cfg.CurrentContext == "" {
		return target, nil
	}
	item, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok {
		return srvgovctx.Context{}, apperrors.New(
			apperrors.CodeValidationFailed,
			fmt.Sprintf("current context %q does not exist; refusing context switch", cfg.CurrentContext),
			nil,
		)
	}
	return item, nil
}

func authorizeControlChange(
	cmd *cobra.Command,
	f *cliFlags,
	policy srvgovctx.Context,
	targetName, action string,
	required safety.AllowFlag,
	granted bool,
) error {
	return authorizeControlChangeWithConfirmation(
		cmd,
		f,
		policy,
		targetName,
		action,
		required,
		granted,
		f.Yes,
	)
}

func authorizeControlChangeWithConfirmation(
	cmd *cobra.Command,
	f *cliFlags,
	policy srvgovctx.Context,
	targetName, action string,
	required safety.AllowFlag,
	granted bool,
	confirmed bool,
) error {
	operator, err := trustedOperator(f)
	if err != nil {
		return err
	}
	for roleOperator, role := range policy.Roles {
		if validRole(role) {
			continue
		}
		roleErr := apperrors.New(
			apperrors.CodeAuthorizationRequired,
			fmt.Sprintf("context policy contains invalid role %q for operator %q", role, roleOperator),
			nil,
		)
		emitControlAuthorizationDenied(f, controlAuthorizationEvent(f, policy, targetName, action), roleErr)
		return roleErr
	}
	authErr := safety.Authorize(safety.R3, safety.Options{
		Yes:                confirmed,
		NonInteractive:     f.NonInteractive,
		Ticket:             f.Ticket,
		TicketPattern:      policy.TicketPattern,
		RequiredAllowFlags: []safety.AllowFlag{required},
		GrantedAllowFlags:  map[safety.AllowFlag]bool{required: granted},
		Stdin:              cmd.InOrStdin(),
		Stdout:             cmd.OutOrStdout(),
		Roles:              policy.Roles,
		Operator:           operator,
	})
	if authErr != nil {
		emitControlAuthorizationDenied(f, controlAuthorizationEvent(f, policy, targetName, action), authErr)
	}
	return authErr
}

func validateRequestedRoles(roles map[string]string) error {
	for operator, role := range roles {
		if strings.TrimSpace(operator) == "" {
			return apperrors.New(apperrors.CodeUsageError, "context role operator must not be empty", nil)
		}
		if !validRole(role) {
			return apperrors.New(
				apperrors.CodeUsageError,
				fmt.Sprintf("context role for operator %q must be reader, writer, or admin", operator),
				nil,
			)
		}
	}
	return nil
}

func beginControlMutationAudit(
	f *cliFlags,
	action, contextName, target string,
	eventContext, auditPolicy srvgovctx.Context,
) (*mutationAuditHandle, error) {
	return beginMutationAudit(f, mutationAuditSpec{
		Action:      action,
		ContextName: contextName,
		Context:     eventContext,
		Target:      target,
		RiskTier:    "R3",
		Ticket:      f.Ticket,
		Options:     coreAuditOptions(auditPolicy),
	})
}

func coreAuditOptions(policy srvgovctx.Context) coreaudit.Options {
	return coreaudit.Options{
		MaxSizeBytes:         policy.AuditMaxSize,
		EncryptPublicKeyPath: policy.AuditEncryptKey,
	}
}

func finishControlMutationAudit(handle *mutationAuditHandle, operationErr error) error {
	if handle == nil {
		return operationErr
	}
	outcome := mutationAuditOutcome{}
	if operationErr == nil {
		outcome.Status = srvgovaudit.StatusSucceeded
		outcome.Succeeded = 1
	} else {
		outcome.Status = srvgovaudit.StatusFailed
		outcome.Failed = 1
	}
	return finishMutationAudit(handle, outcome, operationErr)
}

func finishUncertainControlMutationAudit(handle *mutationAuditHandle, operationErr error) error {
	if handle == nil {
		return operationErr
	}
	return finishMutationAudit(handle, mutationAuditOutcome{
		Status:    srvgovaudit.StatusFailed,
		Uncertain: 1,
	}, operationErr)
}

func emitControlAuthorizationDenied(f *cliFlags, event srvgovaudit.Event, eventErr error) {
	appErr := apperrors.AsAppError(eventErr)
	event.Error = &srvgovaudit.ErrorInfo{Code: string(appErr.Code), Message: appErr.Message}
	emitAudit(f, event, nil)
}

func controlAuthorizationEvent(
	f *cliFlags,
	policy srvgovctx.Context,
	targetName, action string,
) srvgovaudit.Event {
	return srvgovaudit.Event{
		EventType: srvgovaudit.EventTypeAuthorizationDenied,
		Operator:  currentOperator(f),
		Context: srvgovaudit.Context{
			Name:      targetName,
			Env:       policy.Env,
			Protected: policy.Protected,
		},
		Ticket:   f.Ticket,
		Target:   srvgovaudit.Target{Host: targetName},
		Command:  action,
		RiskTier: "R3",
		Status:   srvgovaudit.StatusDenied,
	}
}
