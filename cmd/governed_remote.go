package cmd

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/cmdclass"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type governedRisk struct {
	Base      safety.Risk
	Effective safety.Risk
}

func runGovernedCommandWithStdin(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName, policyCommand, reason string,
	allow bool,
	prepareStdin func() (io.Reader, string, error),
	fileInfo func() *srvgovaudit.FileInfo,
	validate func() error,
) (sshexec.Result, error) {
	risk := classifyGovernedCommand(item, contextName, policyCommand)
	operator, err := trustedOperator(f)
	if err != nil {
		return sshexec.Result{}, err
	}
	if risk.Effective >= safety.R1 && strings.TrimSpace(reason) == "" {
		reasonErr := missingReasonError(risk.Effective)
		appendExecDeniedAudit(f, item, contextName, operator, f.Ticket, reason, policyCommand, risk.Effective, reasonErr)
		return sshexec.Result{}, reasonErr
	}

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
		appendExecDeniedAudit(f, item, contextName, operator, f.Ticket, reason, policyCommand, risk.Effective, authErr)
		return sshexec.Result{}, authErr
	}

	stdin, command, err := prepareStdin()
	if err != nil {
		return sshexec.Result{}, err
	}
	auditHandle, err := beginRemoteMutationAudit(
		f,
		item,
		contextName,
		command,
		reason,
		risk.Effective,
		srvgovaudit.EventTypeFileWrite,
	)
	if err != nil {
		return sshexec.Result{}, err
	}
	result, runErr := newSSHStdinRunner(tofuNotice(f)).RunWithStdin(cmd.Context(), contextName, item, command, stdin)
	if runErr != nil {
		uncertainErr := uncertainRemoteMutationError(runErr)
		return sshexec.Result{}, finishRemoteMutationAudit(auditHandle, fileInfo(), uncertainErr, true, false)
	}
	if validate != nil {
		if validationErr := validate(); validationErr != nil {
			return result, finishRemoteMutationAudit(
				auditHandle,
				fileInfo(),
				validationErr,
				false,
				sshOutputIncomplete(result),
			)
		}
	}
	if result.ExitCode != 0 {
		resultErr := remoteExitError(result)
		uncertain := false
		if !atomicFileWriteExitIsDefiniteFailure(result.ExitCode) {
			resultErr = uncertainAtomicFileWriteError(result)
			uncertain = true
		}
		return result, finishRemoteMutationAudit(
			auditHandle,
			fileInfo(),
			resultErr,
			uncertain,
			sshOutputIncomplete(result),
		)
	}

	if finishErr := finishRemoteMutationAudit(
		auditHandle,
		fileInfo(),
		nil,
		false,
		sshOutputIncomplete(result),
	); finishErr != nil {
		return result, finishErr
	}
	return result, sshOutputLimitError(result, true)
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
	operator, err := trustedOperator(f)
	if err != nil {
		return sshexec.Result{}, risk, err
	}
	if risk.Effective >= safety.R1 && strings.TrimSpace(reason) == "" {
		reasonErr := missingReasonError(risk.Effective)
		appendExecDeniedAudit(f, item, contextName, operator, f.Ticket, reason, command, risk.Effective, reasonErr)
		return sshexec.Result{}, risk, reasonErr
	}

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
		appendExecDeniedAudit(f, item, contextName, operator, f.Ticket, reason, command, risk.Effective, authErr)
		return sshexec.Result{}, risk, authErr
	}

	mutation := isRemoteMutation(eventType, risk.Base)
	var auditHandle *mutationAuditHandle
	var readAuditHandle *requiredReadAuditHandle
	if mutation {
		auditHandle, err = beginRemoteMutationAudit(
			f,
			item,
			contextName,
			command,
			reason,
			risk.Effective,
			eventType,
		)
		if err != nil {
			return sshexec.Result{}, risk, err
		}
	} else {
		readAuditHandle, err = beginRequiredReadAudit(
			f,
			item,
			contextName,
			operator,
			command,
			risk.Effective,
			eventType,
		)
		if err != nil {
			return sshexec.Result{}, risk, err
		}
	}
	notifyTOFU, deferredNotices := governedTOFUNotifier(f, mutation)
	result, runErr := newSSHRunner(notifyTOFU).Run(cmd.Context(), contextName, item, command)
	if runErr != nil {
		if mutation {
			uncertainErr := uncertainRemoteMutationError(runErr)
			return sshexec.Result{}, risk, finishRemoteMutationAudit(auditHandle, nil, uncertainErr, true, false)
		}
		finishErr := finishRequiredReadAudit(
			readAuditHandle,
			sshexec.Result{},
			srvgovaudit.StatusFailed,
			runErr,
		)
		releaseDeferredTOFUNotices(deferredNotices)
		return governedReadResult(sshexec.Result{}, risk, finishErr)
	}

	if result.ExitCode != 0 {
		resultErr := remoteExitError(result)
		if mutation {
			return result, risk, finishRemoteMutationAudit(
				auditHandle,
				nil,
				resultErr,
				false,
				sshOutputIncomplete(result),
			)
		}
		finishErr := finishRequiredReadAudit(
			readAuditHandle,
			result,
			srvgovaudit.StatusFailed,
			resultErr,
		)
		releaseDeferredTOFUNotices(deferredNotices)
		return governedReadResult(result, risk, finishErr)
	}

	outputErr := sshOutputLimitError(result, mutation)
	if mutation {
		if finishErr := finishRemoteMutationAudit(
			auditHandle,
			nil,
			nil,
			false,
			sshOutputIncomplete(result),
		); finishErr != nil {
			return result, risk, finishErr
		}
		return result, risk, outputErr
	}
	if finishErr := finishRequiredReadAudit(
		readAuditHandle,
		result,
		srvgovaudit.StatusSucceeded,
		nil,
	); finishErr != nil {
		releaseDeferredTOFUNotices(deferredNotices)
		return governedReadResult(result, risk, finishErr)
	}
	deferredNotices.flush()
	return result, risk, outputErr
}

func releaseDeferredTOFUNotices(notices *deferredTOFUNotices) {
	if notices != nil {
		notices.flush()
	}
}

func governedReadResult(
	result sshexec.Result,
	risk governedRisk,
	err error,
) (sshexec.Result, governedRisk, error) {
	if errors.Is(err, errRequiredReadAudit) {
		result = sshexec.Result{}
	}
	return result, risk, err
}

func sshOutputLimitError(result sshexec.Result, mutation bool) error {
	streams := truncatedSSHStreams(result)
	if len(streams) == 0 {
		return nil
	}
	err := apperrors.New(
		apperrors.CodePartialFailure,
		"remote command completed successfully but "+strings.Join(streams, " and ")+" exceeded the SSH per-stream capture limit",
		nil,
	)
	if mutation {
		return markRemoteMutationResult(
			err.WithSuggestion("the mutation already ran; verify target state before any retry"),
			remoteMutationResultOutputIncomplete,
		)
	}
	return err.WithSuggestion("narrow the command output and retry")
}

func remoteExitError(result sshexec.Result) error {
	message := fmt.Sprintf("remote command exited with status %d", result.ExitCode)
	if streams := truncatedSSHStreams(result); len(streams) > 0 {
		message += "; captured " + strings.Join(streams, " and ") + " was truncated"
	}
	return apperrors.New(apperrors.CodeBackendError, message, nil)
}

func uncertainAtomicFileWriteError(result sshexec.Result) error {
	return markRemoteMutationResult(
		apperrors.New(
			apperrors.CodePartialFailure,
			fmt.Sprintf(
				"remote file write exited with status %d during the atomic commit window; the target state is uncertain",
				result.ExitCode,
			),
			nil,
		).WithSuggestion("verify the target file and mutation ID before any retry"),
		remoteMutationResultUncertain,
	)
}

func truncatedSSHStreams(result sshexec.Result) []string {
	var streams []string
	if result.StdoutTruncated {
		streams = append(streams, "stdout")
	}
	if result.StderrTruncated {
		streams = append(streams, "stderr")
	}
	return streams
}

func sshOutputIncomplete(result sshexec.Result) bool {
	return result.StdoutTruncated || result.StderrTruncated
}

func uncertainRemoteMutationError(cause error) error {
	return markRemoteMutationResult(
		apperrors.New(
			apperrors.CodePartialFailure,
			"SSH failed after the remote mutation was authorized; the target state is uncertain",
			cause,
		).WithSuggestion("verify the target state and mutation ID before any retry"),
		remoteMutationResultUncertain,
	)
}

func isRemoteMutation(eventType srvgovaudit.EventType, baseRisk safety.Risk) bool {
	switch eventType { //nolint:exhaustive // Only remote mutation events and mutating exec need matching here.
	case srvgovaudit.EventTypeFileWrite,
		srvgovaudit.EventTypeSvcAction,
		srvgovaudit.EventTypeDockerAction:
		return true
	case srvgovaudit.EventTypeExecRun:
		return baseRisk >= safety.R1
	default:
		return false
	}
}

func beginRemoteMutationAudit(
	f *cliFlags,
	item srvgovctx.Context,
	contextName, command, reason string,
	risk safety.Risk,
	eventType srvgovaudit.EventType,
) (*mutationAuditHandle, error) {
	return beginMutationAudit(f, mutationAuditSpec{
		Action:      string(eventType),
		ContextName: contextName,
		Context:     item,
		Target:      item.Address(),
		RiskTier:    riskName(risk),
		Ticket:      f.Ticket,
		Reason:      reason,
		Metadata:    mutationPayloadMetadata(string(eventType), []byte(command)),
		Options: coreaudit.Options{
			MaxSizeBytes:         item.AuditMaxSize,
			EncryptPublicKeyPath: item.AuditEncryptKey,
		},
	})
}

func finishRemoteMutationAudit(
	handle *mutationAuditHandle,
	fileInfo *srvgovaudit.FileInfo,
	operationErr error,
	uncertain bool,
	outputIncomplete bool,
) error {
	outcome := mutationAuditOutcome{OutputIncomplete: outputIncomplete}
	switch {
	case operationErr == nil:
		outcome.Status = srvgovaudit.StatusSucceeded
		outcome.Succeeded = 1
	case uncertain:
		outcome.Status = srvgovaudit.StatusFailed
		outcome.Uncertain = 1
	default:
		outcome.Status = srvgovaudit.StatusFailed
		outcome.Failed = 1
	}
	if fileInfo != nil {
		outcome.PayloadFingerprint = fileInfo.SHA256
		if outcome.PayloadFingerprint != "" && !strings.HasPrefix(outcome.PayloadFingerprint, "sha256:") {
			outcome.PayloadFingerprint = "sha256:" + outcome.PayloadFingerprint
		}
		outcome.PayloadBytes = fileInfo.BytesWritten
	}
	return finishMutationAudit(handle, outcome, operationErr)
}
