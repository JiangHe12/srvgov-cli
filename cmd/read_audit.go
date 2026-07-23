package cmd

import (
	"errors"
	"fmt"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

const (
	readAuditPhaseIntent  = "intent"
	readAuditPhaseOutcome = "outcome"
)

var errRequiredReadAudit = apperrors.New(
	apperrors.CodeLocalIOError,
	"required read audit failed",
	nil,
)

type requiredReadAuditHandle struct {
	f           *cliFlags
	id          string
	path        string
	item        srvgovctx.Context
	contextName string
	target      string
	operator    string
	command     string
	risk        safety.Risk
	eventType   srvgovaudit.EventType
	options     coreaudit.Options
}

func beginRequiredReadAudit(
	f *cliFlags,
	item srvgovctx.Context,
	contextName, operator, command string,
	risk safety.Risk,
	eventType srvgovaudit.EventType,
) (*requiredReadAuditHandle, error) {
	return beginRequiredReadAuditWithSpec(
		f,
		item,
		contextName,
		item.Address(),
		operator,
		command,
		risk,
		eventType,
		coreaudit.Options{
			MaxSizeBytes:         item.AuditMaxSize,
			EncryptPublicKeyPath: item.AuditEncryptKey,
		},
	)
}

func beginRequiredLocalReadAudit(
	f *cliFlags,
	contextName, target, command string,
	eventType srvgovaudit.EventType,
) (*requiredReadAuditHandle, error) {
	operator, err := trustedOperator(f)
	if err != nil {
		return nil, err
	}
	return beginRequiredReadAuditWithSpec(
		f,
		srvgovctx.Context{},
		contextName,
		target,
		operator,
		command,
		safety.R0,
		eventType,
		coreaudit.Options{},
	)
}

func beginRequiredReadAuditWithSpec(
	f *cliFlags,
	item srvgovctx.Context,
	contextName, target, operator, command string,
	risk safety.Risk,
	eventType srvgovaudit.EventType,
	options coreaudit.Options,
) (*requiredReadAuditHandle, error) {
	path, err := coreaudit.DefaultPath()
	if err != nil {
		return nil, requiredReadAuditError("resolve", err)
	}
	random := mutationAuditRuntimeFor(f).random
	if random == nil {
		random = productionMutationAuditRuntime.random
	}
	id, err := newMutationID(random)
	if err != nil {
		return nil, requiredReadAuditError("create intent identifier", err)
	}
	handle := &requiredReadAuditHandle{
		f:           f,
		id:          id,
		path:        path,
		item:        item,
		contextName: contextName,
		target:      target,
		operator:    operator,
		command:     command,
		risk:        risk,
		eventType:   eventType,
		options:     options,
	}
	if err := appendQueuedAuditEvent(f, path, handle.intentEvent(), handle.options); err != nil {
		return nil, requiredReadAuditError("persist intent", err)
	}
	return handle, nil
}

func finishRequiredReadAudit(
	handle *requiredReadAuditHandle,
	result sshexec.Result,
	status string,
	operationErr error,
) error {
	if handle == nil {
		return requiredReadAuditError(
			"persist outcome",
			apperrors.New(apperrors.CodeValidationFailed, "required read audit handle is missing", nil),
		)
	}
	if err := appendQueuedAuditEvent(
		handle.f,
		handle.path,
		handle.outcomeEvent(result, status, operationErr),
		handle.options,
	); err != nil {
		if operationErr != nil {
			err = errors.Join(operationErr, err)
		}
		return requiredReadAuditError("persist outcome", err)
	}
	return operationErr
}

func finishRequiredLocalReadAudit(handle *requiredReadAuditHandle, operationErr error) error {
	status := srvgovaudit.StatusSucceeded
	if operationErr != nil {
		status = srvgovaudit.StatusFailed
	}
	return finishRequiredReadAudit(handle, sshexec.Result{}, status, operationErr)
}

func (handle *requiredReadAuditHandle) intentEvent() srvgovaudit.Event {
	return srvgovaudit.Event{
		EventType: srvgovaudit.EventType(string(handle.eventType) + "." + readAuditPhaseIntent),
		Operator:  handle.operator,
		Context: srvgovaudit.Context{
			Name:      handle.contextName,
			Env:       handle.item.Env,
			Protected: handle.item.Protected,
		},
		Target:      srvgovaudit.Target{Host: handle.target},
		Command:     handle.command,
		RiskTier:    riskName(handle.risk),
		Status:      "pending",
		OperationID: handle.id,
		Phase:       readAuditPhaseIntent,
		Action:      string(handle.eventType),
	}
}

func (handle *requiredReadAuditHandle) outcomeEvent(
	result sshexec.Result,
	status string,
	operationErr error,
) srvgovaudit.Event {
	var errorInfo *srvgovaudit.ErrorInfo
	if operationErr != nil {
		appErr := apperrors.AsAppError(operationErr)
		errorInfo = &srvgovaudit.ErrorInfo{Code: string(appErr.Code), Message: appErr.Message}
	}
	outcome := &srvgovaudit.ReadOutcome{
		Status:           status,
		OutputIncomplete: sshOutputIncomplete(result),
	}
	if operationErr != nil {
		outcome.ErrorCode = string(apperrors.AsAppError(operationErr).Code)
	}
	return srvgovaudit.Event{
		EventType: handle.eventType,
		Operator:  handle.operator,
		Context: srvgovaudit.Context{
			Name:      handle.contextName,
			Env:       handle.item.Env,
			Protected: handle.item.Protected,
		},
		Target:           srvgovaudit.Target{Host: handle.target},
		Command:          handle.command,
		RiskTier:         riskName(handle.risk),
		Status:           status,
		Stdout:           result.Stdout,
		Stderr:           result.Stderr,
		OutputIncomplete: sshOutputIncomplete(result),
		ExitCode:         result.ExitCode,
		Error:            errorInfo,
		OperationID:      handle.id,
		Phase:            readAuditPhaseOutcome,
		Action:           string(handle.eventType),
		ReadOutcome:      outcome,
	}
}

func requiredReadAuditError(action string, cause error) error {
	cause = errors.Join(errRequiredReadAudit, cause)
	return apperrors.New(
		apperrors.CodeLocalIOError,
		fmt.Sprintf("required read audit could not %s; no read result was released", action),
		cause,
	).WithSuggestion("repair the audit path and retry the read")
}
