package cmd

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sort"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

const (
	credentialBackendEncryptedFile = "encrypted-file"
	credentialBackendKeychain      = "keychain"
)

type migrateCredentialsOptions struct {
	toBackend   string
	contextName string
}

type migrateCredentialCandidate struct {
	name       string
	context    srvgovctx.Context
	password   string
	passphrase string
}

type credentialWrite struct {
	name     string
	value    string
	previous string
	existed  bool
}

type credentialStateUncertainError struct {
	err error
}

func (e *credentialStateUncertainError) Error() string {
	return e.err.Error()
}

func (e *credentialStateUncertainError) Unwrap() error {
	return e.err
}

var (
	newCredentialBackend              = credstore.New
	updateCredentialMigrationContexts = srvgovctx.Update
)

func ctxMigrateCredentialsCmd(f *cliFlags) *cobra.Command {
	var opts migrateCredentialsOptions
	command := &cobra.Command{
		Use:   "migrate-credentials",
		Short: "Move context credentials to a credential backend",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runCtxMigrateCredentials(cmd, f, opts)
		},
	}
	command.Flags().StringVar(&opts.toBackend, "to", "", "Target backend: encrypted-file or keychain")
	command.Flags().StringVar(&opts.contextName, "context", "", "Context to migrate")
	return command
}

func runCtxMigrateCredentials(cmd *cobra.Command, f *cliFlags, opts migrateCredentialsOptions) error {
	if !validCredentialMigrationBackend(opts.toBackend) {
		return apperrors.New(apperrors.CodeUsageError, "--to must be encrypted-file or keychain", nil)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		return err
	}
	candidates, err := credentialMigrationCandidates(cmd.Context(), cfg, opts.contextName)
	if err != nil {
		return err
	}
	if len(candidates) == 0 {
		return printCredentialMigrationResult(f, opts.toBackend, 0)
	}
	backend, err := newCredentialBackend(opts.toBackend)
	if err != nil {
		return apperrors.New(apperrors.CodeUsageError, err.Error(), err)
	}
	if err := backend.Available(); err != nil {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("backend %q not available", opts.toBackend), err)
	}
	writes, err := prepareCredentialWrites(cmd.Context(), backend, candidates)
	if err != nil {
		return err
	}
	if err := applyCredentialMigration(cmd, f, opts.toBackend, backend, candidates, writes); err != nil {
		return err
	}
	return printCredentialMigrationResult(f, opts.toBackend, len(candidates))
}

//nolint:gocyclo // Authorization, compensation, commit ambiguity, and audit outcome form one transaction boundary.
func applyCredentialMigration(
	cmd *cobra.Command,
	f *cliFlags,
	targetBackend string,
	backend credstore.Backend,
	candidates []migrateCredentialCandidate,
	writes []credentialWrite,
) error {
	credentialsStored := false
	credentialStateUncertain := false
	var auditHandle *mutationAuditHandle
	updateErr := updateCredentialMigrationContexts(func(current *srvgovctx.Config) error {
		if err := validateCredentialMigrationSnapshot(current, candidates); err != nil {
			return err
		}
		for _, candidate := range candidates {
			if err := authorizeControlChange(
				cmd,
				f,
				candidate.context,
				candidate.name,
				"credential.migrate",
				allowContextChange,
				f.AllowCtxChange,
			); err != nil {
				return err
			}
		}
		auditPolicy, contextName, err := credentialMigrationAuditPolicy(current, candidates)
		if err != nil {
			return err
		}
		auditHandle, err = beginMutationAudit(f, mutationAuditSpec{
			Action:      "credential.migrate",
			ContextName: contextName,
			Context:     auditPolicy,
			Target:      targetBackend,
			RiskTier:    "R3",
			Ticket:      f.Ticket,
			Metadata: mutationAuditMetadata{
				Items:   len(candidates),
				Updates: len(candidates),
			},
			Options: coreAuditOptions(auditPolicy),
		})
		if err != nil {
			return err
		}
		if err := applyCredentialWritesContext(cmd.Context(), backend, writes); err != nil {
			credentialStateUncertain = isCredentialStateUncertain(err)
			return err
		}
		if err := cmd.Context().Err(); err != nil {
			if rollbackErr := rollbackCredentialWrites(backend, writes); rollbackErr != nil {
				credentialStateUncertain = true
				return newCredentialStateUncertainError(
					"credential migration was canceled and compensation was incomplete",
					errors.Join(err, rollbackErr),
				)
			}
			return err
		}
		credentialsStored = true
		for _, candidate := range candidates {
			current.Contexts[candidate.name] = migratedCredentialContext(candidate, targetBackend)
		}
		return nil
	})
	finalErr := updateErr
	if updateErr != nil && credentialsStored {
		finalErr = apperrors.New(
			apperrors.CodePartialFailure,
			"context update reported failure after credential storage; the configuration commit state is uncertain",
			updateErr,
		).WithSuggestion("inspect the context and credential backend before any retry")
	}
	outcome := mutationAuditOutcome{}
	switch {
	case finalErr == nil:
		outcome.Status = srvgovaudit.StatusSucceeded
		outcome.Succeeded = len(candidates)
	case credentialsStored || credentialStateUncertain:
		outcome.Status = srvgovaudit.StatusFailed
		outcome.Uncertain = len(candidates)
	default:
		outcome.Status = srvgovaudit.StatusFailed
		outcome.Failed = len(candidates)
	}
	if auditHandle == nil {
		return finalErr
	}
	return finishMutationAudit(auditHandle, outcome, finalErr)
}

func credentialMigrationAuditPolicy(
	cfg *srvgovctx.Config,
	candidates []migrateCredentialCandidate,
) (srvgovctx.Context, string, error) {
	if cfg.CurrentContext != "" {
		item, ok := cfg.Contexts[cfg.CurrentContext]
		if !ok {
			return srvgovctx.Context{}, "", apperrors.New(
				apperrors.CodeValidationFailed,
				fmt.Sprintf("current context %q does not exist; refusing credential migration audit", cfg.CurrentContext),
				nil,
			)
		}
		return item, cfg.CurrentContext, nil
	}
	if len(candidates) == 0 {
		return srvgovctx.Context{}, "", apperrors.New(
			apperrors.CodeValidationFailed,
			"credential migration has no auditable context",
			nil,
		)
	}
	return candidates[0].context, candidates[0].name, nil
}

func printCredentialMigrationResult(f *cliFlags, backend string, migrated int) error {
	result := map[string]any{"migrated": migrated, "backend": backend}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("CredentialMigration", result)
	}
	return p.Success(fmt.Sprintf("migrated %d context credential(s) to %s", migrated, backend))
}

func validCredentialMigrationBackend(name string) bool {
	return name == credentialBackendEncryptedFile || name == credentialBackendKeychain
}

func credentialMigrationCandidates(
	ctx context.Context,
	cfg *srvgovctx.Config,
	contextName string,
) ([]migrateCredentialCandidate, error) {
	if contextName != "" {
		item, ok := cfg.Contexts[contextName]
		if !ok {
			return nil, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", contextName), nil)
		}
		candidate, err := credentialMigrationCandidate(ctx, contextName, item)
		if err != nil || candidate == nil {
			return nil, err
		}
		return []migrateCredentialCandidate{*candidate}, nil
	}
	names := make([]string, 0, len(cfg.Contexts))
	for name := range cfg.Contexts {
		names = append(names, name)
	}
	sort.Strings(names)
	candidates := make([]migrateCredentialCandidate, 0, len(names))
	for _, name := range names {
		candidate, err := credentialMigrationCandidate(ctx, name, cfg.Contexts[name])
		if err != nil {
			return nil, err
		}
		if candidate != nil {
			candidates = append(candidates, *candidate)
		}
	}
	return candidates, nil
}

func credentialMigrationCandidate(
	ctx context.Context,
	name string,
	item srvgovctx.Context,
) (*migrateCredentialCandidate, error) {
	validated := item
	if err := validated.Normalize(); err != nil {
		return nil, err
	}
	password, err := resolvedCredential(ctx, name, item.Password)
	if err != nil {
		return nil, err
	}
	passphrase, err := resolvedCredential(ctx, name+"#identity", item.IdentityPassphrase)
	if err != nil {
		return nil, err
	}
	if password == "" && passphrase == "" {
		return nil, nil
	}
	return &migrateCredentialCandidate{name: name, context: item, password: password, passphrase: passphrase}, nil
}

func prepareCredentialWrites(
	ctx context.Context,
	backend credstore.Backend,
	candidates []migrateCredentialCandidate,
) ([]credentialWrite, error) {
	writes := make([]credentialWrite, 0, len(candidates)*2)
	for _, candidate := range candidates {
		if candidate.password != "" {
			write, err := prepareCredentialWriteContext(ctx, backend, candidate.name, candidate.password)
			if err != nil {
				return nil, err
			}
			writes = append(writes, write)
		}
		if candidate.passphrase != "" {
			write, err := prepareCredentialWriteContext(
				ctx,
				backend,
				candidate.name+"#identity",
				candidate.passphrase,
			)
			if err != nil {
				return nil, err
			}
			writes = append(writes, write)
		}
	}
	return writes, nil
}

func prepareCredentialWriteContext(
	ctx context.Context,
	backend credstore.Backend,
	name, value string,
) (credentialWrite, error) {
	previous, err := backend.Get(ctx, name)
	if err == nil {
		return credentialWrite{name: name, value: value, previous: previous, existed: true}, nil
	}
	if errors.Is(err, credstore.ErrNotFound) {
		return credentialWrite{name: name, value: value}, nil
	}
	return credentialWrite{}, apperrors.New(
		apperrors.CodeCredentialStoreError,
		fmt.Sprintf("backup target credential %q before update", name),
		err,
	)
}

func applyCredentialWritesContext(
	ctx context.Context,
	backend credstore.Backend,
	writes []credentialWrite,
) error {
	for index, write := range writes {
		if err := backend.Put(ctx, write.name, write.value); err != nil {
			storeErr := apperrors.New(
				apperrors.CodeCredentialStoreError,
				fmt.Sprintf("store credential %q failed", write.name),
				err,
			)
			if rollbackErr := rollbackCredentialWrites(backend, writes[:index+1]); rollbackErr != nil {
				return newCredentialStateUncertainError(
					"credential update failed and compensation was incomplete",
					errors.Join(storeErr, rollbackErr),
				)
			}
			return storeErr
		}
	}
	return nil
}

func newCredentialStateUncertainError(message string, cause error) error {
	return &credentialStateUncertainError{err: apperrors.New(
		apperrors.CodePartialFailure,
		message,
		cause,
	).WithSuggestion("inspect the credential backend before any retry")}
}

func isCredentialStateUncertain(err error) bool {
	var uncertain *credentialStateUncertainError
	return errors.As(err, &uncertain)
}

func rollbackCredentialWrites(backend credstore.Backend, writes []credentialWrite) error {
	var rollbackErr error
	for index := len(writes) - 1; index >= 0; index-- {
		write := writes[index]
		if write.existed {
			if err := backend.Put(context.Background(), write.name, write.previous); err != nil {
				rollbackErr = errors.Join(rollbackErr, err)
			}
			continue
		}
		if err := backend.Delete(context.Background(), write.name); err != nil && !errors.Is(err, credstore.ErrNotFound) {
			rollbackErr = errors.Join(rollbackErr, err)
		}
	}
	return rollbackErr
}

func validateCredentialMigrationSnapshot(
	cfg *srvgovctx.Config,
	candidates []migrateCredentialCandidate,
) error {
	for _, candidate := range candidates {
		current, ok := cfg.Contexts[candidate.name]
		if !ok || !reflect.DeepEqual(current, candidate.context) {
			return apperrors.New(
				apperrors.CodeValidationFailed,
				fmt.Sprintf("context %q changed while credential migration was being prepared; retry", candidate.name),
				nil,
			)
		}
	}
	return nil
}

func migratedCredentialContext(candidate migrateCredentialCandidate, backend string) srvgovctx.Context {
	item := candidate.context
	if candidate.password != "" {
		item.Password = credstore.EncodeRef(backend)
	}
	if candidate.passphrase != "" {
		item.IdentityPassphrase = credstore.EncodeRef(backend)
	}
	if candidate.password != "" || candidate.passphrase != "" {
		item.CredentialBackend = backend
	}
	return item
}

func resolvedCredential(ctx context.Context, name string, value string) (string, error) {
	if value == "" {
		return "", nil
	}
	ref := credstore.ParseRef(value)
	if !ref.IsRef {
		return value, nil
	}
	backend, err := credstore.New(ref.BackendName)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("resolve credential for context %q", name), err)
	}
	secret, err := backend.Get(ctx, name)
	if err != nil {
		return "", apperrors.New(apperrors.CodeCredentialStoreError, fmt.Sprintf("resolve credential for context %q", name), err)
	}
	return secret, nil
}
