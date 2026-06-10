package cmd

import (
	"context"
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/credstore"

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

func ctxMigrateCredentialsCmd(f *cliFlags) *cobra.Command {
	var opts migrateCredentialsOptions
	command := &cobra.Command{
		Use:   "migrate-credentials",
		Short: "Move context credentials to a credential backend",
		RunE: func(_ *cobra.Command, _ []string) error {
			return runCtxMigrateCredentials(f, opts)
		},
	}
	command.Flags().StringVar(&opts.toBackend, "to", "", "Target backend: encrypted-file or keychain")
	command.Flags().StringVar(&opts.contextName, "context", "", "Context to migrate")
	return command
}

func runCtxMigrateCredentials(f *cliFlags, opts migrateCredentialsOptions) error {
	if !validCredentialMigrationBackend(opts.toBackend) {
		return apperrors.New(apperrors.CodeUsageError, "--to must be encrypted-file or keychain", nil)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		return err
	}
	candidates, err := credentialMigrationCandidates(cfg, opts.contextName)
	if err != nil {
		return err
	}
	backend, err := credstore.New(opts.toBackend)
	if err != nil {
		return apperrors.New(apperrors.CodeUsageError, err.Error(), err)
	}
	if err := backend.Available(); err != nil {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("backend %q not available", opts.toBackend), err)
	}
	if err := storeMigratedCredentials(backend, candidates); err != nil {
		return err
	}
	for _, candidate := range candidates {
		item := candidate.context
		if candidate.password != "" {
			item.Password = credstore.EncodeRef(opts.toBackend)
		}
		if candidate.passphrase != "" {
			item.IdentityPassphrase = credstore.EncodeRef(opts.toBackend)
		}
		if candidate.password != "" || candidate.passphrase != "" {
			item.CredentialBackend = opts.toBackend
		}
		if err := srvgovctx.SetContext(candidate.name, item); err != nil {
			return err
		}
		emitAudit(credentialMigrateAuditEvent(f, candidate.name, opts.toBackend), nil)
	}
	result := map[string]any{"migrated": len(candidates), "backend": opts.toBackend}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("CredentialMigration", result)
	}
	p.Success(fmt.Sprintf("migrated %d context credential(s) to %s", len(candidates), opts.toBackend))
	return nil
}

func validCredentialMigrationBackend(name string) bool {
	return name == credentialBackendEncryptedFile || name == credentialBackendKeychain
}

func credentialMigrationCandidates(cfg *srvgovctx.Config, contextName string) ([]migrateCredentialCandidate, error) {
	if contextName != "" {
		item, ok := cfg.Contexts[contextName]
		if !ok {
			return nil, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", contextName), nil)
		}
		candidate, err := credentialMigrationCandidate(contextName, item)
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
		candidate, err := credentialMigrationCandidate(name, cfg.Contexts[name])
		if err != nil {
			return nil, err
		}
		if candidate != nil {
			candidates = append(candidates, *candidate)
		}
	}
	return candidates, nil
}

func credentialMigrationCandidate(name string, item srvgovctx.Context) (*migrateCredentialCandidate, error) {
	password, err := resolvedCredential(context.Background(), name, item.Password)
	if err != nil {
		return nil, err
	}
	passphrase, err := resolvedCredential(context.Background(), name+"#identity", item.IdentityPassphrase)
	if err != nil {
		return nil, err
	}
	if password == "" && passphrase == "" {
		return nil, nil
	}
	return &migrateCredentialCandidate{name: name, context: item, password: password, passphrase: passphrase}, nil
}

func storeMigratedCredentials(backend credstore.Backend, candidates []migrateCredentialCandidate) error {
	for _, candidate := range candidates {
		if candidate.password != "" {
			if err := backend.Put(context.Background(), candidate.name, candidate.password); err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("store password for context %q failed", candidate.name), err)
			}
		}
		if candidate.passphrase != "" {
			if err := backend.Put(context.Background(), candidate.name+"#identity", candidate.passphrase); err != nil {
				return apperrors.New(apperrors.CodeLocalIOError, fmt.Sprintf("store identity passphrase for context %q failed", candidate.name), err)
			}
		}
	}
	return nil
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

func credentialMigrateAuditEvent(f *cliFlags, contextName, backend string) srvgovaudit.Event {
	return srvgovaudit.Event{
		EventType: srvgovaudit.EventTypeCredentialMigrate,
		Operator:  resolveOperator(f.Operator),
		Context:   srvgovaudit.Context{Name: contextName},
		Target:    srvgovaudit.Target{Host: backend},
		Command:   string(srvgovaudit.EventTypeCredentialMigrate),
		RiskTier:  "R0",
		Status:    srvgovaudit.StatusSucceeded,
	}
}
