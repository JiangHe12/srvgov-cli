package cmd

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

const (
	ctxExportAPIVersion       = "srvgov-cli.io/ctx-export/v1"
	legacyCtxExportAPIVersion = "srvgov.io/ctx-export/v1"
	redactedCredential        = "<REDACTED>"
)

type contextExportDocument struct {
	APIVersion string            `yaml:"apiVersion"`
	Name       string            `yaml:"name"`
	Context    srvgovctx.Context `yaml:"context"`
}

type ctxExportOptions struct {
	includeCredentials bool
}

type ctxImportOptions struct {
	file   string
	force  bool
	rename string
}

type contextImportResult struct {
	Name                 string `json:"name"`
	PasswordRedacted     bool   `json:"passwordRedacted"`
	PassphraseRedacted   bool   `json:"passphraseRedacted"`
	CredentialReferences bool   `json:"credentialReferences"`
}

type preparedContextImport struct {
	name               string
	item               srvgovctx.Context
	passwordRedacted   bool
	passphraseRedacted bool
	referenced         bool
}

func ctxExportCmd(f *cliFlags) *cobra.Command {
	var opts ctxExportOptions
	command := &cobra.Command{
		Use:   "export <name>",
		Short: "Export a portable context document",
		Args:  requireExactArgs("ctx export"),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxExport(f, args[0], opts)
		},
	}
	command.Flags().BoolVar(&opts.includeCredentials, "include-credentials", false, "Deprecated; plaintext credential export is disabled")
	return command
}

func ctxImportCmd(f *cliFlags) *cobra.Command {
	var opts ctxImportOptions
	command := &cobra.Command{
		Use:   "import -f <file>",
		Short: "Import a portable context document",
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) != 0 {
				return apperrors.New(apperrors.CodeUsageError, "ctx import accepts no positional arguments", nil)
			}
			return runCtxImport(cmd, f, opts)
		},
	}
	command.Flags().StringVarP(&opts.file, "file", "f", "", "Portable context document to import")
	command.Flags().BoolVar(&opts.force, "force", false, "Overwrite an existing context")
	command.Flags().StringVar(&opts.rename, "rename", "", "Import under a different context name")
	return command
}

func runCtxExport(f *cliFlags, name string, opts ctxExportOptions) error {
	cfg, err := srvgovctx.Load()
	if err != nil {
		return err
	}
	item, ok := cfg.Contexts[name]
	if !ok {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
	}
	if err := prepareContextForExport(&item, opts.includeCredentials); err != nil {
		return err
	}
	data, err := yaml.Marshal(contextExportDocument{
		APIVersion: ctxExportAPIVersion,
		Name:       name,
		Context:    item,
	})
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to marshal context export", err)
	}
	out := f.Out
	if out == nil {
		out = os.Stdout
	}
	if _, err := out.Write(data); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write context export", err)
	}
	emitAudit(f, contextAuditEvent(f, srvgovaudit.EventTypeContextExport, name, item), nil)
	return nil
}

func prepareContextForExport(item *srvgovctx.Context, includeCredentials bool) error {
	if includeCredentials {
		return apperrors.New(
			apperrors.CodeUsageError,
			"--include-credentials is disabled; migrate legacy credentials to keychain or encrypted-file and share them out-of-band",
			nil,
		)
	}
	if isLiteralCredential(item.Password) {
		item.Password = redactedCredential
	}
	if isLiteralCredential(item.IdentityPassphrase) {
		item.IdentityPassphrase = redactedCredential
	}
	return nil
}

func runCtxImport(cmd *cobra.Command, f *cliFlags, opts ctxImportOptions) error {
	prepared, err := prepareContextImport(opts)
	if err != nil {
		return err
	}
	var auditHandle *mutationAuditHandle
	updateErr := srvgovctx.Update(func(cfg *srvgovctx.Config) error {
		if _, exists := cfg.Contexts[prepared.name]; exists && !opts.force {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q already exists; use --force to overwrite", prepared.name), nil)
		}
		prePolicy, policyErr := contextPreChangePolicy(cfg, prepared.name)
		if policyErr != nil {
			return policyErr
		}
		if authErr := authorizeControlChange(
			cmd,
			f,
			prePolicy,
			prepared.name,
			"context.import",
			allowContextChange,
			f.AllowCtxChange,
		); authErr != nil {
			return authErr
		}
		auditHandle, policyErr = beginControlMutationAudit(
			f,
			"context.import",
			prepared.name,
			prepared.name,
			prepared.item,
			prePolicy,
		)
		if policyErr != nil {
			return policyErr
		}
		cfg.Contexts[prepared.name] = prepared.item
		return nil
	})
	if err := finishControlMutationAudit(auditHandle, updateErr); err != nil {
		return err
	}
	result := contextImportResult{
		Name:                 prepared.name,
		PasswordRedacted:     prepared.passwordRedacted,
		PassphraseRedacted:   prepared.passphraseRedacted,
		CredentialReferences: prepared.referenced,
	}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ContextImportResult", result)
	}
	if err := p.Success(fmt.Sprintf("context %q imported", prepared.name)); err != nil {
		return err
	}
	if prepared.passwordRedacted || prepared.passphraseRedacted {
		return p.Warn(fmt.Sprintf(
			"credentials are redacted; run: srvgov ctx set %s --credential-backend encrypted-file --password=... --identity-passphrase=...",
			prepared.name,
		))
	}
	return nil
}

func prepareContextImport(opts ctxImportOptions) (preparedContextImport, error) {
	if opts.file == "" {
		return preparedContextImport{}, apperrors.New(apperrors.CodeUsageError, "-f/--file is required", nil)
	}
	doc, err := readContextExportDocument(opts.file)
	if err != nil {
		return preparedContextImport{}, err
	}
	name, err := contextImportName(doc.Name, opts.rename)
	if err != nil {
		return preparedContextImport{}, err
	}
	prepared := preparedContextImport{
		name:               name,
		item:               doc.Context,
		passwordRedacted:   doc.Context.Password == redactedCredential,
		passphraseRedacted: doc.Context.IdentityPassphrase == redactedCredential,
	}
	if prepared.passwordRedacted {
		prepared.item.Password = ""
	}
	if prepared.passphraseRedacted {
		prepared.item.IdentityPassphrase = ""
	}
	if isLiteralCredential(prepared.item.Password) || isLiteralCredential(prepared.item.IdentityPassphrase) {
		return preparedContextImport{}, apperrors.New(
			apperrors.CodeUsageError,
			"context import accepts only redacted credentials or credstore references; store credentials with ctx set after import",
			nil,
		)
	}
	referenceBackend, err := contextCredentialReferenceBackend(
		prepared.item.Password,
		prepared.item.IdentityPassphrase,
	)
	if err != nil {
		return preparedContextImport{}, err
	}
	if referenceBackend != "" {
		if credstore.IsPlaintextBackend(prepared.item.CredentialBackend) {
			prepared.item.CredentialBackend = referenceBackend
		} else if prepared.item.CredentialBackend != referenceBackend {
			return preparedContextImport{}, apperrors.New(
				apperrors.CodeUsageError,
				"credential references must match context credentialBackend",
				nil,
			)
		}
		prepared.referenced = true
	}
	if err := prepared.item.Normalize(); err != nil {
		return preparedContextImport{}, err
	}
	if err := validateRequestedRoles(prepared.item.Roles); err != nil {
		return preparedContextImport{}, err
	}
	return prepared, nil
}

func readContextExportDocument(path string) (contextExportDocument, error) {
	data, err := os.ReadFile(path) //nolint:gosec // User supplied context import path.
	if err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeLocalIOError, "failed to read context import file", err)
	}
	var doc contextExportDocument
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&doc); err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "failed to parse context import file", err)
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			err = apperrors.New(apperrors.CodeUsageError, "multiple YAML documents are not allowed", nil)
		}
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "failed to parse context import file", err)
	}
	if doc.APIVersion != ctxExportAPIVersion && doc.APIVersion != legacyCtxExportAPIVersion {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUnsupportedProtocol, fmt.Sprintf("unsupported context export apiVersion %q", doc.APIVersion), nil)
	}
	return doc, nil
}

func contextImportName(original, rename string) (string, error) {
	name := original
	if rename != "" {
		name = rename
	}
	if name == "" {
		return "", apperrors.New(apperrors.CodeUsageError, "context name is required", nil)
	}
	return name, nil
}

func isLiteralCredential(value string) bool {
	return value != "" && !credstore.ParseRef(value).IsRef
}

func contextAuditEvent(f *cliFlags, eventType srvgovaudit.EventType, name string, item srvgovctx.Context) srvgovaudit.Event {
	risk := "R0"
	if eventType != srvgovaudit.EventTypeContextExport {
		risk = "R3"
	}
	return srvgovaudit.Event{
		EventType: eventType,
		Operator:  currentOperator(f),
		Context: srvgovaudit.Context{
			Name:      name,
			Env:       item.Env,
			Protected: item.Protected,
		},
		Ticket:   f.Ticket,
		Target:   srvgovaudit.Target{Host: name},
		Command:  string(eventType),
		RiskTier: risk,
		Status:   srvgovaudit.StatusSucceeded,
	}
}
