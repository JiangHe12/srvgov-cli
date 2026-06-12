package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"gopkg.in/yaml.v3"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/credstore"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

const (
	ctxExportAPIVersion = "srvgov.io/ctx-export/v1"
	redactedCredential  = "<REDACTED>"
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
	command.Flags().BoolVar(&opts.includeCredentials, "include-credentials", false, "Include plaintext credentials when stored as plain-yaml")
	return command
}

func ctxImportCmd(f *cliFlags) *cobra.Command {
	var opts ctxImportOptions
	command := &cobra.Command{
		Use:   "import -f <file>",
		Short: "Import a portable context document",
		RunE: func(_ *cobra.Command, args []string) error {
			if len(args) != 0 {
				return apperrors.New(apperrors.CodeUsageError, "ctx import accepts no positional arguments", nil)
			}
			return runCtxImport(f, opts)
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
	if includeCredentials && item.CredentialBackend != "" && item.CredentialBackend != "plain-yaml" {
		if isLiteralCredential(item.Password) || isLiteralCredential(item.IdentityPassphrase) {
			return apperrors.New(apperrors.CodeCredentialStoreError, "cannot export plaintext credentials from secure backend; migrate to plain-yaml first or share out-of-band", nil)
		}
	}
	if !includeCredentials {
		if isLiteralCredential(item.Password) {
			item.Password = redactedCredential
		}
		if isLiteralCredential(item.IdentityPassphrase) {
			item.IdentityPassphrase = redactedCredential
		}
	}
	return nil
}

func runCtxImport(f *cliFlags, opts ctxImportOptions) error {
	if f.NonInteractive && !f.Yes {
		return apperrors.New(apperrors.CodeAuthorizationRequired, "ctx import requires --yes in non-interactive mode", nil)
	}
	if opts.file == "" {
		return apperrors.New(apperrors.CodeUsageError, "-f/--file is required", nil)
	}
	doc, err := readContextExportDocument(opts.file)
	if err != nil {
		return err
	}
	name, err := contextImportName(doc.Name, opts.rename)
	if err != nil {
		return err
	}
	passwordRedacted := doc.Context.Password == redactedCredential
	passphraseRedacted := doc.Context.IdentityPassphrase == redactedCredential
	if passwordRedacted {
		doc.Context.Password = ""
	}
	if passphraseRedacted {
		doc.Context.IdentityPassphrase = ""
	}
	referenced := applyCredentialBackendFromRefs(&doc.Context)
	cfg, err := srvgovctx.Load()
	if err != nil {
		return err
	}
	if _, exists := cfg.Contexts[name]; exists && !opts.force {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q already exists; use --force to overwrite", name), nil)
	}
	if err := srvgovctx.SetContext(name, doc.Context); err != nil {
		return err
	}
	emitAudit(f, contextAuditEvent(f, srvgovaudit.EventTypeContextImport, name, doc.Context), nil)
	result := contextImportResult{
		Name:                 name,
		PasswordRedacted:     passwordRedacted,
		PassphraseRedacted:   passphraseRedacted,
		CredentialReferences: referenced,
	}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ContextImportResult", result)
	}
	p.Success(fmt.Sprintf("context %q imported", name))
	if passwordRedacted || passphraseRedacted {
		p.Warn(fmt.Sprintf("credentials are redacted; run: srvgov ctx set %s --password=... --identity-passphrase=...", name))
	}
	return nil
}

func readContextExportDocument(path string) (contextExportDocument, error) {
	data, err := os.ReadFile(path) //nolint:gosec // User supplied context import path.
	if err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeLocalIOError, "failed to read context import file", err)
	}
	var doc contextExportDocument
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return contextExportDocument{}, apperrors.New(apperrors.CodeUsageError, "failed to parse context import file", err)
	}
	if doc.APIVersion != ctxExportAPIVersion {
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

func applyCredentialBackendFromRefs(item *srvgovctx.Context) bool {
	for _, value := range []string{item.Password, item.IdentityPassphrase} {
		ref := credstore.ParseRef(value)
		if ref.IsRef {
			item.CredentialBackend = ref.BackendName
			return true
		}
	}
	return false
}

func contextAuditEvent(f *cliFlags, eventType srvgovaudit.EventType, name string, item srvgovctx.Context) srvgovaudit.Event {
	return srvgovaudit.Event{
		EventType: eventType,
		Operator:  resolveOperator(f.Operator),
		Context: srvgovaudit.Context{
			Name:      name,
			Env:       item.Env,
			Protected: item.Protected,
		},
		Target:   srvgovaudit.Target{Host: name},
		Command:  string(eventType),
		RiskTier: "R0",
		Status:   srvgovaudit.StatusSucceeded,
	}
}
