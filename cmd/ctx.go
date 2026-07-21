package cmd

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

type contextView struct {
	Name      string            `json:"name"`
	Server    string            `json:"server"`
	Host      string            `json:"host"`
	Port      int               `json:"port"`
	Username  string            `json:"username,omitempty"`
	Env       string            `json:"env,omitempty"`
	Protected bool              `json:"protected"`
	Current   bool              `json:"current"`
	Labels    map[string]string `json:"labels,omitempty"`
}

type contextCredentialPlan struct {
	backend            credstore.Backend
	backendName        string
	password           string
	identityPassphrase string
}

var updateContextSetContexts = srvgovctx.Update

func newContextCmd(f *cliFlags) *cobra.Command {
	command := &cobra.Command{
		Use:     "ctx",
		Aliases: []string{"context"},
		Short:   "Manage server contexts",
	}
	command.AddCommand(
		ctxSetCmd(f),
		ctxUseCmd(f),
		ctxListCmd(f),
		ctxCurrentCmd(f),
		ctxDeleteCmd(f),
		ctxRoleCmd(f),
		ctxExportCmd(f),
		ctxImportCmd(f),
		ctxMigrateCredentialsCmd(f),
	)
	return command
}

func ctxSetCmd(f *cliFlags) *cobra.Command {
	var request srvgovctx.Context
	var labels []string
	command := &cobra.Command{
		Use:   "set <name>",
		Short: "Add or update a server context",
		Args:  requireExactArgs("ctx set"),
		RunE: func(cmd *cobra.Command, args []string) error {
			parsedLabels, err := parseLabelFlags(labels)
			if err != nil {
				return err
			}
			request.Labels = parsedLabels
			if err := request.Normalize(); err != nil {
				return err
			}
			credentialPlan, err := prepareContextCredentialPlan(&request)
			if err != nil {
				return err
			}
			var auditHandle *mutationAuditHandle
			credentialsStored := false
			credentialStateUncertain := false
			updateErr := updateContextSetContexts(func(cfg *srvgovctx.Config) error {
				prePolicy, policyErr := contextPreChangePolicy(cfg, args[0])
				if policyErr != nil {
					return policyErr
				}
				if authErr := authorizeControlChange(
					cmd,
					f,
					prePolicy,
					args[0],
					"context.set",
					allowContextChange,
					f.AllowCtxChange,
				); authErr != nil {
					return authErr
				}
				auditHandle, policyErr = beginControlMutationAudit(
					f,
					"context.set",
					args[0],
					args[0],
					request,
					prePolicy,
				)
				if policyErr != nil {
					return policyErr
				}
				stored, didStore, stateUncertain, storeErr := storeContextCredentials(cmd, args[0], request, credentialPlan)
				credentialsStored = didStore
				credentialStateUncertain = stateUncertain
				if storeErr != nil {
					return storeErr
				}
				cfg.Contexts[args[0]] = stored
				return nil
			})
			if updateErr != nil && credentialStateUncertain {
				return finishUncertainControlMutationAudit(auditHandle, updateErr)
			}
			if updateErr != nil && credentialsStored {
				uncertainErr := apperrors.New(
					apperrors.CodePartialFailure,
					"context update reported failure after credential storage; the configuration commit state is uncertain",
					updateErr,
				).WithSuggestion("inspect the context and credential backend before any retry")
				return finishUncertainControlMutationAudit(auditHandle, uncertainErr)
			}
			if err := finishControlMutationAudit(auditHandle, updateErr); err != nil {
				return err
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONData("ContextItem", map[string]string{"name": args[0]})
			}
			return p.Success(fmt.Sprintf("context %q saved", args[0]))
		},
	}
	command.Flags().StringVar(&request.Server, "server", "", "SSH server URI, for example ssh://user@host:22")
	command.Flags().StringVar(&request.Host, "host", "", "SSH host")
	command.Flags().IntVar(&request.Port, "port", 0, "SSH port (default 22)")
	command.Flags().StringVar(&request.Username, "username", "", "SSH username")
	command.Flags().StringVar(&request.Password, "password", "", "SSH password to store in a secure backend, or a credstore reference")
	command.Flags().StringVar(&request.IdentityFile, "identity-file", "", "Private key path")
	command.Flags().StringVar(&request.IdentityPassphrase, "identity-passphrase", "", "Private key passphrase to store in a secure backend, or a credstore reference")
	command.Flags().StringSliceVar(&request.AuthMethods, "auth-method", nil, "Authentication preference: private-key, agent, password")
	command.Flags().StringVar(&request.Env, "env", "", "Environment label")
	command.Flags().StringArrayVar(&labels, "label", nil, "Context label key=value; repeat to set multiple labels")
	command.Flags().BoolVar(&request.Protected, "protected", false, "Enable protected-context governance")
	command.Flags().StringVar(&request.TicketPattern, "ticket-pattern", "", "Ticket regex pattern")
	command.Flags().StringVar(&request.CredentialBackend, "credential-backend", "plain-yaml", "Credential backend; credentials require keychain or encrypted-file")
	command.Flags().StringVar(&request.OTLPEndpoint, "otel-endpoint", "", "OTLP trace endpoint")
	command.Flags().BoolVar(&request.OTLPInsecure, "otel-insecure", false, "Disable TLS for OTLP exporter")
	command.Flags().BoolVar(&request.OTLPRedact, "otel-redact", true, "Redact sensitive OTel attributes")
	return command
}

func prepareContextCredentialPlan(item *srvgovctx.Context) (contextCredentialPlan, error) {
	item.CredentialBackend = strings.TrimSpace(item.CredentialBackend)
	plan := contextCredentialPlan{
		backendName:        item.CredentialBackend,
		password:           literalCredential(item.Password),
		identityPassphrase: literalCredential(item.IdentityPassphrase),
	}
	hasLiteral := plan.password != "" || plan.identityPassphrase != ""
	if err := credstore.RequireSecureBackend(plan.backendName, hasLiteral); err != nil {
		return contextCredentialPlan{}, err
	}

	referenceBackend, err := contextCredentialReferenceBackend(item.Password, item.IdentityPassphrase)
	if err != nil {
		return contextCredentialPlan{}, err
	}
	if referenceBackend != "" {
		if credstore.IsPlaintextBackend(item.CredentialBackend) {
			item.CredentialBackend = referenceBackend
			plan.backendName = referenceBackend
		} else if item.CredentialBackend != referenceBackend {
			return contextCredentialPlan{}, apperrors.New(
				apperrors.CodeUsageError,
				"credential references must match --credential-backend",
				nil,
			)
		}
	}
	if !hasLiteral {
		return plan, nil
	}

	backend, err := newCredentialBackend(plan.backendName)
	if err != nil {
		return contextCredentialPlan{}, apperrors.New(
			apperrors.CodeCredentialStoreError,
			fmt.Sprintf("credential backend %q is not available", plan.backendName),
			err,
		)
	}
	if err := backend.Available(); err != nil {
		return contextCredentialPlan{}, apperrors.New(
			apperrors.CodeCredentialStoreError,
			fmt.Sprintf("credential backend %q is not available", plan.backendName),
			err,
		)
	}
	plan.backend = backend
	return plan, nil
}

func storeContextCredentials(
	cmd *cobra.Command,
	name string,
	item srvgovctx.Context,
	plan contextCredentialPlan,
) (srvgovctx.Context, bool, bool, error) {
	if plan.backend == nil {
		return item, false, false, nil
	}
	writes := make([]credentialWrite, 0, 2)
	if plan.password != "" {
		write, err := prepareCredentialWriteContext(cmd.Context(), plan.backend, name, plan.password)
		if err != nil {
			return srvgovctx.Context{}, false, false, err
		}
		writes = append(writes, write)
	}
	if plan.identityPassphrase != "" {
		write, err := prepareCredentialWriteContext(
			cmd.Context(),
			plan.backend,
			name+"#identity",
			plan.identityPassphrase,
		)
		if err != nil {
			return srvgovctx.Context{}, false, false, err
		}
		writes = append(writes, write)
	}
	if err := applyCredentialWritesContext(cmd.Context(), plan.backend, writes); err != nil {
		return srvgovctx.Context{}, false, isCredentialStateUncertain(err), err
	}
	if err := cmd.Context().Err(); err != nil {
		if rollbackErr := rollbackCredentialWrites(plan.backend, writes); rollbackErr != nil {
			return srvgovctx.Context{}, false, true, newCredentialStateUncertainError(
				"credential storage was canceled and compensation was incomplete",
				errors.Join(err, rollbackErr),
			)
		}
		return srvgovctx.Context{}, false, false, err
	}
	if plan.password != "" {
		item.Password = credstore.EncodeRef(plan.backendName)
	}
	if plan.identityPassphrase != "" {
		item.IdentityPassphrase = credstore.EncodeRef(plan.backendName)
	}
	item.CredentialBackend = plan.backendName
	return item, len(writes) > 0, false, nil
}

func literalCredential(value string) string {
	if value == "" || credstore.ParseRef(value).IsRef {
		return ""
	}
	return value
}

func contextCredentialReferenceBackend(values ...string) (string, error) {
	backendName := ""
	for _, value := range values {
		ref := credstore.ParseRef(value)
		if !ref.IsRef {
			continue
		}
		if ref.BackendName == "" {
			return "", apperrors.New(apperrors.CodeUsageError, "credential reference backend must not be empty", nil)
		}
		if backendName != "" && backendName != ref.BackendName {
			return "", apperrors.New(apperrors.CodeUsageError, "credential references must use the same backend", nil)
		}
		backendName = ref.BackendName
	}
	return backendName, nil
}

func ctxUseCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Switch current context",
		Args:  requireExactArgs("ctx use"),
		RunE: func(cmd *cobra.Command, args []string) error {
			var auditHandle *mutationAuditHandle
			updateErr := srvgovctx.Update(func(cfg *srvgovctx.Config) error {
				target, ok := cfg.Contexts[args[0]]
				if !ok {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", args[0]), nil)
				}
				prePolicy, policyErr := contextUsePreChangePolicy(cfg, target)
				if policyErr != nil {
					return policyErr
				}
				if authErr := authorizeControlChange(
					cmd,
					f,
					prePolicy,
					args[0],
					"context.use",
					allowContextChange,
					f.AllowCtxChange,
				); authErr != nil {
					return authErr
				}
				auditHandle, policyErr = beginControlMutationAudit(
					f,
					"context.use",
					args[0],
					args[0],
					target,
					prePolicy,
				)
				if policyErr != nil {
					return policyErr
				}
				cfg.CurrentContext = args[0]
				return nil
			})
			if err := finishControlMutationAudit(auditHandle, updateErr); err != nil {
				return err
			}
			return newPrinter(f).Success(fmt.Sprintf("current context is %q", args[0]))
		},
	}
}

func ctxListCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List server contexts",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			cfg, err := srvgovctx.Load()
			if err != nil {
				return err
			}
			names := make([]string, 0, len(cfg.Contexts))
			for name := range cfg.Contexts {
				names = append(names, name)
			}
			sort.Strings(names)
			views := make([]contextView, 0, len(names))
			rows := make([][]string, 0, len(names))
			for _, name := range names {
				view := makeContextView(name, cfg.Contexts[name], name == cfg.CurrentContext)
				views = append(views, view)
				rows = append(rows, []string{
					view.Name,
					view.Host,
					fmt.Sprintf("%d", view.Port),
					view.Username,
					view.Env,
					formatLabels(view.Labels),
					fmt.Sprintf("%t", view.Current),
				})
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONList("ContextList", views, len(views), 1, len(views), false)
			}
			return p.Table([]string{"NAME", "HOST", "PORT", "USERNAME", "ENV", "LABELS", "CURRENT"}, rows)
		},
	}
}

func ctxCurrentCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show current context",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			current, name, err := srvgovctx.Current()
			if err != nil {
				return err
			}
			view := makeContextView(name, *current, true)
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONData("ContextItem", view)
			}
			return p.KV([][2]string{
				{"Name", view.Name},
				{"Server", view.Server},
				{"Host", view.Host},
				{"Port", fmt.Sprintf("%d", view.Port)},
				{"Username", view.Username},
				{"Environment", view.Env},
				{"Labels", formatLabels(view.Labels)},
				{"Protected", fmt.Sprintf("%t", view.Protected)},
			})
		},
	}
}

func ctxDeleteCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name>",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a server context",
		Args:    requireExactArgs("ctx delete"),
		RunE: func(cmd *cobra.Command, args []string) error {
			var auditHandle *mutationAuditHandle
			updateErr := srvgovctx.Update(func(cfg *srvgovctx.Config) error {
				item, ok := cfg.Contexts[args[0]]
				if !ok {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", args[0]), nil)
				}
				if authErr := authorizeControlChange(
					cmd,
					f,
					item,
					args[0],
					"context.delete",
					allowContextDelete,
					f.AllowCtxDelete,
				); authErr != nil {
					return authErr
				}
				var auditErr error
				auditHandle, auditErr = beginControlMutationAudit(
					f,
					"context.delete",
					args[0],
					args[0],
					item,
					item,
				)
				if auditErr != nil {
					return auditErr
				}
				delete(cfg.Contexts, args[0])
				if cfg.CurrentContext == args[0] {
					cfg.CurrentContext = ""
				}
				return nil
			})
			if err := finishControlMutationAudit(auditHandle, updateErr); err != nil {
				return err
			}
			return newPrinter(f).Success(fmt.Sprintf("context %q deleted", args[0]))
		},
	}
}

func makeContextView(name string, item srvgovctx.Context, current bool) contextView {
	return contextView{
		Name:      name,
		Server:    item.Server,
		Host:      item.Host,
		Port:      item.Port,
		Username:  item.Username,
		Env:       item.Env,
		Protected: item.Protected,
		Current:   current,
		Labels:    cloneLabels(item.Labels),
	}
}

func parseLabelFlags(values []string) (map[string]string, error) {
	if len(values) == 0 {
		return nil, nil
	}
	labels := make(map[string]string, len(values))
	for _, value := range values {
		key, labelValue, ok := strings.Cut(value, "=")
		key = strings.TrimSpace(key)
		labelValue = strings.TrimSpace(labelValue)
		if !ok || key == "" || labelValue == "" {
			return nil, apperrors.New(apperrors.CodeUsageError, "--label must be key=value with non-empty key and value", nil)
		}
		labels[key] = labelValue
	}
	return labels, nil
}

func cloneLabels(labels map[string]string) map[string]string {
	if len(labels) == 0 {
		return nil
	}
	out := make(map[string]string, len(labels))
	for key, value := range labels {
		out[key] = value
	}
	return out
}

func formatLabels(labels map[string]string) string {
	if len(labels) == 0 {
		return ""
	}
	keys := make([]string, 0, len(labels))
	for key := range labels {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+labels[key])
	}
	return strings.Join(parts, ",")
}
