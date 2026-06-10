package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

type contextView struct {
	Name      string `json:"name"`
	Server    string `json:"server"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	Username  string `json:"username,omitempty"`
	Env       string `json:"env,omitempty"`
	Protected bool   `json:"protected"`
	Current   bool   `json:"current"`
}

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
	command := &cobra.Command{
		Use:   "set <name>",
		Short: "Add or update a server context",
		Args:  requireExactArgs("ctx set"),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := srvgovctx.SetContext(args[0], request); err != nil {
				return err
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONData("ContextItem", map[string]string{"name": args[0]})
			}
			p.Success(fmt.Sprintf("context %q saved", args[0]))
			return nil
		},
	}
	command.Flags().StringVar(&request.Server, "server", "", "SSH server URI, for example ssh://user@host:22")
	command.Flags().StringVar(&request.Host, "host", "", "SSH host")
	command.Flags().IntVar(&request.Port, "port", 0, "SSH port (default 22)")
	command.Flags().StringVar(&request.Username, "username", "", "SSH username")
	command.Flags().StringVar(&request.Password, "password", "", "SSH password or credstore reference")
	command.Flags().StringVar(&request.IdentityFile, "identity-file", "", "Private key path")
	command.Flags().StringVar(&request.IdentityPassphrase, "identity-passphrase", "", "Private key passphrase or credstore reference")
	command.Flags().StringSliceVar(&request.AuthMethods, "auth-method", nil, "Authentication preference: private-key, agent, password")
	command.Flags().StringVar(&request.Env, "env", "", "Environment label")
	command.Flags().BoolVar(&request.Protected, "protected", false, "Enable protected-context governance")
	command.Flags().StringVar(&request.TicketPattern, "ticket-pattern", "", "Ticket regex pattern")
	command.Flags().StringVar(&request.CredentialBackend, "credential-backend", "plain-yaml", "Credential backend")
	command.Flags().StringVar(&request.OTLPEndpoint, "otel-endpoint", "", "OTLP trace endpoint")
	command.Flags().BoolVar(&request.OTLPInsecure, "otel-insecure", false, "Disable TLS for OTLP exporter")
	command.Flags().BoolVar(&request.OTLPRedact, "otel-redact", true, "Redact sensitive OTel attributes")
	return command
}

func ctxUseCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "use <name>",
		Short: "Switch current context",
		Args:  requireExactArgs("ctx use"),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := srvgovctx.UseContext(args[0]); err != nil {
				return err
			}
			newPrinter(f).Success(fmt.Sprintf("current context is %q", args[0]))
			return nil
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
					fmt.Sprintf("%t", view.Current),
				})
			}
			p := newPrinter(f)
			if f.Output == "json" {
				return p.JSONList("ContextList", views, len(views), 1, len(views), false)
			}
			p.Table([]string{"NAME", "HOST", "PORT", "USERNAME", "ENV", "CURRENT"}, rows)
			return nil
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
			p.KV([][2]string{
				{"Name", view.Name},
				{"Server", view.Server},
				{"Host", view.Host},
				{"Port", fmt.Sprintf("%d", view.Port)},
				{"Username", view.Username},
				{"Environment", view.Env},
				{"Protected", fmt.Sprintf("%t", view.Protected)},
			})
			return nil
		},
	}
}

func ctxDeleteCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:     "delete <name>",
		Aliases: []string{"rm", "remove"},
		Short:   "Delete a server context",
		Args:    requireExactArgs("ctx delete"),
		RunE: func(_ *cobra.Command, args []string) error {
			if err := srvgovctx.DeleteContext(args[0]); err != nil {
				return err
			}
			newPrinter(f).Success(fmt.Sprintf("context %q deleted", args[0]))
			return nil
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
	}
}
