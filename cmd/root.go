// Package cmd defines the srvgov command tree.
package cmd

import (
	"fmt"
	"io"
	"os"
	osuser "os/user"
	"strings"
	"sync"

	"github.com/fatih/color"
	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/printer"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

var auditWarningMu sync.Mutex

type cliFlags struct {
	Output          string
	Debug           bool
	Trace           bool
	NoColor         bool
	Config          string
	Context         string
	IgnoredOperator string
	Ticket          string
	Yes             bool
	NonInteractive  bool
	AllowCtxChange  bool
	AllowCtxDelete  bool
	AllowRoleChange bool
	AllowAuditPrune bool
	Out             io.Writer
	Err             io.Writer
	trustedOperator string
	resolveOperator func() (string, error)
	mutationAudit   *mutationAuditRuntime
}

// NewRootCmd constructs the srvgov root command.
func NewRootCmd() *cobra.Command {
	return newRootCmdWith(&cliFlags{Output: "table"})
}

func newRootCmdWith(f *cliFlags) *cobra.Command {
	root := &cobra.Command{
		Use:           "srvgov-cli",
		Short:         "Governed remote server operations for AI agents",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			applyGlobalFlags(f)
			f.Out = cmd.OutOrStdout()
			f.Err = cmd.ErrOrStderr()
			if f.Config != "" {
				srvgovctx.SetConfigPath(f.Config)
			}
			_, err := trustedOperator(f)
			return err
		},
	}
	root.PersistentFlags().StringVarP(&f.Output, "output", "o", "table", "Output format: table | json | plain")
	root.PersistentFlags().BoolVar(&f.Debug, "debug", false, "Enable debug logging")
	root.PersistentFlags().BoolVar(&f.Trace, "trace", false, "Enable trace logging (implies --debug)")
	root.PersistentFlags().BoolVar(&f.NoColor, "no-color", false, "Disable colored output")
	root.PersistentFlags().StringVar(&f.Config, "config", "", "Temporarily override config file path")
	root.PersistentFlags().StringVar(&f.Context, "context", "", "Server context name (default current)")
	root.PersistentFlags().StringVar(&f.IgnoredOperator, "operator", "", "Deprecated compatibility input; ignored for identity and authorization")
	root.PersistentFlags().StringVar(&f.Ticket, "ticket", "", "Change ticket")
	root.PersistentFlags().BoolVar(&f.Yes, "yes", false, "Confirm an authorized change")
	root.PersistentFlags().BoolVar(&f.NonInteractive, "non-interactive", false, "Disable interactive authorization prompts")
	root.PersistentFlags().BoolVar(&f.AllowCtxChange, "allow-context-change", false, "Allow an R3 context create, replacement, selection, import, or credential migration")
	root.PersistentFlags().BoolVar(&f.AllowCtxDelete, "allow-context-delete", false, "Allow an R3 context deletion")
	root.PersistentFlags().BoolVar(&f.AllowRoleChange, "allow-role-change", false, "Allow an R3 context role assignment or removal")
	root.PersistentFlags().BoolVar(&f.AllowAuditPrune, "allow-audit-prune", false, "Allow R3 deletion of rotated audit logs")
	root.AddCommand(
		newContextCmd(f),
		newExecCmd(f),
		newStatusCmd(f),
		newPortsCmd(f),
		newLogsCmd(f),
		newSvcCmd(f),
		newFileCmd(f),
		newDockerCmd(f),
		newAuditCmd(f),
		newDoctorCmd(f),
		newVersionCmd(f),
		newCapabilitiesCmd(f),
		newInstallCmd(f),
	)
	return root
}

func applyGlobalFlags(f *cliFlags) {
	if f.Trace {
		f.Debug = true
	}
	if f.NoColor {
		_ = os.Setenv("NO_COLOR", "1")
		color.NoColor = true
	}
}

func newPrinter(f *cliFlags) *printer.Printer {
	out := f.Out
	errOut := f.Err
	if out == nil {
		out = os.Stdout
	}
	if errOut == nil {
		errOut = os.Stderr
	}
	return printer.NewWithWriters(printer.Format(f.Output), out, errOut)
}

func warnAuditFailure(f *cliFlags, err error) {
	writer := io.Writer(os.Stderr)
	if f != nil && f.Err != nil {
		writer = f.Err
	}
	auditWarningMu.Lock()
	defer auditWarningMu.Unlock()
	_, _ = fmt.Fprintf(writer, "warning: failed to write audit log: %v\n", err)
}

func requireExactArgs(name string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("%s requires 1 argument(s)", name), nil)
		}
		return nil
	}
}

func currentOperator(f *cliFlags) string {
	operator, _ := trustedOperator(f)
	return operator
}

func trustedOperator(f *cliFlags) (string, error) {
	if strings.TrimSpace(f.trustedOperator) != "" {
		return f.trustedOperator, nil
	}
	resolver := f.resolveOperator
	if resolver == nil {
		resolver = resolveOSOperator
	}
	operator, err := resolver()
	if err != nil {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "trusted local operator identity is unavailable", err)
	}
	operator = strings.TrimSpace(operator)
	if operator == "" {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "trusted local operator identity is unavailable", nil)
	}
	f.trustedOperator = operator
	return operator, nil
}

func resolveOSOperator() (string, error) {
	current, err := osuser.Current()
	if err != nil {
		return "", err
	}
	if current == nil || strings.TrimSpace(current.Username) == "" {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "local OS username is unavailable", nil)
	}
	hostname, err := os.Hostname()
	if err != nil {
		return "", err
	}
	hostname = strings.TrimSpace(hostname)
	if hostname == "" {
		return "", apperrors.New(apperrors.CodeAuthorizationRequired, "local hostname is unavailable", nil)
	}
	return strings.TrimSpace(current.Username) + "@" + hostname, nil
}
