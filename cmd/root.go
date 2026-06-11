// Package cmd defines the srvgov command tree.
package cmd

import (
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/printer"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

type cliFlags struct {
	Output         string
	Config         string
	Context        string
	Operator       string
	Ticket         string
	Yes            bool
	NonInteractive bool
	Out            io.Writer
	Err            io.Writer
}

// NewRootCmd constructs the srvgov root command.
func NewRootCmd() *cobra.Command {
	return newRootCmdWith(&cliFlags{Output: "table"})
}

func newRootCmdWith(f *cliFlags) *cobra.Command {
	root := &cobra.Command{
		Use:           "srvgov",
		Short:         "Governed remote server operations for AI agents",
		Version:       version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRun: func(cmd *cobra.Command, _ []string) {
			f.Out = cmd.OutOrStdout()
			f.Err = cmd.ErrOrStderr()
			if f.Config != "" {
				srvgovctx.SetConfigPath(f.Config)
			}
		},
	}
	root.PersistentFlags().StringVarP(&f.Output, "output", "o", "table", "Output format: table | json | plain")
	root.PersistentFlags().StringVar(&f.Config, "config", "", "Temporarily override config file path")
	root.PersistentFlags().StringVar(&f.Context, "context", "", "Server context name (default current)")
	root.PersistentFlags().StringVar(&f.Operator, "operator", "", "Human operator identity")
	root.PersistentFlags().StringVar(&f.Ticket, "ticket", "", "Change ticket")
	root.PersistentFlags().BoolVar(&f.Yes, "yes", false, "Confirm an authorized change")
	root.PersistentFlags().BoolVar(&f.NonInteractive, "non-interactive", false, "Disable interactive authorization prompts")
	root.AddCommand(
		newContextCmd(f),
		newExecCmd(f),
		newStatusCmd(f),
		newPortsCmd(f),
		newLogsCmd(f),
		newAuditCmd(f),
		newDoctorCmd(f),
		newVersionCmd(f),
		newCapabilitiesCmd(f),
		newInstallCmd(f),
	)
	return root
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

func requireExactArgs(name string) cobra.PositionalArgs {
	return func(_ *cobra.Command, args []string) error {
		if len(args) != 1 {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("%s requires 1 argument(s)", name), nil)
		}
		return nil
	}
}
