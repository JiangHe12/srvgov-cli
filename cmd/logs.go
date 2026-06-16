package cmd

import (
	"context"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/redact"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

type logsMeta struct {
	Backend        string `json:"backend"`
	Unit           string `json:"unit"`
	File           string `json:"file"`
	Since          string `json:"since"`
	Priority       string `json:"priority"`
	Grep           string `json:"grep"`
	RequestedLines int    `json:"requestedLines"`
	ReturnedLines  int    `json:"returnedLines"`
}

type logsView struct {
	Lines []observe.LogLine `json:"lines"`
	Meta  logsMeta          `json:"meta"`
}

func newLogsCmd(f *cliFlags) *cobra.Command {
	opts := observe.LogOptions{}
	flags := fanoutFlags{Concurrency: defaultFanoutConcurrency}
	command := &cobra.Command{
		Use:   "logs",
		Short: "Show structured journal or file logs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runLogs(cmd, f, opts, flags)
		},
	}
	command.Flags().StringVar(&opts.Unit, "unit", "", "systemd unit name")
	command.Flags().StringVar(&opts.File, "file", "", "log file path")
	command.Flags().StringVar(&opts.Since, "since", "", "journal start time")
	command.Flags().IntVar(&opts.Lines, "lines", 100, "maximum log lines")
	command.Flags().StringVar(&opts.Priority, "priority", "", "journal priority filter")
	command.Flags().StringVar(&opts.Grep, "grep", "", "literal log text filter")
	bindFanoutFlags(command, &flags)
	return command
}

func runLogs(cmd *cobra.Command, f *cliFlags, opts observe.LogOptions, flags fanoutFlags) error {
	if err := validateLogOptions(opts); err != nil {
		return err
	}
	if fanoutRequested(cmd) {
		targets, err := loadFanoutTargetsForCommand(cmd, flags)
		if err != nil {
			return err
		}
		if err := requireFanoutR0(targets, logCandidateCommands(opts)); err != nil {
			return err
		}
		results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
			return runLogsForTarget(cmd, f, target.Value, target.Name, opts)
		})
		return printFanout(cmd, f, buildFanoutView(targets, flags.Concurrency, results))
	}
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	view, err := runLogsForTarget(cmd, f, *item, contextName, opts)
	if err != nil {
		return err
	}
	return printLogs(f, view)
}

func runLogsForTarget(cmd *cobra.Command, f *cliFlags, item srvgovctx.Context, contextName string, opts observe.LogOptions) (logsView, error) {
	var (
		lines   []observe.LogLine
		backend string
		err     error
	)
	if opts.File != "" {
		lines, backend, err = collectFileLogs(cmd, f, item, contextName, opts)
	} else {
		lines, backend, err = collectJournalLogs(cmd, f, item, contextName, opts)
	}
	if err != nil {
		return logsView{}, err
	}

	return logsView{
		Lines: lines,
		Meta: logsMeta{
			Backend:        backend,
			Unit:           redact.String(opts.Unit),
			File:           redact.String(opts.File),
			Since:          redact.String(opts.Since),
			Priority:       redact.String(opts.Priority),
			Grep:           redact.String(opts.Grep),
			RequestedLines: opts.Lines,
			ReturnedLines:  len(lines),
		},
	}, nil
}

func logCandidateCommands(opts observe.LogOptions) []string {
	if opts.File != "" {
		return []string{observe.FileCommand(opts)}
	}
	commands := []string{observe.JournalCommand(opts)}
	if opts.Unit != "" {
		commands = append(commands, observe.SystemctlCommand(opts))
	}
	return commands
}

func validateLogOptions(opts observe.LogOptions) error {
	if opts.Lines <= 0 || opts.Lines > 10000 {
		return apperrors.New(apperrors.CodeUsageError, "--lines must be between 1 and 10000", nil)
	}
	if opts.File != "" && (opts.Unit != "" || opts.Since != "" || opts.Priority != "") {
		return apperrors.New(apperrors.CodeUsageError, "--file cannot be combined with --unit, --since, or --priority", nil)
	}
	return nil
}

func collectFileLogs(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName string,
	opts observe.LogOptions,
) ([]observe.LogLine, string, error) {
	return collectTextLogs(
		cmd,
		f,
		item,
		contextName,
		observe.FileCommand(opts),
		opts.Grep,
		"tail",
		"tail is not available on the target",
		"log file not found or unreadable: "+redact.String(opts.File),
	)
}

func collectJournalLogs(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName string,
	opts observe.LogOptions,
) ([]observe.LogLine, string, error) {
	command := observe.JournalCommand(opts)
	result, _, err := runGovernedCommand(cmd, f, item, contextName, command, "", false, srvgovaudit.EventTypeLogsObserve)
	if err == nil {
		return observe.ParseJournal(result.Stdout), "journalctl", nil
	}
	if !commandUnavailable(result) {
		return nil, "", err
	}
	if opts.Unit == "" {
		return nil, "", apperrors.New(apperrors.CodeResourceNotFound, "journalctl is unavailable", nil)
	}
	return collectSystemctlLogs(cmd, f, item, contextName, opts)
}

func collectSystemctlLogs(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName string,
	opts observe.LogOptions,
) ([]observe.LogLine, string, error) {
	return collectTextLogs(
		cmd,
		f,
		item,
		contextName,
		observe.SystemctlCommand(opts),
		opts.Grep,
		"systemctl",
		"journalctl and systemctl are unavailable",
		"",
	)
}

func collectTextLogs(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName, command, grep, backend, missingMessage, targetErrorMessage string,
) ([]observe.LogLine, string, error) {
	result, _, err := runGovernedCommand(cmd, f, item, contextName, command, "", false, srvgovaudit.EventTypeLogsObserve)
	if err == nil {
		return observe.ParseFileLines(result.Stdout, grep), backend, nil
	}
	if commandUnavailable(result) {
		return nil, "", apperrors.New(apperrors.CodeResourceNotFound, missingMessage, nil)
	}
	if targetErrorMessage != "" {
		return nil, "", apperrors.New(apperrors.CodeResourceNotFound, targetErrorMessage, nil)
	}
	return nil, "", err
}

func printLogs(f *cliFlags, value logsView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("Logs", value)
	}
	p.KV([][2]string{
		{"Backend", value.Meta.Backend},
		{"Unit", value.Meta.Unit},
		{"File", value.Meta.File},
		{"Since", value.Meta.Since},
		{"Priority", value.Meta.Priority},
		{"Grep", value.Meta.Grep},
		{"Requested Lines", strconv.Itoa(value.Meta.RequestedLines)},
		{"Returned Lines", strconv.Itoa(value.Meta.ReturnedLines)},
	})
	rows := make([][]string, 0, len(value.Lines))
	for _, line := range value.Lines {
		rows = append(rows, []string{line.Timestamp, line.Hostname, line.Unit, line.Priority, line.Message})
	}
	p.Table([]string{"TIMESTAMP", "HOSTNAME", "UNIT", "PRIORITY", "MESSAGE"}, rows)
	return nil
}

func commandUnavailable(result sshexec.Result) bool {
	if result.ExitCode == 127 {
		return true
	}
	message := strings.ToLower(result.Stderr)
	return strings.Contains(message, "command not found")
}
