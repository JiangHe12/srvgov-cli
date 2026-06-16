package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/redact"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

const (
	defaultFileReadMaxBytes = 1024 * 1024
	maxFileReadMaxBytes     = 16 * 1024 * 1024
)

type fileReadView struct {
	Path      string `json:"path"`
	Content   string `json:"content"`
	Bytes     int    `json:"bytes"`
	Truncated bool   `json:"truncated"`
}

type fileStatView struct {
	Path  string `json:"path"`
	Type  string `json:"type"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	Owner string `json:"owner"`
	Group string `json:"group"`
	Mtime string `json:"mtime"`
}

type fileListItem struct {
	Name  string `json:"name"`
	Type  string `json:"type"`
	Size  int64  `json:"size"`
	Mode  string `json:"mode"`
	Mtime string `json:"mtime"`
}

type fileWriteView struct {
	Path         string `json:"path"`
	BytesWritten int64  `json:"bytesWritten"`
	Success      bool   `json:"success"`
}

type fileWriteTracker struct {
	reader io.Reader
	hash   hash.Hash
	bytes  int64
}

func newFileCmd(f *cliFlags) *cobra.Command {
	var (
		maxBytes int
		content  string
		reason   string
		allow    bool
		dryRun   bool
		flags    fanoutFlags
	)
	command := &cobra.Command{
		Use:   "file <read|stat|list|write> <path>",
		Short: "Read, inspect, list, or write one remote path",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) != 2 {
				return apperrors.New(apperrors.CodeUsageError, "file requires an action and one path", nil)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			action := strings.ToLower(args[0])
			contentSet := cmd.Flags().Changed("content")
			switch action {
			case "read":
				if contentSet {
					return apperrors.New(apperrors.CodeUsageError, "--content is only valid with file write", nil)
				}
				if maxBytes <= 0 || maxBytes > maxFileReadMaxBytes {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("--max-bytes must be between 1 and %d", maxFileReadMaxBytes), nil)
				}
				if fanoutRequested(cmd) {
					return runFileReadFanout(cmd, f, flags, action, args[1], maxBytes, dryRun)
				}
				if dryRun {
					return runFileDryRun(f, fileReadCommand(args[1], maxBytes))
				}
				return runFileRead(cmd, f, args[1], maxBytes)
			case "stat":
				if contentSet {
					return apperrors.New(apperrors.CodeUsageError, "--content is only valid with file write", nil)
				}
				if fanoutRequested(cmd) {
					return runFileReadFanout(cmd, f, flags, action, args[1], maxBytes, dryRun)
				}
				if dryRun {
					return runFileDryRun(f, fileStatCommand(args[1]))
				}
				return runFileStat(cmd, f, args[1])
			case "list":
				if contentSet {
					return apperrors.New(apperrors.CodeUsageError, "--content is only valid with file write", nil)
				}
				if fanoutRequested(cmd) {
					return runFileReadFanout(cmd, f, flags, action, args[1], maxBytes, dryRun)
				}
				if dryRun {
					return runFileDryRun(f, fileListCommand(args[1]))
				}
				return runFileList(cmd, f, args[1])
			case "write":
				if !dryRun && !contentSet && !f.Yes {
					return apperrors.New(apperrors.CodeUsageError, "reading content from stdin requires --yes", nil)
				}
				if fanoutRequested(cmd) {
					return runFileWriteFanout(cmd, f, flags, args[1], content, contentSet, reason, allow, dryRun)
				}
				if dryRun {
					return runFileDryRun(f, fileWriteCommand(args[1]))
				}
				return runFileWrite(cmd, f, args[1], content, contentSet, reason, allow)
			default:
				return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("unsupported file action %q", args[0]), nil)
			}
		},
	}
	command.Flags().IntVar(&maxBytes, "max-bytes", defaultFileReadMaxBytes, "Maximum bytes returned by file read")
	command.Flags().StringVar(&content, "content", "", "Literal content for file write; takes precedence over stdin")
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed file write")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 file write")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Classify and show required authorization without connecting")
	bindFanoutFlags(command, &flags)
	return command
}

func runFileDryRun(f *cliFlags, command string) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	risk := classifyGovernedCommand(*item, contextName, command)
	return printExecDryRun(f, contextName, *item, command, risk.Base, risk.Effective)
}

func runFileReadFanout(
	cmd *cobra.Command,
	f *cliFlags,
	flags fanoutFlags,
	action, path string,
	maxBytes int,
	dryRun bool,
) error {
	if action == "read" && (maxBytes <= 0 || maxBytes > maxFileReadMaxBytes) {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("--max-bytes must be between 1 and %d", maxFileReadMaxBytes), nil)
	}
	targets, err := loadFanoutTargetsForCommand(cmd, flags)
	if err != nil {
		return err
	}
	command, eventType, tool := fileReadGovernedCommand(action, path, maxBytes)
	plans, maxEffective := planGovernedFanout(targets, command)
	if dryRun {
		return printFanoutDryRun(cmd, f, targets, flags.Concurrency, plans, command, maxEffective)
	}
	if err := authorizeGovernedFanout(cmd, f, plans, command, "", false, maxEffective); err != nil {
		return err
	}
	results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
		targetFlags := *f
		targetFlags.NonInteractive = true
		result, runErr := runFileReadCommandTarget(cmd, &targetFlags, target.Value, target.Name, path, command, eventType, tool)
		if runErr != nil {
			return nil, runErr
		}
		return fileReadData(action, path, maxBytes, result.Stdout)
	})
	return printFanout(cmd, f, buildFanoutView(targets, flags.Concurrency, results))
}

func fileReadGovernedCommand(action, path string, maxBytes int) (string, srvgovaudit.EventType, string) {
	switch action {
	case "read":
		return fileReadCommand(path, maxBytes), srvgovaudit.EventTypeFileRead, "head"
	case "stat":
		return fileStatCommand(path), srvgovaudit.EventTypeFileStat, "stat"
	default:
		return fileListCommand(path), srvgovaudit.EventTypeFileList, "find"
	}
}

func fileReadData(action, path string, maxBytes int, output string) (any, error) {
	switch action {
	case "read":
		data := []byte(output)
		truncated := len(data) > maxBytes
		if truncated {
			data = data[:maxBytes]
		}
		return fileReadView{
			Path:      redact.String(path),
			Content:   redact.String(string(data)),
			Bytes:     len(data),
			Truncated: truncated,
		}, nil
	case "stat":
		return parseFileStat(path, output)
	default:
		return parseFileList(output)
	}
}

func runFileWriteFanout(
	cmd *cobra.Command,
	f *cliFlags,
	flags fanoutFlags,
	path, content string,
	contentSet bool,
	reason string,
	allow, dryRun bool,
) error {
	targets, err := loadFanoutTargetsForCommand(cmd, flags)
	if err != nil {
		return err
	}
	command := fileWriteCommand(path)
	plans, maxEffective := planGovernedFanout(targets, command)
	if dryRun {
		return printFanoutDryRun(cmd, f, targets, flags.Concurrency, plans, command, maxEffective)
	}
	if err := authorizeGovernedFanout(cmd, f, plans, command, reason, allow, maxEffective); err != nil {
		return err
	}
	var data []byte
	if contentSet {
		data = []byte(content)
	} else {
		data, err = io.ReadAll(cmd.InOrStdin())
		if err != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to read file content from stdin", err)
		}
	}
	results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
		targetFlags := *f
		targetFlags.NonInteractive = true
		tracker := &fileWriteTracker{reader: bytes.NewReader(data), hash: sha256.New()}
		result, runErr := runGovernedCommandWithStdin(
			cmd,
			&targetFlags,
			target.Value,
			target.Name,
			command,
			reason,
			allow,
			tracker,
			func() *srvgovaudit.FileInfo { return tracker.fileInfo(path) },
		)
		if runErr != nil && result.ExitCode == 0 {
			return nil, runErr
		}
		return fileWriteView{
			Path:         redact.String(path),
			BytesWritten: tracker.bytes,
			Success:      runErr == nil,
		}, runErr
	})
	return printFanout(cmd, f, buildFanoutView(targets, flags.Concurrency, results))
}

func runFileRead(cmd *cobra.Command, f *cliFlags, path string, maxBytes int) error {
	if maxBytes <= 0 || maxBytes > maxFileReadMaxBytes {
		return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("--max-bytes must be between 1 and %d", maxFileReadMaxBytes), nil)
	}
	result, err := runFileReadCommand(cmd, f, path, fileReadCommand(path, maxBytes), srvgovaudit.EventTypeFileRead, "head")
	if err != nil {
		return err
	}
	data := []byte(result.Stdout)
	truncated := len(data) > maxBytes
	if truncated {
		data = data[:maxBytes]
	}
	return printFileRead(f, fileReadView{
		Path:      redact.String(path),
		Content:   redact.String(string(data)),
		Bytes:     len(data),
		Truncated: truncated,
	})
}

func runFileStat(cmd *cobra.Command, f *cliFlags, path string) error {
	result, err := runFileReadCommand(cmd, f, path, fileStatCommand(path), srvgovaudit.EventTypeFileStat, "stat")
	if err != nil {
		return err
	}
	value, err := parseFileStat(path, result.Stdout)
	if err != nil {
		return err
	}
	return printFileStat(f, value)
}

func runFileList(cmd *cobra.Command, f *cliFlags, path string) error {
	result, err := runFileReadCommand(cmd, f, path, fileListCommand(path), srvgovaudit.EventTypeFileList, "find")
	if err != nil {
		return err
	}
	items, err := parseFileList(result.Stdout)
	if err != nil {
		return err
	}
	return printFileList(f, items)
}

func runFileReadCommand(
	cmd *cobra.Command,
	f *cliFlags,
	path, command string,
	eventType srvgovaudit.EventType,
	tool string,
) (sshexec.Result, error) {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return sshexec.Result{}, err
	}
	return runFileReadCommandTarget(cmd, f, *item, contextName, path, command, eventType, tool)
}

func runFileReadCommandTarget(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName, path, command string,
	eventType srvgovaudit.EventType,
	tool string,
) (sshexec.Result, error) {
	result, _, runErr := runGovernedCommand(cmd, f, item, contextName, command, "", false, eventType)
	if runErr == nil {
		return result, nil
	}
	if commandUnavailable(result) {
		return sshexec.Result{}, apperrors.New(apperrors.CodeResourceNotFound, tool+" is not available on the target", nil)
	}
	if result.ExitCode != 0 {
		return sshexec.Result{}, apperrors.New(
			apperrors.CodeResourceNotFound,
			"file not found or unreadable: "+redact.String(path),
			nil,
		)
	}
	return sshexec.Result{}, runErr
}

func runFileWrite(
	cmd *cobra.Command,
	f *cliFlags,
	path, content string,
	contentSet bool,
	reason string,
	allow bool,
) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	source := cmd.InOrStdin()
	if contentSet {
		source = strings.NewReader(content)
	}
	tracker := &fileWriteTracker{reader: source, hash: sha256.New()}
	command := fileWriteCommand(path)
	result, runErr := runGovernedCommandWithStdin(
		cmd,
		f,
		*item,
		contextName,
		command,
		reason,
		allow,
		tracker,
		func() *srvgovaudit.FileInfo { return tracker.fileInfo(path) },
	)
	if runErr != nil && result.ExitCode == 0 {
		return runErr
	}
	view := fileWriteView{
		Path:         redact.String(path),
		BytesWritten: tracker.bytes,
		Success:      runErr == nil,
	}
	if err := printFileWrite(f, view); err != nil {
		return err
	}
	return runErr
}

func (t *fileWriteTracker) Read(buffer []byte) (int, error) {
	n, err := t.reader.Read(buffer)
	if n > 0 {
		_, _ = t.hash.Write(buffer[:n])
		t.bytes += int64(n)
	}
	return n, err
}

func (t *fileWriteTracker) fileInfo(path string) *srvgovaudit.FileInfo {
	return &srvgovaudit.FileInfo{
		Path:         path,
		BytesWritten: t.bytes,
		SHA256:       hex.EncodeToString(t.hash.Sum(nil)),
	}
}

func fileReadCommand(path string, maxBytes int) string {
	return fmt.Sprintf("head -c %d -- %s", maxBytes+1, observe.ShellQuote(path))
}

func fileStatCommand(path string) string {
	return "stat -c '%F\\t%s\\t%a\\t%U\\t%G\\t%Y' -- " + observe.ShellQuote(path)
}

func fileListCommand(path string) string {
	return "find " + observe.ShellQuote(path) +
		" -mindepth 1 -maxdepth 1 -printf '%f\\0%y\\0%s\\0%m\\0%T@\\0'"
}

func fileWriteCommand(path string) string {
	return "tee -- " + observe.ShellQuote(path)
}

func parseFileStat(path, output string) (fileStatView, error) {
	fields := strings.Split(strings.TrimSuffix(output, "\n"), "\t")
	if len(fields) != 6 {
		return fileStatView{}, apperrors.New(apperrors.CodeValidationFailed, "unable to parse stat output", nil)
	}
	size, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return fileStatView{}, apperrors.New(apperrors.CodeValidationFailed, "unable to parse stat size", err)
	}
	mtime, err := unixTime(fields[5])
	if err != nil {
		return fileStatView{}, err
	}
	return fileStatView{
		Path:  redact.String(path),
		Type:  redact.String(fields[0]),
		Size:  size,
		Mode:  redact.String(fields[2]),
		Owner: redact.String(fields[3]),
		Group: redact.String(fields[4]),
		Mtime: mtime,
	}, nil
}

func parseFileList(output string) ([]fileListItem, error) {
	if output == "" {
		return []fileListItem{}, nil
	}
	fields := strings.Split(output, "\x00")
	if fields[len(fields)-1] == "" {
		fields = fields[:len(fields)-1]
	}
	if len(fields)%5 != 0 {
		return nil, apperrors.New(apperrors.CodeValidationFailed, "unable to parse find output", nil)
	}
	items := make([]fileListItem, 0, len(fields)/5)
	for index := 0; index < len(fields); index += 5 {
		size, err := strconv.ParseInt(fields[index+2], 10, 64)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "unable to parse file-list size", err)
		}
		mtime, err := unixTime(fields[index+4])
		if err != nil {
			return nil, err
		}
		items = append(items, fileListItem{
			Name:  redact.String(fields[index]),
			Type:  fileType(fields[index+1]),
			Size:  size,
			Mode:  redact.String(fields[index+3]),
			Mtime: mtime,
		})
	}
	sort.Slice(items, func(i, j int) bool { return items[i].Name < items[j].Name })
	return items, nil
}

func unixTime(value string) (string, error) {
	seconds, err := strconv.ParseFloat(strings.TrimSpace(value), 64)
	if err != nil {
		return "", apperrors.New(apperrors.CodeValidationFailed, "unable to parse file mtime", err)
	}
	nanoseconds := int64(seconds * float64(time.Second))
	return time.Unix(0, nanoseconds).UTC().Format(time.RFC3339Nano), nil
}

func fileType(value string) string {
	switch value {
	case "f":
		return "file"
	case "d":
		return "directory"
	case "l":
		return "symlink"
	default:
		return "other"
	}
}

func printFileRead(f *cliFlags, value fileReadView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("FileRead", value)
	}
	p.KV([][2]string{
		{"Path", value.Path},
		{"Bytes", strconv.Itoa(value.Bytes)},
		{"Truncated", strconv.FormatBool(value.Truncated)},
		{"Content", value.Content},
	})
	return nil
}

func printFileStat(f *cliFlags, value fileStatView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("FileStat", value)
	}
	p.KV([][2]string{
		{"Path", value.Path},
		{"Type", value.Type},
		{"Size", strconv.FormatInt(value.Size, 10)},
		{"Mode", value.Mode},
		{"Owner", value.Owner},
		{"Group", value.Group},
		{"Mtime", value.Mtime},
	})
	return nil
}

func printFileList(f *cliFlags, items []fileListItem) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONList("FileList", items, len(items), 1, len(items), false)
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{
			item.Name,
			item.Type,
			strconv.FormatInt(item.Size, 10),
			item.Mode,
			item.Mtime,
		})
	}
	p.Table([]string{"NAME", "TYPE", "SIZE", "MODE", "MTIME"}, rows)
	return nil
}

func printFileWrite(f *cliFlags, value fileWriteView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("FileWrite", value)
	}
	p.KV([][2]string{
		{"Path", value.Path},
		{"Bytes Written", strconv.FormatInt(value.BytesWritten, 10)},
		{"Success", strconv.FormatBool(value.Success)},
	})
	return nil
}
