package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/redact"
	"github.com/JiangHe12/opskit-core/v2/safety"

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
	expect int64
}

type fileWriteTargetBinding struct {
	ResolvedDirectory string
	Base              string
	DirectoryIdentity string
}

var resolveFileWriteTargetForCommand = resolveFileWriteTarget

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
				if maxBytes <= 0 || maxBytes > maxFileReadMaxBytes {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("--max-bytes must be between 1 and %d", maxFileReadMaxBytes), nil)
				}
				if contentSet && len(content) > maxBytes {
					return fileWriteLimitError(maxBytes)
				}
				if !dryRun && !contentSet && !f.Yes {
					return apperrors.New(apperrors.CodeUsageError, "reading content from stdin requires --yes", nil)
				}
				if fanoutRequested(cmd) {
					return runFileWriteFanout(cmd, f, flags, args[1], content, contentSet, reason, allow, dryRun, maxBytes)
				}
				if dryRun {
					return runFileWriteDryRun(cmd, f, args[1])
				}
				return runFileWrite(cmd, f, args[1], content, contentSet, reason, allow, maxBytes)
			default:
				return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("unsupported file action %q", args[0]), nil)
			}
		},
	}
	command.Flags().IntVar(&maxBytes, "max-bytes", defaultFileReadMaxBytes, "Maximum bytes read or written")
	command.Flags().StringVar(&content, "content", "", "Literal content for file write; takes precedence over stdin")
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed file write")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 file write")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Classify and show required authorization; file writes inspect the remote parent path")
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

func runFileWriteDryRun(cmd *cobra.Command, f *cliFlags, target string) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	binding, err := resolveFileWriteTargetForCommand(cmd, f, *item, contextName, target)
	if err != nil {
		return err
	}
	command := binding.policyCommand()
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
	maxBytes int,
) error {
	targets, err := loadFanoutTargetsForCommand(cmd, flags)
	if err != nil {
		return err
	}
	bindings := make(map[string]fileWriteTargetBinding, len(targets))
	plans := make([]governedFanoutPlan, 0, len(targets))
	maxEffective := safety.R0
	for _, target := range targets {
		binding, resolveErr := resolveFileWriteTargetForCommand(cmd, f, target.Value, target.Name, path)
		if resolveErr != nil {
			return resolveErr
		}
		bindings[target.Name] = binding
		risk := classifyGovernedCommand(target.Value, target.Name, binding.policyCommand())
		if risk.Effective > maxEffective {
			maxEffective = risk.Effective
		}
		plans = append(plans, governedFanoutPlan{Target: target, Risk: risk, PolicyCommand: binding.policyCommand()})
	}
	policyCommand := fileWritePolicyCommand(path)
	if dryRun {
		return printFanoutDryRun(cmd, f, targets, flags.Concurrency, plans, policyCommand, maxEffective)
	}
	if err := authorizeGovernedFanout(cmd, f, plans, policyCommand, reason, allow, maxEffective); err != nil {
		return err
	}
	var source io.Reader
	if contentSet {
		source = strings.NewReader(content)
	} else {
		source = cmd.InOrStdin()
	}
	data, err := readFileWriteInput(source, maxBytes)
	if err != nil {
		return err
	}
	batchAudit, err := beginFanoutMutationAudit(
		f,
		targets,
		string(srvgovaudit.EventTypeFileWrite),
		fileWriteBatchAuditPayload(path, data),
		reason,
		maxEffective,
	)
	if err != nil {
		return err
	}
	results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
		targetFlags := *f
		targetFlags.NonInteractive = true
		binding := bindings[target.Name]
		command := fileWriteCommand(binding, maxBytes, data)
		tracker := newFileWriteTracker(data)
		result, runErr := runGovernedCommandWithStdin(
			cmd,
			&targetFlags,
			target.Value,
			target.Name,
			binding.policyCommand(),
			reason,
			allow,
			func() (io.Reader, string, error) { return tracker, command, nil },
			func() *srvgovaudit.FileInfo { return tracker.fileInfo(binding.resolvedTarget()) },
			func() error { return tracker.validate(maxBytes) },
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
	if err := finishFanoutMutationAudit(batchAudit, results); err != nil {
		return err
	}
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
	maxBytes int,
) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	binding, err := resolveFileWriteTargetForCommand(cmd, f, *item, contextName, path)
	if err != nil {
		return err
	}
	source := cmd.InOrStdin()
	if contentSet {
		source = strings.NewReader(content)
	}
	var tracker *fileWriteTracker
	result, runErr := runGovernedCommandWithStdin(
		cmd,
		f,
		*item,
		contextName,
		binding.policyCommand(),
		reason,
		allow,
		func() (io.Reader, string, error) {
			data, readErr := readFileWriteInput(source, maxBytes)
			if readErr != nil {
				return nil, "", readErr
			}
			tracker = newFileWriteTracker(data)
			return tracker, fileWriteCommand(binding, maxBytes, data), nil
		},
		func() *srvgovaudit.FileInfo { return tracker.fileInfo(binding.resolvedTarget()) },
		func() error { return tracker.validate(maxBytes) },
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

func newFileWriteTracker(data []byte) *fileWriteTracker {
	return &fileWriteTracker{
		reader: bytes.NewReader(data),
		hash:   sha256.New(),
		expect: int64(len(data)),
	}
}

func (t *fileWriteTracker) fileInfo(path string) *srvgovaudit.FileInfo {
	return &srvgovaudit.FileInfo{
		Path:         path,
		BytesWritten: t.bytes,
		SHA256:       hex.EncodeToString(t.hash.Sum(nil)),
	}
}

func (t *fileWriteTracker) validate(maxBytes int) error {
	if t.bytes > int64(maxBytes) {
		return fileWriteLimitError(maxBytes)
	}
	if t.bytes != t.expect {
		return apperrors.New(
			apperrors.CodePartialFailure,
			fmt.Sprintf("SSH consumed %d of %d file-content bytes", t.bytes, t.expect),
			nil,
		)
	}
	return nil
}

func readFileWriteInput(source io.Reader, maxBytes int) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(source, int64(maxBytes)+1))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read file content from stdin", err)
	}
	if len(data) > maxBytes {
		return nil, fileWriteLimitError(maxBytes)
	}
	return data, nil
}

func fileWriteLimitError(maxBytes int) error {
	return apperrors.New(
		apperrors.CodeValidationFailed,
		fmt.Sprintf("file content exceeds --max-bytes (%d)", maxBytes),
		nil,
	)
}

func resolveFileWriteTarget(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName, target string,
) (fileWriteTargetBinding, error) {
	directory, base, err := splitRemoteFileWriteTarget(target)
	if err != nil {
		return fileWriteTargetBinding{}, err
	}
	resolvedResult, _, err := runGovernedCommand(
		cmd,
		f,
		item,
		contextName,
		fileWriteResolveDirectoryCommand(directory),
		"",
		false,
		srvgovaudit.EventTypeFileStat,
	)
	if err != nil {
		return fileWriteTargetBinding{}, err
	}
	resolvedDirectory, err := parseResolvedFileWriteDirectory(resolvedResult.Stdout)
	if err != nil {
		return fileWriteTargetBinding{}, err
	}
	identityResult, _, err := runGovernedCommand(
		cmd,
		f,
		item,
		contextName,
		fileWriteDirectoryIdentityCommand(resolvedDirectory),
		"",
		false,
		srvgovaudit.EventTypeFileStat,
	)
	if err != nil {
		return fileWriteTargetBinding{}, err
	}
	identity, err := parseFileWriteDirectoryIdentity(identityResult.Stdout)
	if err != nil {
		return fileWriteTargetBinding{}, err
	}
	return fileWriteTargetBinding{
		ResolvedDirectory: resolvedDirectory,
		Base:              base,
		DirectoryIdentity: identity,
	}, nil
}

func splitRemoteFileWriteTarget(target string) (string, string, error) {
	if target == "" || len(target) > 4096 || containsControlCharacter(target) {
		return "", "", apperrors.New(apperrors.CodeValidationFailed, "invalid remote file target", nil)
	}
	separator := strings.LastIndexByte(target, '/')
	directory := "."
	base := target
	if separator >= 0 {
		directory = target[:separator]
		base = target[separator+1:]
		if directory == "" {
			directory = "/"
		}
	}
	if base == "" || base == "." || base == ".." || strings.ContainsRune(base, '/') {
		return "", "", apperrors.New(apperrors.CodeValidationFailed, "invalid remote file target basename", nil)
	}
	return directory, base, nil
}

func parseResolvedFileWriteDirectory(output string) (string, error) {
	value, err := parseFileWritePreflightLine(output, "resolved remote file directory")
	if err != nil {
		return "", err
	}
	if !strings.HasPrefix(value, "/") || path.Clean(value) != value {
		return "", apperrors.New(apperrors.CodeValidationFailed, "remote file parent did not resolve to a canonical absolute directory", nil)
	}
	return value, nil
}

func parseFileWriteDirectoryIdentity(output string) (string, error) {
	value, err := parseFileWritePreflightLine(output, "remote file directory identity")
	if err != nil {
		return "", err
	}
	parts := strings.Split(value, ":")
	if len(parts) != 2 || !decimalToken(parts[0]) || !decimalToken(parts[1]) {
		return "", apperrors.New(apperrors.CodeValidationFailed, "remote file parent returned an invalid directory identity", nil)
	}
	return value, nil
}

func parseFileWritePreflightLine(output, field string) (string, error) {
	value := strings.TrimSuffix(output, "\n")
	if value == "" || strings.ContainsRune(value, '\n') || containsControlCharacter(value) {
		return "", apperrors.New(apperrors.CodeValidationFailed, field+" is invalid", nil)
	}
	return value, nil
}

func containsControlCharacter(value string) bool {
	for _, char := range value {
		if char < 0x20 || char == 0x7f {
			return true
		}
	}
	return false
}

func decimalToken(value string) bool {
	if value == "" || len(value) > 32 {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
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

func fileWritePolicyCommand(path string) string {
	return "tee -- " + observe.ShellQuote(path)
}

func fileWriteResolveDirectoryCommand(directory string) string {
	return "readlink -f -- " + observe.ShellQuote(directory)
}

func fileWriteDirectoryIdentityCommand(directory string) string {
	return "stat -Lc '%d:%i' -- " + observe.ShellQuote(directory)
}

func (binding fileWriteTargetBinding) resolvedTarget() string {
	return path.Join(binding.ResolvedDirectory, binding.Base)
}

func (binding fileWriteTargetBinding) policyCommand() string {
	return fileWritePolicyCommand(binding.resolvedTarget())
}

func fileWriteBatchAuditPayload(target string, data []byte) string {
	digest := sha256.Sum256(data)
	return target + "\x00" + strconv.Itoa(len(data)) + "\x00" + hex.EncodeToString(digest[:])
}

const atomicFileWriteScript = `set -eu
directory=$1
base=$2
expected_directory_id=$3
limit=$4
expected_size=$5
expected_sha256=$6
case "$base" in ''|.|..|*/*) exit 64 ;; esac
if [ -z "$directory" ] || [ -L "$directory" ] || [ ! -d "$directory" ]; then
	printf '%s\n' 'srvgov: invalid file target' >&2
	exit 64
fi
directory_id=$(stat -Lc '%d:%i' -- "$directory") || exit 68
if [ "$directory_id" != "$expected_directory_id" ]; then
	printf '%s\n' 'srvgov: file target directory changed before write' >&2
	exit 68
fi
cd -P -- "$directory" || exit 68
bound_directory_id=$(stat -Lc '%d:%i' -- .) || exit 68
if [ "$bound_directory_id" != "$expected_directory_id" ]; then
	printf '%s\n' 'srvgov: file target directory changed while binding' >&2
	exit 68
fi
target=./$base
if [ -L "$target" ] || { [ -e "$target" ] && [ ! -f "$target" ]; }; then
	printf '%s\n' 'srvgov: target must be a regular file or absent' >&2
  exit 65
fi
existed=false
target_id=
target_uid=
target_gid=
target_mode=
if [ -e "$target" ]; then
  existed=true
  target_id=$(stat -c '%d:%i' -- "$target")
  target_uid=$(stat -c '%u' -- "$target")
  target_gid=$(stat -c '%g' -- "$target")
  target_mode=$(stat -c '%a' -- "$target")
fi
tmp=$(mktemp "./.${base}.srvgov.XXXXXX")
cleanup() { rm -f -- "$tmp"; }
trap cleanup 0
trap 'exit 70' HUP INT TERM
head -c "$((limit + 1))" > "$tmp"
size=$(wc -c < "$tmp")
if [ "$size" -gt "$limit" ] || [ "$size" -ne "$expected_size" ]; then
  printf '%s\n' 'srvgov: file content length mismatch' >&2
  exit 66
fi
actual_sha256=$(sha256sum "$tmp")
actual_sha256=${actual_sha256%% *}
if [ "$actual_sha256" != "$expected_sha256" ]; then
  printf '%s\n' 'srvgov: file content digest mismatch' >&2
  exit 66
fi
if [ "$existed" = true ]; then
  if cp --help 2>&1 | grep -q -- '--attributes-only'; then
    cp --attributes-only --preserve=mode,ownership,xattr -- "$target" "$tmp"
  else
    chown "$target_uid:$target_gid" "$tmp"
    chmod "$target_mode" "$tmp"
  fi
fi
if [ "$existed" = true ]; then
  current_id=$(stat -c '%d:%i' -- "$target")
  current_uid=$(stat -c '%u' -- "$target")
  current_gid=$(stat -c '%g' -- "$target")
  current_mode=$(stat -c '%a' -- "$target")
  if [ "$current_id" != "$target_id" ] ||
     [ "$current_uid" != "$target_uid" ] ||
     [ "$current_gid" != "$target_gid" ] ||
     [ "$current_mode" != "$target_mode" ] ||
     [ -L "$target" ] ||
     [ ! -f "$target" ]; then
    printf '%s\n' 'srvgov: target changed during file write' >&2
    exit 67
  fi
elif [ -e "$target" ] || [ -L "$target" ]; then
	printf '%s\n' 'srvgov: target appeared during file write' >&2
	exit 67
fi
current_directory_id=$(stat -Lc '%d:%i' -- "$directory") || exit 68
if [ "$current_directory_id" != "$expected_directory_id" ]; then
	printf '%s\n' 'srvgov: file target directory changed before commit' >&2
	exit 68
fi
mv -fT -- "$tmp" "$target"
trap - 0
exit 0`

func atomicFileWriteExitIsDefiniteFailure(exitCode int) bool {
	return exitCode >= 64 && exitCode <= 68
}

func fileWriteCommand(binding fileWriteTargetBinding, maxBytes int, data []byte) string {
	digest := sha256.Sum256(data)
	return "sh -c " + observe.ShellQuote(atomicFileWriteScript) +
		" srvgov-file-write " + observe.ShellQuote(binding.ResolvedDirectory) +
		" " + observe.ShellQuote(binding.Base) +
		" " + observe.ShellQuote(binding.DirectoryIdentity) +
		" " + strconv.Itoa(maxBytes) +
		" " + strconv.Itoa(len(data)) +
		" " + hex.EncodeToString(digest[:])
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
	return p.KV([][2]string{
		{"Path", value.Path},
		{"Bytes", strconv.Itoa(value.Bytes)},
		{"Truncated", strconv.FormatBool(value.Truncated)},
		{"Content", value.Content},
	})
}

func printFileStat(f *cliFlags, value fileStatView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("FileStat", value)
	}
	return p.KV([][2]string{
		{"Path", value.Path},
		{"Type", value.Type},
		{"Size", strconv.FormatInt(value.Size, 10)},
		{"Mode", value.Mode},
		{"Owner", value.Owner},
		{"Group", value.Group},
		{"Mtime", value.Mtime},
	})
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
	return p.Table([]string{"NAME", "TYPE", "SIZE", "MODE", "MTIME"}, rows)
}

func printFileWrite(f *cliFlags, value fileWriteView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("FileWrite", value)
	}
	return p.KV([][2]string{
		{"Path", value.Path},
		{"Bytes Written", strconv.FormatInt(value.BytesWritten, 10)},
		{"Success", strconv.FormatBool(value.Success)},
	})
}
