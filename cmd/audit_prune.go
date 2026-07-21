package cmd

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/lockfile"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

type auditPruneOptions struct {
	path           string
	before         string
	keepLast       int
	dryRun         bool
	dryRunExplicit bool
	confirm        bool
}

type auditPruneResult struct {
	DryRun          bool                           `json:"dryRun"`
	Files           []string                       `json:"files"`
	Count           int                            `json:"count"`
	Started         bool                           `json:"started"`
	CheckpointState coreaudit.PruneCheckpointState `json:"checkpointState"`
}

func auditPruneCmd(f *cliFlags) *cobra.Command {
	opts := auditPruneOptions{keepLast: -1, dryRun: true}
	command := &cobra.Command{
		Use:   "prune",
		Short: "Prune rotated audit logs",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			opts.dryRunExplicit = cmd.Flags().Changed("dry-run")
			return runAuditPrune(cmd, f, opts)
		},
	}
	command.Flags().StringVar(&opts.path, "path", "", "Audit log path")
	command.Flags().StringVar(&opts.before, "before", "", "Prune rotated logs before this time (30d / RFC3339 / YYYY-MM-DD)")
	command.Flags().IntVar(&opts.keepLast, "keep-last", -1, "Keep the newest N rotated logs (0 = delete all rotated logs)")
	command.Flags().BoolVar(&opts.dryRun, "dry-run", true, "Preview matched rotated logs without deleting")
	command.Flags().BoolVar(&opts.confirm, "confirm", false, "Actually delete matched rotated logs")
	return command
}

func runAuditPrune(cmd *cobra.Command, f *cliFlags, opts auditPruneOptions) error { //nolint:gocyclo // Validation, preview, authorization, and checkpoint-aware pruning stay in execution order.
	if opts.dryRunExplicit && opts.dryRun && opts.confirm {
		return apperrors.New(apperrors.CodeUsageError, "audit prune accepts only one of --dry-run or --confirm", nil)
	}
	if opts.before == "" && opts.keepLast < 0 {
		return apperrors.New(apperrors.CodeUsageError, "audit prune requires --before or --keep-last", nil)
	}
	if opts.before != "" && opts.keepLast >= 0 {
		return apperrors.New(apperrors.CodeUsageError, "audit prune accepts only one of --before or --keep-last", nil)
	}
	if opts.keepLast < -1 {
		return apperrors.New(apperrors.CodeUsageError, "--keep-last must be >= 0", nil)
	}
	path, err := auditPath(opts.path)
	if err != nil {
		return err
	}
	path, err = normalizeAuditPruneTarget(f, path)
	if err != nil {
		return err
	}
	rotated, err := strictAuditRotatedFiles(path)
	if err != nil {
		return err
	}
	candidates, err := selectAuditPruneCandidates(path, opts, rotated)
	if err != nil {
		return err
	}
	preview := coreaudit.PruneResult{
		Candidates:      candidates,
		DeletedFiles:    []string{},
		CheckpointState: coreaudit.PruneCheckpointUnchanged,
	}
	if !opts.confirm {
		return printAuditPrune(f, auditPruneResult{
			DryRun:          true,
			Files:           preview.Candidates,
			Count:           len(preview.Candidates),
			Started:         preview.Started,
			CheckpointState: preview.CheckpointState,
		})
	}
	pruneResult := preview
	if err := withAuditPrunePolicyLock(func(policy srvgovctx.Context, policyName string) error {
		if err := authorizeControlChange(
			cmd,
			f,
			policy,
			policyName,
			"audit.prune",
			allowAuditPrune,
			f.AllowAuditPrune,
		); err != nil {
			return err
		}
		auditSink := auditPruneControlPath(path)
		auditHandle, err := beginMutationAudit(f, mutationAuditSpec{
			Action:      string(srvgovaudit.EventTypeAuditPrune),
			ContextName: policyName,
			Context:     policy,
			Target:      path,
			RiskTier:    "R3",
			Ticket:      f.Ticket,
			Metadata: mutationAuditMetadata{
				Items:   len(candidates),
				Deletes: len(candidates),
			},
			AuditPath: auditSink,
			Options:   coreAuditOptions(policy),
		})
		if err != nil {
			return err
		}
		confirmed, operationErr := coreaudit.PruneRotatedFiles(path, candidates, coreaudit.PruneOptions{
			Confirm:              true,
			ExpectedRotatedFiles: rotated,
		})
		pruneResult = confirmed
		outcome := auditPruneMutationOutcome(
			len(candidates),
			pruneResult,
			operationErr,
		)
		return finishMutationAudit(auditHandle, outcome, operationErr)
	}); err != nil {
		return err
	}
	return printAuditPrune(f, auditPruneResult{
		DryRun:          false,
		Files:           pruneResult.DeletedFiles,
		Count:           len(pruneResult.DeletedFiles),
		Started:         pruneResult.Started,
		CheckpointState: pruneResult.CheckpointState,
	})
}

func auditPruneControlPath(target string) string {
	return filepath.Join(filepath.Dir(target), "."+filepath.Base(target)+"-control")
}

func auditPruneMutationOutcome(
	total int,
	result coreaudit.PruneResult,
	operationErr error,
) mutationAuditOutcome {
	if total < 0 {
		total = 0
	}
	deleted := len(result.DeletedFiles)
	if deleted > total {
		deleted = total
	}
	outcome := mutationAuditOutcome{
		Status:    srvgovaudit.StatusSucceeded,
		Succeeded: deleted,
		Skipped:   total - deleted,
	}
	if operationErr == nil {
		return outcome
	}
	outcome.Status = srvgovaudit.StatusFailed
	if result.CheckpointState == coreaudit.PruneCheckpointIndeterminate {
		outcome.Uncertain = total - deleted
		outcome.Skipped = 0
		return outcome
	}
	if deleted < total {
		outcome.Failed = 1
		outcome.Skipped = total - deleted - 1
		if outcome.Skipped < 0 {
			outcome.Skipped = 0
		}
	}
	return outcome
}

func withAuditPrunePolicyLock(fn func(srvgovctx.Context, string) error) (retErr error) {
	configDir, err := corectx.ConfigDir()
	if err != nil {
		return err
	}
	if err := os.MkdirAll(configDir, 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create context config directory", err)
	}
	lock := lockfile.New(filepath.Join(configDir, "config"))
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() {
		if err := lock.Release(); err != nil && retErr == nil {
			retErr = apperrors.New(apperrors.CodeLocalIOError, "failed to release context config lock", err)
		}
	}()
	policy, policyName, err := currentAuditPrunePolicy()
	if err != nil {
		return err
	}
	return fn(policy, policyName)
}

func selectAuditPruneCandidates(path string, opts auditPruneOptions, rotated []string) ([]string, error) {
	if opts.keepLast >= 0 {
		if opts.keepLast >= len(rotated) {
			return []string{}, nil
		}
		return append([]string{}, rotated[:len(rotated)-opts.keepLast]...), nil
	}
	cutoff, err := parseAuditPruneBefore(opts.before, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	out := make([]string, 0, len(rotated))
	for _, filePath := range rotated {
		ts, _, ok := strictAuditRotatedFileOrder(path, filePath)
		if ok && ts.Before(cutoff) {
			out = append(out, filePath)
		}
	}
	return out, nil
}

type auditRotatedFile struct {
	path      string
	timestamp time.Time
	ordinal   uint64
}

func strictAuditRotatedFiles(path string) ([]string, error) {
	directory := filepath.Dir(path)
	entries, err := os.ReadDir(directory)
	if os.IsNotExist(err) {
		return []string{}, nil
	}
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to list rotated audit logs", err)
	}
	activeName := filepath.Base(path)
	rotated := make([]auditRotatedFile, 0)
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, activeName+".") || !strings.HasSuffix(name, ".log") {
			continue
		}
		candidate := filepath.Join(directory, name)
		timestamp, ordinal, ok := strictAuditRotatedFileOrder(path, candidate)
		if !ok {
			return nil, apperrors.New(
				apperrors.CodeValidationFailed,
				fmt.Sprintf("unexpected audit rotation filename %q; refusing prune", name),
				nil,
			)
		}
		info, err := os.Lstat(candidate)
		if err != nil {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect rotated audit log", err)
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, apperrors.New(
				apperrors.CodeValidationFailed,
				fmt.Sprintf("rotated audit log %q must be a real regular file", name),
				nil,
			)
		}
		rotated = append(rotated, auditRotatedFile{
			path:      candidate,
			timestamp: timestamp,
			ordinal:   ordinal,
		})
	}
	sort.Slice(rotated, func(i, j int) bool {
		if !rotated[i].timestamp.Equal(rotated[j].timestamp) {
			return rotated[i].timestamp.Before(rotated[j].timestamp)
		}
		if rotated[i].ordinal != rotated[j].ordinal {
			return rotated[i].ordinal < rotated[j].ordinal
		}
		return rotated[i].path < rotated[j].path
	})
	out := make([]string, len(rotated))
	for i := range rotated {
		out[i] = rotated[i].path
	}
	return out, nil
}

func strictAuditRotatedFileOrder(activePath, candidate string) (time.Time, uint64, bool) {
	if filepath.Clean(filepath.Dir(activePath)) != filepath.Clean(filepath.Dir(candidate)) {
		return time.Time{}, 0, false
	}
	activeName := filepath.Base(activePath)
	candidateName := filepath.Base(candidate)
	if !strings.HasPrefix(candidateName, activeName+".") || !strings.HasSuffix(candidateName, ".log") {
		return time.Time{}, 0, false
	}
	stem := strings.TrimSuffix(strings.TrimPrefix(candidateName, activeName+"."), ".log")
	parts := strings.Split(stem, ".")
	if len(parts) < 1 || len(parts) > 2 {
		return time.Time{}, 0, false
	}
	timestamp, err := time.Parse("20060102-150405", parts[0])
	if err != nil {
		return time.Time{}, 0, false
	}
	ordinal := uint64(0)
	if len(parts) == 2 {
		if parts[1] == "" || (len(parts[1]) > 1 && strings.HasPrefix(parts[1], "0")) {
			return time.Time{}, 0, false
		}
		ordinal, err = strconv.ParseUint(parts[1], 10, 64)
		if err != nil || ordinal == 0 {
			return time.Time{}, 0, false
		}
	}
	return timestamp.UTC(), ordinal, true
}

func currentAuditPrunePolicy() (srvgovctx.Context, string, error) {
	cfg, err := srvgovctx.Load()
	if err != nil {
		return srvgovctx.Context{}, "", err
	}
	if cfg.CurrentContext == "" {
		return srvgovctx.Context{}, "", nil
	}
	item, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok {
		return srvgovctx.Context{}, "", apperrors.New(
			apperrors.CodeValidationFailed,
			fmt.Sprintf("current context %q does not exist; refusing audit prune authorization", cfg.CurrentContext),
			nil,
		)
	}
	return item, cfg.CurrentContext, nil
}

func normalizeAuditPruneTarget(f *cliFlags, path string) (string, error) { //nolint:gocyclo // Alias and governed-state checks intentionally share one fail-closed boundary.
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return "", apperrors.New(apperrors.CodeLocalIOError, "audit prune target must be a real regular file", nil)
		}
	} else if !os.IsNotExist(err) {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit prune target", nil)
	}
	targetAbsolute, err := filepath.Abs(path)
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit prune path", nil)
	}
	defaultAudit, err := coreaudit.DefaultPath()
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve default audit path", err)
	}
	defaultAbsolute, err := filepath.Abs(defaultAudit)
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve default audit path", nil)
	}
	if auditPrunePathsEqual(targetAbsolute, defaultAbsolute) {
		return defaultAudit, nil
	}
	targetResolved, err := resolveAuditPruneAlias(path)
	if err != nil {
		return "", err
	}
	defaultResolved, err := resolveAuditPruneAlias(defaultAudit)
	if err != nil {
		return "", err
	}
	if conflict, err := auditPrunePathsConflict(path, targetResolved, defaultAudit); err != nil {
		return "", err
	} else if conflict {
		return "", apperrors.New(
			apperrors.CodeUsageError,
			"audit prune path aliases the default audit log; use the canonical default path",
			nil,
		)
	}
	protected, spoolPath, err := auditPruneProtectedPaths(f, defaultAudit)
	if err != nil {
		return "", err
	}
	for _, protectedPath := range protected {
		conflict, conflictErr := auditPrunePathsConflict(path, targetResolved, protectedPath)
		if conflictErr != nil {
			return "", conflictErr
		}
		if conflict {
			return "", apperrors.New(apperrors.CodeUsageError, "audit prune path conflicts with governed state", nil)
		}
	}
	if auditPruneConflictsWithTempNamespace(targetResolved, defaultResolved) {
		return "", apperrors.New(apperrors.CodeUsageError, "audit prune path conflicts with temporary audit state", nil)
	}
	if _, _, rotated := strictAuditRotatedFileOrder(defaultResolved, targetResolved); rotated {
		return "", apperrors.New(apperrors.CodeUsageError, "audit prune path conflicts with rotated audit state", nil)
	}
	spoolResolved, err := resolveAuditPruneAlias(spoolPath)
	if err != nil {
		return "", err
	}
	if auditPrunePathWithin(targetResolved, spoolResolved) {
		return "", apperrors.New(apperrors.CodeUsageError, "audit prune path conflicts with the mutation audit spool", nil)
	}
	return targetResolved, nil
}

func auditPruneProtectedPaths(
	f *cliFlags,
	defaultAudit string,
) ([]string, string, error) {
	configDir, err := corectx.ConfigDir()
	if err != nil {
		return nil, "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve context config directory", err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	if f != nil && strings.TrimSpace(f.Config) != "" {
		configPath = f.Config
	}
	spoolPath := mutationAuditSpoolPath(defaultAudit)
	return []string{
		configPath,
		configPath + ".tmp",
		configPath + ".lock",
		filepath.Join(filepath.Dir(configPath), "config.lock"),
		filepath.Join(configDir, "credentials.enc"),
		filepath.Join(configDir, "credentials.enc.tmp"),
		defaultAudit,
		defaultAudit + ".lock",
		defaultAudit + ".checkpoint",
		defaultAudit + ".hmac-key",
		spoolPath,
		filepath.Join(spoolPath, mutationAuditSpoolLockBase+".lock"),
	}, spoolPath, nil
}

func resolveAuditPruneAlias(path string) (string, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit prune path", nil)
	}
	current := filepath.Clean(absolute)
	var suffix []string
	for {
		if _, err := os.Lstat(current); err == nil {
			break
		} else if !os.IsNotExist(err) {
			return "", apperrors.New(apperrors.CodeLocalIOError, "failed to inspect audit prune path", nil)
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", apperrors.New(apperrors.CodeLocalIOError, "audit prune path has no existing ancestor", nil)
		}
		suffix = append(suffix, filepath.Base(current))
		current = parent
	}
	resolved, err := filepath.EvalSymlinks(current)
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve audit prune path aliases", nil)
	}
	for index := len(suffix) - 1; index >= 0; index-- {
		resolved = filepath.Join(resolved, suffix[index])
	}
	return filepath.Clean(resolved), nil
}

func auditPrunePathsConflict(target, targetResolved, protected string) (bool, error) {
	protectedResolved, err := resolveAuditPruneAlias(protected)
	if err != nil {
		return false, err
	}
	if auditPrunePathsEqual(targetResolved, protectedResolved) {
		return true, nil
	}
	targetInfo, targetErr := os.Stat(target)
	protectedInfo, protectedErr := os.Stat(protected)
	if targetErr == nil && protectedErr == nil && os.SameFile(targetInfo, protectedInfo) {
		return true, nil
	}
	if targetErr != nil && !os.IsNotExist(targetErr) {
		return false, apperrors.New(apperrors.CodeLocalIOError, "failed to identify audit prune target", nil)
	}
	if protectedErr != nil && !os.IsNotExist(protectedErr) {
		return false, apperrors.New(apperrors.CodeLocalIOError, "failed to identify governed state path", nil)
	}
	return false, nil
}

func auditPrunePathsEqual(left, right string) bool {
	if filepath.VolumeName(left) != "" || filepath.VolumeName(right) != "" {
		return strings.EqualFold(filepath.Clean(left), filepath.Clean(right))
	}
	return filepath.Clean(left) == filepath.Clean(right)
}

func auditPrunePathWithin(path, directory string) bool {
	relative, err := filepath.Rel(directory, path)
	if err != nil {
		return false
	}
	return relative == "." ||
		(relative != ".." && !strings.HasPrefix(relative, ".."+string(os.PathSeparator)))
}

func auditPruneConflictsWithTempNamespace(target, defaultAudit string) bool {
	if !auditPrunePathsEqual(filepath.Dir(target), filepath.Dir(defaultAudit)) {
		return false
	}
	targetName := filepath.Base(target)
	auditName := filepath.Base(defaultAudit)
	if filepath.VolumeName(target) != "" || filepath.VolumeName(defaultAudit) != "" {
		targetName = strings.ToLower(targetName)
		auditName = strings.ToLower(auditName)
	}
	return strings.HasPrefix(targetName, auditName+".checkpoint.tmp-") ||
		strings.HasPrefix(targetName, auditName+".hmac-key.tmp-")
}

func parseAuditPruneBefore(value string, now time.Time) (time.Time, error) {
	if t, err := coreaudit.ParseTime(value, now); err == nil {
		return t, nil
	}
	t, err := time.Parse("2006-01-02", value)
	if err != nil {
		return time.Time{}, apperrors.New(apperrors.CodeUsageError, "invalid --before: expected relative (30d), RFC3339, or YYYY-MM-DD", nil)
	}
	return t, nil
}

func printAuditPrune(f *cliFlags, result auditPruneResult) error {
	if result.Files == nil {
		result.Files = []string{}
	}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("AuditPruneResult", result)
	}
	if f.Output == "plain" {
		for _, filePath := range result.Files {
			if err := p.Info(filePath); err != nil {
				return err
			}
		}
		return nil
	}
	action := "would-delete"
	if !result.DryRun {
		action = "deleted"
	}
	rows := make([][]string, 0, len(result.Files))
	for _, filePath := range result.Files {
		rows = append(rows, []string{action, filepath.Base(filePath), filePath})
	}
	if len(rows) == 0 {
		return p.Info("(no rotated audit logs matched)")
	}
	if err := p.Table([]string{"ACTION", "FILE", "PATH"}, rows); err != nil {
		return err
	}
	if result.DryRun {
		return p.Info(fmt.Sprintf("(dry-run: pass --confirm to delete %d rotated audit logs)", result.Count))
	}
	return nil
}
