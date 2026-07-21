package cmd

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

var agentPaths = map[string]string{
	"claude":    ".claude/skills",
	"codex":     ".codex/skills",
	"opencode":  ".opencode/skills",
	"copilot":   ".copilot/skills",
	"cursor":    ".cursor/skills",
	"cc-switch": ".cc-switch/skills",
	"windsurf":  ".windsurf/skills",
	"aider":     ".aider/skills",
}

var skillFS fs.FS

var writeEmbeddedSkillFile = os.WriteFile

// SetSkillFS injects the embedded skill file system from main.
func SetSkillFS(fsys fs.FS) {
	skillFS = fsys
}

func newInstallCmd(f *cliFlags) *cobra.Command {
	command := &cobra.Command{
		Use:   "install <agent>",
		Short: "Install skill to AI agent working directory",
		Long: `Install srvgov-cli skill to the specified AI agent's skills directory.

Preset agents:
  claude      -> ~/.claude/skills/
  codex       -> ~/.codex/skills/
  opencode    -> ~/.opencode/skills/
  copilot     -> ~/.copilot/skills/
  cursor      -> ~/.cursor/skills/
  cc-switch   -> ~/.cc-switch/skills/
  windsurf    -> ~/.windsurf/skills/
  aider       -> ~/.aider/skills/

Custom path:
  srvgov install /my/path --skills  -> /my/path/srvgov-cli/`,
		Example: `  srvgov install claude --skills
  srvgov install codex --skills
  srvgov install /custom/path --skills`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			skills, _ := cmd.Flags().GetBool("skills")
			if !skills {
				return apperrors.New(apperrors.CodeUsageError, "please specify --skills flag", nil)
			}
			return installSkills(f, args[0])
		},
	}
	command.Flags().Bool("skills", false, "Install skill files")
	_ = command.MarkFlagRequired("skills")
	return command
}

func installSkills(f *cliFlags, target string) error {
	installDir, err := resolveInstallDir(target)
	if err != nil {
		return err
	}
	dstDir := filepath.Join(installDir, "srvgov-cli")
	files, err := prepareEmbeddedSkill(skillFS, "skills/srvgov-cli")
	if err != nil {
		return err
	}
	auditHandle, err := beginMutationAudit(f, mutationAuditSpec{
		Action:   "install.skills",
		Target:   dstDir,
		RiskTier: "R1",
		Metadata: mutationAuditMetadata{Items: len(files)},
	})
	if err != nil {
		return err
	}
	succeeded, installErr := writeEmbeddedSkill(files, dstDir)
	outcome := mutationAuditOutcome{}
	if installErr == nil {
		outcome.Status = "succeeded"
		outcome.Succeeded = succeeded
	} else {
		outcome.Status = "failed"
		outcome.Succeeded = succeeded
		outcome.Failed = 1
		outcome.Skipped = len(files) - succeeded - 1
		if outcome.Skipped < 0 {
			outcome.Skipped = 0
		}
	}
	if err := finishMutationAudit(auditHandle, outcome, installErr); err != nil {
		return err
	}

	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("InstallResult", map[string]string{"path": dstDir})
	}
	return p.Success(fmt.Sprintf("skill installed to %s", dstDir))
}

func resolveInstallDir(target string) (string, error) {
	if skillsDir, ok := agentPaths[strings.ToLower(target)]; ok {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", apperrors.New(apperrors.CodeLocalIOError, "failed to get home directory", err)
		}
		return filepath.Join(home, skillsDir), nil
	}
	return target, nil
}

func copyEmbeddedSkill(fsys fs.FS, srcDir, dstDir string) error {
	files, err := prepareEmbeddedSkill(fsys, srcDir)
	if err != nil {
		return err
	}
	_, err = writeEmbeddedSkill(files, dstDir)
	return err
}

type embeddedSkillFile struct {
	relativePath string
	data         []byte
}

func prepareEmbeddedSkill(fsys fs.FS, srcDir string) ([]embeddedSkillFile, error) {
	if fsys == nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "embedded skill filesystem is not initialized", nil)
	}
	files := []embeddedSkillFile{}
	err := fs.WalkDir(fsys, srcDir, func(srcPath string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || strings.HasSuffix(entry.Name(), "_test.go") {
			return nil
		}
		data, err := fs.ReadFile(fsys, srcPath)
		if err != nil {
			return err
		}
		relative := strings.TrimPrefix(srcPath, strings.TrimSuffix(srcDir, "/")+"/")
		if relative == srcPath || relative == "" || strings.HasPrefix(relative, "../") {
			return apperrors.New(apperrors.CodeLocalIOError, "embedded skill contains an invalid path", nil)
		}
		files = append(files, embeddedSkillFile{relativePath: filepath.FromSlash(relative), data: data})
		return nil
	})
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read embedded skill", err)
	}
	return files, nil
}

func writeEmbeddedSkill(files []embeddedSkillFile, dstDir string) (int, error) {
	if err := os.MkdirAll(dstDir, 0o750); err != nil {
		return 0, apperrors.New(apperrors.CodeLocalIOError, "failed to create skill directory", err)
	}
	succeeded := 0
	for _, file := range files {
		dstPath := filepath.Join(dstDir, file.relativePath)
		if err := os.MkdirAll(filepath.Dir(dstPath), 0o750); err != nil {
			return succeeded, apperrors.New(apperrors.CodeLocalIOError, "failed to create skill directory", err)
		}
		if err := writeEmbeddedSkillFile(dstPath, file.data, 0o600); err != nil { //nolint:gosec // Destination is rooted below the user-selected install directory.
			return succeeded, apperrors.New(apperrors.CodeLocalIOError, "failed to write skill file", err)
		}
		succeeded++
	}
	return succeeded, nil
}
