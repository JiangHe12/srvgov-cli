package cmd

import (
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"testing/fstest"

	"github.com/JiangHe12/opskit-core/apperrors"
)

func TestInstallSkillsToCustomDirectory(t *testing.T) {
	previous := skillFS
	SetSkillFS(fstest.MapFS{
		"skills/srvgov-cli/SKILL.md": &fstest.MapFile{
			Data: []byte("# srvgov-cli test skill\n"),
		},
	})
	t.Cleanup(func() { SetSkillFS(previous) })

	target := t.TempDir()
	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "install", target, "--skills",
	)
	if err != nil {
		t.Fatalf("install error = %v", err)
	}
	result := decodeJSONData[map[string]string](t, output, "InstallResult")
	if result["path"] != filepath.Join(target, "srvgov-cli") {
		t.Fatalf("install path = %q", result["path"])
	}
	path := filepath.Join(target, "srvgov-cli", "SKILL.md")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != "# srvgov-cli test skill\n" {
		t.Fatalf("SKILL.md = %q", data)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("SKILL.md mode = %#o, want owner-only", info.Mode().Perm())
	}
}

func TestInstallRequiresSkillsFlag(t *testing.T) {
	_, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), "install", t.TempDir())
	assertAppError(t, err, apperrors.CodeUsageError, 1)
}

func TestCopyEmbeddedSkillRejectsUninitializedFS(t *testing.T) {
	err := copyEmbeddedSkill(nil, "skills/srvgov-cli", t.TempDir())
	assertAppError(t, err, apperrors.CodeLocalIOError, 6)
}

var _ fs.FS = fstest.MapFS{}
