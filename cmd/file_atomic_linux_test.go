//go:build linux

package cmd

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestAtomicFileWriteCommandReplacesOnlyAfterCompleteBoundedInput(t *testing.T) {
	t.Run("success preserves mode and treats path literally", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "app'; touch injected; #")
		injected := filepath.Join(dir, "injected")
		if err := os.WriteFile(target, []byte("old"), 0o640); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		runAtomicFileWriteCommand(t, target, 8, "new-data", "new-data", false)

		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if string(data) != "new-data" {
			t.Fatalf("target content = %q, want new-data", data)
		}
		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o640 {
			t.Fatalf("target mode = %o, want 640", got)
		}
		if _, err := os.Stat(injected); !os.IsNotExist(err) {
			t.Fatalf("injection marker error = %v, want absent", err)
		}
		requireNoFileWriteTemps(t, dir)
	})

	t.Run("oversized input leaves original intact", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "app")
		if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		runAtomicFileWriteCommand(t, target, 4, "12345", "12345", true)

		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if string(data) != "original" {
			t.Fatalf("target content = %q, want original", data)
		}
		requireNoFileWriteTemps(t, dir)
	})

	t.Run("new file is owner-only", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "new")

		runAtomicFileWriteCommand(t, target, 8, "new-data", "new-data", false)

		info, err := os.Stat(target)
		if err != nil {
			t.Fatalf("Stat() error = %v", err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("target mode = %o, want 600", got)
		}
		requireNoFileWriteTemps(t, dir)
	})

	t.Run("short or different input leaves original intact", func(t *testing.T) {
		tests := []struct {
			name  string
			input string
		}{
			{name: "short", input: "new"},
			{name: "digest mismatch", input: "different"},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "app")
				if err := os.WriteFile(target, []byte("original"), 0o600); err != nil {
					t.Fatalf("WriteFile() error = %v", err)
				}

				runAtomicFileWriteCommand(t, target, 16, "expected!", test.input, true)

				data, err := os.ReadFile(target)
				if err != nil {
					t.Fatalf("ReadFile() error = %v", err)
				}
				if string(data) != "original" {
					t.Fatalf("target content = %q, want original", data)
				}
				requireNoFileWriteTemps(t, dir)
			})
		}
	})

	t.Run("symlink is rejected without replacing link or referent", func(t *testing.T) {
		dir := t.TempDir()
		referent := filepath.Join(dir, "referent")
		target := filepath.Join(dir, "link")
		if err := os.WriteFile(referent, []byte("original"), 0o600); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}
		if err := os.Symlink(referent, target); err != nil {
			t.Fatalf("Symlink() error = %v", err)
		}

		runAtomicFileWriteCommand(t, target, 8, "new-data", "new-data", true)

		info, err := os.Lstat(target)
		if err != nil {
			t.Fatalf("Lstat() error = %v", err)
		}
		if info.Mode()&os.ModeSymlink == 0 {
			t.Fatalf("target mode = %v, want symlink", info.Mode())
		}
		data, err := os.ReadFile(referent)
		if err != nil {
			t.Fatalf("ReadFile() error = %v", err)
		}
		if string(data) != "original" {
			t.Fatalf("referent content = %q, want original", data)
		}
		requireNoFileWriteTemps(t, dir)
	})

	t.Run("directory fifo and broken symlink are rejected", func(t *testing.T) {
		tests := []struct {
			name  string
			setup func(*testing.T, string)
		}{
			{
				name: "directory",
				setup: func(t *testing.T, target string) {
					t.Helper()
					if err := os.Mkdir(target, 0o700); err != nil {
						t.Fatalf("Mkdir() error = %v", err)
					}
				},
			},
			{
				name: "fifo",
				setup: func(t *testing.T, target string) {
					t.Helper()
					if err := unix.Mkfifo(target, 0o600); err != nil {
						t.Fatalf("Mkfifo() error = %v", err)
					}
				},
			},
			{
				name: "broken symlink",
				setup: func(t *testing.T, target string) {
					t.Helper()
					if err := os.Symlink(target+".missing", target); err != nil {
						t.Fatalf("Symlink() error = %v", err)
					}
				},
			},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				dir := t.TempDir()
				target := filepath.Join(dir, "target")
				test.setup(t, target)
				before, err := os.Lstat(target)
				if err != nil {
					t.Fatalf("Lstat(before) error = %v", err)
				}

				runAtomicFileWriteCommand(t, target, 8, "new-data", "new-data", true)

				after, err := os.Lstat(target)
				if err != nil {
					t.Fatalf("Lstat(after) error = %v", err)
				}
				if after.Mode().Type() != before.Mode().Type() {
					t.Fatalf("target type changed from %v to %v", before.Mode(), after.Mode())
				}
				requireNoFileWriteTemps(t, dir)
			})
		}
	})

	t.Run("target replacement during upload fails with no overwrite", func(t *testing.T) {
		dir := t.TempDir()
		target := filepath.Join(dir, "app")
		original := filepath.Join(dir, "app.original")
		if err := os.WriteFile(target, []byte("original"), 0o640); err != nil {
			t.Fatalf("WriteFile() error = %v", err)
		}

		expected := "new-data"
		command := directAtomicFileWriteCommand(t, target, 8, expected)
		stdin, err := command.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe() error = %v", err)
		}
		if err := command.Start(); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		if _, err := stdin.Write([]byte("new")); err != nil {
			t.Fatalf("stdin.Write() error = %v", err)
		}
		waitForFileWriteTemp(t, dir)
		if err := os.Rename(target, original); err != nil {
			t.Fatalf("Rename() error = %v", err)
		}
		if err := os.WriteFile(target, []byte("concurrent"), 0o600); err != nil {
			t.Fatalf("concurrent WriteFile() error = %v", err)
		}
		if _, err := stdin.Write([]byte("-data")); err != nil {
			t.Fatalf("stdin.Write() remainder error = %v", err)
		}
		if err := stdin.Close(); err != nil {
			t.Fatalf("stdin.Close() error = %v", err)
		}
		if err := command.Wait(); err == nil {
			t.Fatal("atomic write error = nil, want target-identity conflict")
		}

		data, err := os.ReadFile(target)
		if err != nil {
			t.Fatalf("ReadFile(concurrent target) error = %v", err)
		}
		if string(data) != "concurrent" {
			t.Fatalf("concurrent target content = %q, want concurrent", data)
		}
		data, err = os.ReadFile(original)
		if err != nil {
			t.Fatalf("ReadFile(original) error = %v", err)
		}
		if string(data) != "original" {
			t.Fatalf("original content = %q, want original", data)
		}
		requireNoFileWriteTemps(t, dir)
	})

	t.Run("parent replacement during upload fails without writing replacement", func(t *testing.T) {
		root := t.TempDir()
		directory := filepath.Join(root, "live")
		replacement := filepath.Join(root, "replacement")
		original := filepath.Join(root, "original")
		if err := os.Mkdir(directory, 0o700); err != nil {
			t.Fatalf("Mkdir(live) error = %v", err)
		}
		if err := os.Mkdir(replacement, 0o700); err != nil {
			t.Fatalf("Mkdir(replacement) error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(directory, "app"), []byte("original"), 0o600); err != nil {
			t.Fatalf("WriteFile(original) error = %v", err)
		}
		if err := os.WriteFile(filepath.Join(replacement, "app"), []byte("replacement"), 0o600); err != nil {
			t.Fatalf("WriteFile(replacement) error = %v", err)
		}

		command := directAtomicFileWriteCommand(t, filepath.Join(directory, "app"), 8, "new-data")
		stdin, err := command.StdinPipe()
		if err != nil {
			t.Fatalf("StdinPipe() error = %v", err)
		}
		if err := command.Start(); err != nil {
			t.Fatalf("Start() error = %v", err)
		}
		if _, err := stdin.Write([]byte("new")); err != nil {
			t.Fatalf("stdin.Write() error = %v", err)
		}
		waitForFileWriteTemp(t, directory)
		if err := os.Rename(directory, original); err != nil {
			t.Fatalf("Rename(live, original) error = %v", err)
		}
		if err := os.Rename(replacement, directory); err != nil {
			t.Fatalf("Rename(replacement, live) error = %v", err)
		}
		if _, err := stdin.Write([]byte("-data")); err != nil {
			t.Fatalf("stdin.Write(remainder) error = %v", err)
		}
		if err := stdin.Close(); err != nil {
			t.Fatalf("stdin.Close() error = %v", err)
		}
		if err := command.Wait(); err == nil {
			t.Fatal("atomic write error = nil, want parent-identity conflict")
		}

		for file, want := range map[string]string{
			filepath.Join(original, "app"):  "original",
			filepath.Join(directory, "app"): "replacement",
		} {
			data, err := os.ReadFile(file)
			if err != nil {
				t.Fatalf("ReadFile(%s) error = %v", file, err)
			}
			if string(data) != want {
				t.Fatalf("%s content = %q, want %q", file, data, want)
			}
		}
		requireNoFileWriteTemps(t, original)
		requireNoFileWriteTemps(t, directory)
	})
}

func runAtomicFileWriteCommand(
	t *testing.T,
	target string,
	maxBytes int,
	expectedContent, input string,
	wantFailure bool,
) {
	t.Helper()
	command := exec.CommandContext(
		t.Context(),
		"sh",
		"-c",
		fileWriteCommand(localFileWriteTargetBinding(t, target), maxBytes, []byte(expectedContent)),
	)
	command.Stdin = strings.NewReader(input)
	output, err := command.CombinedOutput()
	if wantFailure && err == nil {
		t.Fatalf("atomic write error = nil, want failure; output=%q", output)
	}
	if !wantFailure && err != nil {
		t.Fatalf("atomic write error = %v; output=%q", err, output)
	}
}

func requireNoFileWriteTemps(t *testing.T, dir string) {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, ".*.srvgov.*"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(matches) != 0 {
		t.Fatalf("temporary files remain: %v", matches)
	}
}

func directAtomicFileWriteCommand(t *testing.T, target string, maxBytes int, expected string) *exec.Cmd {
	t.Helper()
	binding := localFileWriteTargetBinding(t, target)
	digest := sha256.Sum256([]byte(expected))
	return exec.CommandContext(
		t.Context(),
		"sh",
		"-c",
		atomicFileWriteScript,
		"srvgov-file-write",
		binding.ResolvedDirectory,
		binding.Base,
		binding.DirectoryIdentity,
		strconv.Itoa(maxBytes),
		strconv.Itoa(len(expected)),
		hex.EncodeToString(digest[:]),
	)
}

func localFileWriteTargetBinding(t *testing.T, target string) fileWriteTargetBinding {
	t.Helper()
	directory, base, err := splitRemoteFileWriteTarget(filepath.ToSlash(target))
	if err != nil {
		t.Fatalf("splitRemoteFileWriteTarget(%q) error = %v", target, err)
	}
	resolved, err := filepath.EvalSymlinks(filepath.FromSlash(directory))
	if err != nil {
		t.Fatalf("EvalSymlinks(%q) error = %v", directory, err)
	}
	var stat unix.Stat_t
	if err := unix.Stat(resolved, &stat); err != nil {
		t.Fatalf("Stat(%q) error = %v", resolved, err)
	}
	return fileWriteTargetBinding{
		ResolvedDirectory: filepath.ToSlash(resolved),
		Base:              base,
		DirectoryIdentity: fmt.Sprintf("%d:%d", stat.Dev, stat.Ino),
	}
}

func waitForFileWriteTemp(t *testing.T, dir string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		matches, err := filepath.Glob(filepath.Join(dir, ".*.srvgov.*"))
		if err != nil {
			t.Fatalf("Glob() error = %v", err)
		}
		if len(matches) > 0 {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("remote temporary file was not created")
}
