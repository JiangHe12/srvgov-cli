package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/credstore"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestContextExportRedactsCredentialsAndImportRequiresYes(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	runCommand(t, configPath,
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
		"--password", "login-secret",
		"--identity-passphrase", "key-secret",
	)

	exported := runCommand(t, configPath, "ctx", "export", "dev")
	if strings.Contains(exported, "login-secret") || strings.Contains(exported, "key-secret") {
		t.Fatalf("export leaked credentials:\n%s", exported)
	}
	if count := strings.Count(exported, redactedCredential); count != 2 {
		t.Fatalf("redacted count = %d; export:\n%s", count, exported)
	}

	file := filepath.Join(t.TempDir(), "ctx.yaml")
	if err := os.WriteFile(file, []byte(exported), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := executeRoot(t, configPath, "--non-interactive", "ctx", "import", "-f", file, "--rename", "copy")
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)

	runCommand(t, configPath, "--non-interactive", "--yes", "-o", "json", "ctx", "import", "-f", file, "--rename", "copy")
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	imported := cfg.Contexts["copy"]
	if imported.Password != "" || imported.IdentityPassphrase != "" {
		t.Fatalf("imported credentials = password:%q passphrase:%q", imported.Password, imported.IdentityPassphrase)
	}
}

func TestContextExportCanIncludePlainYamlCredentialsAndPreservesRefs(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	runCommand(t, configPath,
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
		"--password", "login-secret",
		"--identity-passphrase", "credstore:encrypted-file",
	)

	redacted := runCommand(t, configPath, "ctx", "export", "dev")
	if !strings.Contains(redacted, "credstore:encrypted-file") {
		t.Fatalf("credstore ref not preserved:\n%s", redacted)
	}
	included := runCommand(t, configPath, "ctx", "export", "dev", "--include-credentials")
	if !strings.Contains(included, "login-secret") {
		t.Fatalf("included export missing literal credential:\n%s", included)
	}
	if !strings.Contains(included, "credstore:encrypted-file") {
		t.Fatalf("included export missing ref:\n%s", included)
	}
}

func TestMigrateCredentialsMovesPasswordAndIdentityPassphrase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SRVGOV_MASTER_PASSWORD", "test-master-password")
	configPath := filepath.Join(home, "config.yaml")
	runCommand(t, configPath,
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
		"--password", "login-secret",
		"--identity-passphrase", "key-secret",
	)

	output := runCommand(t, configPath, "-o", "json", "ctx", "migrate-credentials", "--to", "encrypted-file", "--context", "dev")
	if strings.Contains(output, "login-secret") || strings.Contains(output, "key-secret") {
		t.Fatalf("migration output leaked credential: %s", output)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	item := cfg.Contexts["dev"]
	if item.Password != "credstore:encrypted-file" || item.IdentityPassphrase != "credstore:encrypted-file" {
		t.Fatalf("stored refs = password:%q passphrase:%q", item.Password, item.IdentityPassphrase)
	}
	backend, err := credstore.New("encrypted-file")
	if err != nil {
		t.Fatalf("credstore.New() error = %v", err)
	}
	password, err := backend.Get(context.Background(), "dev")
	if err != nil {
		t.Fatalf("Get(password) error = %v", err)
	}
	passphrase, err := backend.Get(context.Background(), "dev#identity")
	if err != nil {
		t.Fatalf("Get(passphrase) error = %v", err)
	}
	if password != "login-secret" || passphrase != "key-secret" {
		t.Fatalf("migrated values = %q/%q", password, passphrase)
	}
}
