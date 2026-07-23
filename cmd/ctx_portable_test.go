package cmd

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestContextExportRedactsCredentialsAndImportRequiresR3Authorization(t *testing.T) {
	configPath := isolatedContextConfig(t)
	item := testServerContext("example.com")
	item.Username = "alice"
	item.Password = "login-secret"
	item.IdentityPassphrase = "key-secret"
	item.CredentialBackend = "plain-yaml"
	mustSetContext(t, configPath, "dev", item)

	exported := runCommand(t, configPath, "ctx", "export", "dev")
	if strings.Contains(exported, "login-secret") || strings.Contains(exported, "key-secret") {
		t.Fatalf("export leaked credentials:\n%s", exported)
	}
	if count := strings.Count(exported, redactedCredential); count != 2 {
		t.Fatalf("redacted count = %d; export:\n%s", count, exported)
	}
	requireReadAuditPairs(
		t,
		readAuditEvents(t),
		string(srvgovaudit.EventTypeContextExport),
		"R0",
		1,
	)

	file := filepath.Join(t.TempDir(), "ctx.yaml")
	if err := os.WriteFile(file, []byte(exported), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	_, err := executeRoot(t, configPath, "--non-interactive", "ctx", "import", "-f", file, "--rename", "copy")
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)

	runCommand(t, configPath,
		"--non-interactive", "--yes", "--ticket", "TEST-1", "--allow-context-change", "-o", "json",
		"ctx", "import", "-f", file, "--rename", "copy",
	)
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	imported := cfg.Contexts["copy"]
	if imported.Password != "" || imported.IdentityPassphrase != "" {
		t.Fatalf("imported credentials = password:%q passphrase:%q", imported.Password, imported.IdentityPassphrase)
	}

	legacyFile := filepath.Join(t.TempDir(), "legacy-ctx.yaml")
	legacyExport := strings.Replace(exported, ctxExportAPIVersion, legacyCtxExportAPIVersion, 1)
	if err := os.WriteFile(legacyFile, []byte(legacyExport), 0o600); err != nil {
		t.Fatalf("WriteFile(legacy) error = %v", err)
	}
	runCommand(t, configPath,
		"--non-interactive", "--yes", "--ticket", "TEST-1", "--allow-context-change",
		"ctx", "import", "-f", legacyFile, "--rename", "legacy-copy",
	)
	cfg, err = srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, ok := cfg.Contexts["legacy-copy"]; !ok {
		t.Fatalf("legacy context was not imported: %#v", cfg.Contexts)
	}
}

func TestContextExportDisablesPlaintextCredentialsAndPreservesRefs(t *testing.T) {
	configPath := isolatedContextConfig(t)
	item := testServerContext("example.com")
	item.Username = "alice"
	item.Password = "login-secret"
	item.IdentityPassphrase = "credstore:encrypted-file"
	item.CredentialBackend = "plain-yaml"
	mustSetContext(t, configPath, "dev", item)

	redacted := runCommand(t, configPath, "ctx", "export", "dev")
	if strings.Contains(redacted, "login-secret") {
		t.Fatalf("default export leaked literal credential:\n%s", redacted)
	}
	if !strings.Contains(redacted, "credstore:encrypted-file") {
		t.Fatalf("credstore ref not preserved:\n%s", redacted)
	}
	included := runCommandError(t, configPath, "ctx", "export", "dev", "--include-credentials")
	if !strings.Contains(included, "--include-credentials is disabled") {
		t.Fatalf("include-credentials error = %q", included)
	}
	if strings.Contains(included, "login-secret") {
		t.Fatalf("include-credentials error leaked literal credential: %q", included)
	}
}

func TestContextExportEnforcesTargetRBACAndProtectedRisk(t *testing.T) {
	configPath := isolatedContextConfig(t)
	operator, err := trustedOperator(&cliFlags{})
	if err != nil {
		t.Fatalf("trustedOperator() error = %v", err)
	}
	item := testServerContext("example.com")
	item.Roles = map[string]string{"another-operator": safety.RoleReader}
	mustSetContext(t, configPath, "restricted", item)

	output, err := executeRoot(t, configPath, "ctx", "export", "restricted")
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if output != "" {
		t.Fatalf("denied export output = %q, want empty", output)
	}
	outcomes := requireReadAuditPairs(
		t,
		readAuditEvents(t),
		string(srvgovaudit.EventTypeContextExport),
		"R0",
		1,
	)
	if outcomes[0].Status != srvgovaudit.StatusFailed ||
		outcomes[0].Error == nil ||
		outcomes[0].Error.Code != string(apperrors.CodeAuthorizationRequired) {
		t.Fatalf("denied export outcome = %#v", outcomes[0])
	}

	item.Protected = true
	item.Roles = map[string]string{operator: safety.RoleReader}
	mustSetContext(t, configPath, "protected", item)
	output, err = executeRoot(
		t,
		configPath,
		"--non-interactive",
		"ctx",
		"export",
		"protected",
	)
	if err != nil {
		t.Fatalf("protected R0 export error = %v", err)
	}
	if !strings.Contains(output, "name: protected") {
		t.Fatalf("protected export output = %q", output)
	}
}

func TestMigrateCredentialsMovesPasswordAndIdentityPassphrase(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SRVGOV_MASTER_PASSWORD", "test-master-password")
	configPath := filepath.Join(home, "config.yaml")
	srvgovctx.SetConfigPath(configPath)
	item := testServerContext("example.com")
	item.Username = "alice"
	item.Password = "login-secret"
	item.IdentityPassphrase = "key-secret"
	item.CredentialBackend = "plain-yaml"
	mustSetContext(t, configPath, "dev", item)

	output := runCommand(t, configPath,
		"-o", "json", "--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "migrate-credentials", "--to", "encrypted-file", "--context", "dev",
	)
	if strings.Contains(output, "login-secret") || strings.Contains(output, "key-secret") {
		t.Fatalf("migration output leaked credential: %s", output)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	migrated := cfg.Contexts["dev"]
	if migrated.Password != "credstore:encrypted-file" || migrated.IdentityPassphrase != "credstore:encrypted-file" {
		t.Fatalf("stored refs = password:%q passphrase:%q", migrated.Password, migrated.IdentityPassphrase)
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

func TestContextImportValidatesEntireDocumentBeforeAuthorizationOrWrite(t *testing.T) {
	tests := []struct {
		name string
		body string
	}{
		{
			name: "unknown field",
			body: `apiVersion: srvgov-cli.io/ctx-export/v1
name: imported
context:
  server: ssh://alice@example.com:22
  unexpected: true
`,
		},
		{
			name: "multiple documents",
			body: `apiVersion: srvgov-cli.io/ctx-export/v1
name: imported
context:
  server: ssh://alice@example.com:22
---
apiVersion: srvgov-cli.io/ctx-export/v1
name: second
context:
  server: ssh://alice@second.example.com:22
`,
		},
		{
			name: "invalid context",
			body: `apiVersion: srvgov-cli.io/ctx-export/v1
name: imported
context:
  server: mysql://db.example.com:3306
`,
		},
		{
			name: "invalid role",
			body: `apiVersion: srvgov-cli.io/ctx-export/v1
name: imported
context:
  server: ssh://alice@example.com:22
  roles:
    alice@ops-host: owner
`,
		},
		{
			name: "literal credential",
			body: `apiVersion: srvgov-cli.io/ctx-export/v1
name: imported
context:
  server: ssh://alice@example.com:22
  password: import-secret
  credentialBackend: plain-yaml
`,
		},
		{
			name: "literal credential with declared secure backend",
			body: `apiVersion: srvgov-cli.io/ctx-export/v1
name: imported
context:
  server: ssh://alice@example.com:22
  password: import-secret
  credentialBackend: encrypted-file
`,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			configPath := isolatedContextConfig(t)
			file := filepath.Join(t.TempDir(), "import.yaml")
			if err := os.WriteFile(file, []byte(test.body), 0o600); err != nil {
				t.Fatalf("WriteFile() error = %v", err)
			}

			_, err := executeRoot(t, configPath, "ctx", "import", "-f", file)
			assertAppError(t, err, apperrors.CodeUsageError, 1)
			cfg, loadErr := srvgovctx.Load()
			if loadErr != nil {
				t.Fatalf("Load() error = %v", loadErr)
			}
			if len(cfg.Contexts) != 0 {
				t.Fatalf("contexts written from invalid import = %#v", cfg.Contexts)
			}
		})
	}
}

func TestContextImportPreservesCredentialReferencesAndDerivesBackend(t *testing.T) {
	configPath := isolatedContextConfig(t)
	file := filepath.Join(t.TempDir(), "import.yaml")
	body := `apiVersion: srvgov-cli.io/ctx-export/v1
name: imported
context:
  server: ssh://alice@example.com:22
  password: credstore:encrypted-file
  identityPassphrase: credstore:encrypted-file
`
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	runCommand(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "import", "-f", file,
	)
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	item := cfg.Contexts["imported"]
	if item.Password != "credstore:encrypted-file" ||
		item.IdentityPassphrase != "credstore:encrypted-file" ||
		item.CredentialBackend != "encrypted-file" {
		t.Fatalf("imported credential references = %#v", item)
	}
}
