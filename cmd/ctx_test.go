package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestContextCommandsLifecycleAndRedaction(t *testing.T) {
	configPath := isolatedContextConfig(t)

	runCommand(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:2222",
		"--password", "credstore:encrypted-file",
		"--identity-file", "/home/alice/.ssh/id_ed25519",
		"--identity-passphrase", "credstore:encrypted-file",
		"--credential-backend", "encrypted-file",
	)
	runCommand(t, configPath, "--ticket", "TEST-1", "--yes", "--allow-context-change", "ctx", "use", "dev")

	current := runCommand(t, configPath, "-o", "json", "ctx", "current")
	view := decodeJSONData[contextView](t, current, "ContextItem")
	if view.Name != "dev" || view.Host != "example.com" || view.Port != 2222 || view.Username != "alice" {
		t.Fatalf("current view = %#v", view)
	}
	assertNoCredentialLeak(t, current)

	list := runCommand(t, configPath, "-o", "json", "ctx", "list")
	assertNoCredentialLeak(t, list)
	if !strings.Contains(list, `"name": "dev"`) {
		t.Fatalf("list output = %q", list)
	}

	runCommand(t, configPath, "--ticket", "TEST-1", "--yes", "--allow-context-delete", "ctx", "delete", "dev")
	currentAfterDelete := runCommandError(t, configPath, "ctx", "current")
	if !strings.Contains(currentAfterDelete, "no current context set") {
		t.Fatalf("current error = %q", currentAfterDelete)
	}
}

func TestContextLabelsDisplayAndPortableRoundTrip(t *testing.T) {
	configPath := isolatedContextConfig(t)
	dir := filepath.Dir(configPath)

	runCommand(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "set", "prod",
		"--server", "ssh://alice@example.com:22",
		"--label", "env=prod",
		"--label", "role=web",
	)
	runCommand(t, configPath, "--ticket", "TEST-1", "--yes", "--allow-context-change", "ctx", "use", "prod")

	current := runCommand(t, configPath, "-o", "json", "ctx", "current")
	view := decodeJSONData[contextView](t, current, "ContextItem")
	if view.Labels["env"] != "prod" || view.Labels["role"] != "web" {
		t.Fatalf("labels = %#v", view.Labels)
	}
	list := runCommand(t, configPath, "ctx", "list")
	if !strings.Contains(list, "env=prod,role=web") {
		t.Fatalf("list output missing labels: %q", list)
	}

	exported := runCommand(t, configPath, "ctx", "export", "prod")
	if !strings.Contains(exported, "labels:") || !strings.Contains(exported, "env: prod") || !strings.Contains(exported, "role: web") {
		t.Fatalf("export missing labels:\n%s", exported)
	}
	importFile := filepath.Join(dir, "prod.yaml")
	if err := os.WriteFile(importFile, []byte(exported), 0o600); err != nil {
		t.Fatal(err)
	}
	importConfig := filepath.Join(dir, "import-config.yaml")
	runCommand(t, importConfig,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "import", "-f", importFile, "--rename", "prod-copy",
	)
	runCommand(t, importConfig,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "use", "prod-copy",
	)
	imported := runCommand(t, importConfig, "-o", "json", "ctx", "current")
	importedView := decodeJSONData[contextView](t, imported, "ContextItem")
	if importedView.Labels["env"] != "prod" || importedView.Labels["role"] != "web" {
		t.Fatalf("imported labels = %#v", importedView.Labels)
	}
}

func TestContextSetRejectsInvalidLabels(t *testing.T) {
	configPath := isolatedContextConfig(t)
	for _, label := range []string{"env", "=prod", "env="} {
		output := runCommandError(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "set", "bad",
			"--server", "ssh://alice@example.com:22",
			"--label", label,
		)
		if !strings.Contains(output, "--label must be key=value") {
			t.Fatalf("label %q error = %q", label, output)
		}
	}
}

func TestContextSetRequiresHostOrSSHServer(t *testing.T) {
	configPath := isolatedContextConfig(t)
	output := runCommandError(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "set", "bad", "--server", "mysql://db:3306",
	)
	if !strings.Contains(output, "SSH server must use ssh://") {
		t.Fatalf("error output = %q", output)
	}
}

func TestContextSetRejectsPlainYamlCredentialsBeforeAuthorizationOrWrite(t *testing.T) {
	configPath := isolatedContextConfig(t)
	for _, args := range [][]string{
		{"--password", "login-secret"},
		{"--identity-passphrase", "key-secret"},
	} {
		command := make([]string, 0, 5+len(args))
		command = append(command,
			"ctx", "set", "bad",
			"--server", "ssh://alice@example.com:22",
		)
		output := runCommandError(t, configPath, append(command, args...)...)
		if !strings.Contains(output, "credentials must use a non-plain credential backend") {
			t.Fatalf("error output = %q", output)
		}
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if len(cfg.Contexts) != 0 {
		t.Fatalf("rejected contexts were persisted: %#v", cfg.Contexts)
	}
}

func TestContextSetStoresCredentialsInSecureBackend(t *testing.T) {
	configPath := isolatedContextConfig(t)
	backend := newMemoryCredentialBackend()
	restore := replaceCredentialBackendFactory(backend)
	t.Cleanup(restore)

	runCommand(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
		"--password", "login-secret",
		"--identity-passphrase", "key-secret",
		"--credential-backend", "encrypted-file",
	)

	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	item := cfg.Contexts["dev"]
	if item.Password != "credstore:encrypted-file" ||
		item.IdentityPassphrase != "credstore:encrypted-file" ||
		item.CredentialBackend != "encrypted-file" {
		t.Fatalf("stored context credentials = %#v", item)
	}
	if backend.values["dev"] != "login-secret" || backend.values["dev#identity"] != "key-secret" {
		t.Fatalf("credential backend values = %#v", backend.values)
	}
	data, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if strings.Contains(string(data), "login-secret") || strings.Contains(string(data), "key-secret") {
		t.Fatalf("context file contains plaintext credentials:\n%s", data)
	}
}

func TestContextSetCompensatesCredentialWritesOnFailure(t *testing.T) {
	configPath := isolatedContextConfig(t)
	backend := newMemoryCredentialBackend()
	backend.values["dev"] = "previous-password"
	backend.failPut = "dev#identity"
	restore := replaceCredentialBackendFactory(backend)
	t.Cleanup(restore)

	output := runCommandError(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
		"--password", "login-secret",
		"--identity-passphrase", "key-secret",
		"--credential-backend", "encrypted-file",
	)
	if !strings.Contains(output, "store credential") {
		t.Fatalf("error output = %q", output)
	}
	if len(backend.values) != 1 || backend.values["dev"] != "previous-password" {
		t.Fatalf("credential compensation values = %#v", backend.values)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if _, ok := cfg.Contexts["dev"]; ok {
		t.Fatalf("context persisted after credential failure: %#v", cfg.Contexts["dev"])
	}
}

func TestContextSetReportsUncertainCredentialStateWhenCompensationFails(t *testing.T) {
	configPath := isolatedContextConfig(t)
	backend := newMemoryCredentialBackend()
	backend.values["dev"] = "previous-password"
	backend.failPut = "dev#identity"
	backend.failDelete = "dev#identity"
	restore := replaceCredentialBackendFactory(backend)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
		"--password", "login-secret",
		"--identity-passphrase", "key-secret",
		"--credential-backend", "encrypted-file",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	if !strings.Contains(apperrors.AsAppError(err).Suggestion, "before any retry") {
		t.Fatalf("suggestion = %q, want inspect-before-retry guidance", apperrors.AsAppError(err).Suggestion)
	}
	cfg, loadErr := srvgovctx.Load()
	if loadErr != nil {
		t.Fatalf("Load() error = %v", loadErr)
	}
	if _, ok := cfg.Contexts["dev"]; ok {
		t.Fatalf("context persisted after uncertain credential compensation: %#v", cfg.Contexts["dev"])
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeContextSet), "dev", "R3")
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Outcome == nil ||
		outcome.Outcome.Uncertain != 1 ||
		outcome.Outcome.Failed != 0 {
		t.Fatalf("context set outcome = %#v", outcome)
	}
}

func TestContextSetReportsUnknownCommitAfterCredentialStorage(t *testing.T) {
	configPath := isolatedContextConfig(t)
	backend := newMemoryCredentialBackend()
	restoreBackend := replaceCredentialBackendFactory(backend)
	t.Cleanup(restoreBackend)
	previousUpdate := updateContextSetContexts
	updateContextSetContexts = func(fn func(*srvgovctx.Config) error) error {
		cfg, err := srvgovctx.Load()
		if err != nil {
			return err
		}
		if err := fn(cfg); err != nil {
			return err
		}
		return apperrors.New(
			apperrors.CodeLocalIOError,
			"injected error after the configuration callback",
			nil,
		)
	}
	t.Cleanup(func() { updateContextSetContexts = previousUpdate })

	_, err := executeRoot(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:22",
		"--password", "login-secret",
		"--credential-backend", "encrypted-file",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	if !strings.Contains(apperrors.AsAppError(err).Suggestion, "before any retry") {
		t.Fatalf("suggestion = %q, want verify-before-retry guidance", apperrors.AsAppError(err).Suggestion)
	}
	if backend.values["dev"] != "login-secret" {
		t.Fatalf("stored credential was blindly compensated: %#v", backend.values)
	}
	cfg, loadErr := srvgovctx.Load()
	if loadErr != nil {
		t.Fatalf("Load() error = %v", loadErr)
	}
	if _, ok := cfg.Contexts["dev"]; ok {
		t.Fatalf("test configuration unexpectedly committed: %#v", cfg.Contexts["dev"])
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeContextSet), "dev", "R3")
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Outcome == nil ||
		outcome.Outcome.Uncertain != 1 ||
		outcome.Outcome.Failed != 0 {
		t.Fatalf("context set outcome = %#v", outcome)
	}
}

func runCommand(t *testing.T, configPath string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"--config", configPath}, args...))
	if err := root.Execute(); err != nil {
		t.Fatalf("Execute(%v) error = %v; stderr = %q", args, err, errOut.String())
	}
	return out.String()
}

func runCommandError(t *testing.T, configPath string, args ...string) string {
	t.Helper()
	var out bytes.Buffer
	var errOut bytes.Buffer
	root := NewRootCmd()
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs(append([]string{"--config", configPath}, args...))
	err := root.Execute()
	if err == nil {
		t.Fatalf("Execute(%v) error = nil; output = %q", args, out.String())
	}
	return err.Error() + "\n" + errOut.String()
}

func assertNoCredentialLeak(t *testing.T, output string) {
	t.Helper()
	for _, secret := range []string{
		"login-secret",
		"key-secret",
		"id_ed25519",
		"password",
		"identityPassphrase",
		"identityFile",
	} {
		if strings.Contains(output, secret) {
			t.Fatalf("output leaked %q: %q", secret, output)
		}
	}
}
