package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestContextCommandsLifecycleAndRedaction(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")

	runCommand(t, configPath,
		"ctx", "set", "dev",
		"--server", "ssh://alice@example.com:2222",
		"--password", "login-secret",
		"--identity-file", "/home/alice/.ssh/id_ed25519",
		"--identity-passphrase", "key-secret",
	)
	runCommand(t, configPath, "ctx", "use", "dev")

	current := runCommand(t, configPath, "-o", "json", "ctx", "current")
	var view contextView
	if err := json.Unmarshal([]byte(current), &view); err != nil {
		t.Fatalf("current JSON error = %v; output = %q", err, current)
	}
	if view.Name != "dev" || view.Host != "example.com" || view.Port != 2222 || view.Username != "alice" {
		t.Fatalf("current view = %#v", view)
	}
	assertNoCredentialLeak(t, current)

	list := runCommand(t, configPath, "-o", "json", "ctx", "list")
	assertNoCredentialLeak(t, list)
	if !strings.Contains(list, `"name": "dev"`) {
		t.Fatalf("list output = %q", list)
	}

	runCommand(t, configPath, "ctx", "delete", "dev")
	currentAfterDelete := runCommandError(t, configPath, "ctx", "current")
	if !strings.Contains(currentAfterDelete, "no current context set") {
		t.Fatalf("current error = %q", currentAfterDelete)
	}
}

func TestContextLabelsDisplayAndPortableRoundTrip(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")

	runCommand(t, configPath,
		"ctx", "set", "prod",
		"--server", "ssh://alice@example.com:22",
		"--label", "env=prod",
		"--label", "role=web",
	)
	runCommand(t, configPath, "ctx", "use", "prod")

	current := runCommand(t, configPath, "-o", "json", "ctx", "current")
	var view contextView
	if err := json.Unmarshal([]byte(current), &view); err != nil {
		t.Fatalf("current JSON error = %v; output = %q", err, current)
	}
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
	runCommand(t, importConfig, "ctx", "import", "-f", importFile, "--rename", "prod-copy", "--yes")
	runCommand(t, importConfig, "ctx", "use", "prod-copy")
	imported := runCommand(t, importConfig, "-o", "json", "ctx", "current")
	var importedView contextView
	if err := json.Unmarshal([]byte(imported), &importedView); err != nil {
		t.Fatalf("imported current JSON error = %v; output = %q", err, imported)
	}
	if importedView.Labels["env"] != "prod" || importedView.Labels["role"] != "web" {
		t.Fatalf("imported labels = %#v", importedView.Labels)
	}
}

func TestContextSetRejectsInvalidLabels(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	for _, label := range []string{"env", "=prod", "env="} {
		output := runCommandError(t, configPath,
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
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	output := runCommandError(t, configPath, "ctx", "set", "bad", "--server", "mysql://db:3306")
	if !strings.Contains(output, "SSH server must use ssh://") {
		t.Fatalf("error output = %q", output)
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
