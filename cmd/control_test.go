package cmd

import (
	"bytes"
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestTrustedOperatorResolutionFailsClosed(t *testing.T) {
	var out, errOut bytes.Buffer
	root := newRootCmdWith(&cliFlags{
		Output: "table",
		resolveOperator: func() (string, error) {
			return "", errors.New("identity unavailable")
		},
	})
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"version"})

	err := root.Execute()
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
}

func TestOperatorFlagAndEnvironmentCannotSpoofContextAuthorizationOrAudit(t *testing.T) {
	for _, test := range []struct {
		name string
		args []string
		env  string
	}{
		{name: "flag", args: []string{"--operator", "spoofed-admin"}},
		{name: "environment", env: "spoofed-admin"},
	} {
		t.Run(test.name, func(t *testing.T) {
			configPath := isolatedContextConfig(t)
			operator := mustTrustedOperator(t)
			item := testServerContext("before.example")
			item.Roles = map[string]string{
				operator:        "reader",
				"spoofed-admin": "admin",
			}
			mustSetContext(t, configPath, "guarded", item)
			t.Setenv("SRVGOV_OPERATOR", test.env)

			args := append([]string{}, test.args...)
			args = append(args,
				"--ticket", "TEST-1", "--yes", "--allow-context-change",
				"ctx", "set", "guarded", "--server", "ssh://alice@after.example:22", "--protected",
			)
			_, err := executeRoot(t, configPath, args...)
			assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)

			cfg, loadErr := srvgovctx.Load()
			if loadErr != nil {
				t.Fatalf("Load() error = %v", loadErr)
			}
			if cfg.Contexts["guarded"].Host != "before.example" || cfg.Contexts["guarded"].Protected {
				t.Fatalf("context changed after spoofed authorization: %#v", cfg.Contexts["guarded"])
			}
			events := readAuditEvents(t)
			if len(events) != 1 ||
				events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied ||
				events[0].Operator != operator ||
				events[0].Status != srvgovaudit.StatusDenied {
				t.Fatalf("audit events = %#v, want trusted operator %q", events, operator)
			}
		})
	}
}

func TestContextCreateUsesCurrentPreChangePolicyAndBootstrapStillRequiresR3(t *testing.T) {
	operator := mustTrustedOperator(t)

	t.Run("current policy denies", func(t *testing.T) {
		configPath := isolatedContextConfig(t)
		guard := testServerContext("guard.example")
		guard.Roles = map[string]string{operator: "reader"}
		mustSetContext(t, configPath, "guard", guard)
		if err := srvgovctx.UseContext("guard"); err != nil {
			t.Fatalf("UseContext() error = %v", err)
		}

		_, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "set", "new", "--server", "ssh://alice@new.example:22",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
		cfg, loadErr := srvgovctx.Load()
		if loadErr != nil {
			t.Fatalf("Load() error = %v", loadErr)
		}
		if _, exists := cfg.Contexts["new"]; exists {
			t.Fatalf("new context was written despite current pre-policy denial")
		}
	})

	t.Run("empty bootstrap requires exact allow", func(t *testing.T) {
		configPath := isolatedContextConfig(t)
		_, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-role-change",
			"ctx", "set", "new", "--server", "ssh://alice@new.example:22",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)

		if _, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "set", "new", "--server", "ssh://alice@new.example:22",
		); err != nil {
			t.Fatalf("bootstrap ctx set error = %v", err)
		}
	})
}

func TestContextUseCannotSwitchToAWeakerPolicyBeforeCreatingTargets(t *testing.T) {
	operator := mustTrustedOperator(t)

	t.Run("old current policy controls switch", func(t *testing.T) {
		configPath := isolatedContextConfig(t)
		strong := testServerContext("strong.example")
		strong.Roles = map[string]string{operator: "reader"}
		mustSetContext(t, configPath, "strong", strong)
		mustSetContext(t, configPath, "weak", testServerContext("weak.example"))
		if err := srvgovctx.UseContext("strong"); err != nil {
			t.Fatalf("UseContext() error = %v", err)
		}

		_, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "use", "weak",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
		cfg, loadErr := srvgovctx.Load()
		if loadErr != nil {
			t.Fatalf("Load() error = %v", loadErr)
		}
		if cfg.CurrentContext != "strong" {
			t.Fatalf("current context = %q, want strong", cfg.CurrentContext)
		}
	})

	t.Run("target policy controls first selection", func(t *testing.T) {
		configPath := isolatedContextConfig(t)
		guarded := testServerContext("guarded.example")
		guarded.Roles = map[string]string{operator: "reader"}
		mustSetContext(t, configPath, "guarded", guarded)

		_, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "use", "guarded",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)

		mustSetContext(t, configPath, "bootstrap", testServerContext("bootstrap.example"))
		if _, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "use", "bootstrap",
		); err != nil {
			t.Fatalf("bootstrap ctx use error = %v", err)
		}
	})
}

func TestContextDeleteAndRoleChangesRequireTheirExactAllowFlags(t *testing.T) {
	t.Run("delete", func(t *testing.T) {
		configPath := isolatedContextConfig(t)
		mustSetContext(t, configPath, "dev", testServerContext("dev.example"))

		_, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "delete", "dev",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
		if _, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-delete",
			"ctx", "delete", "dev",
		); err != nil {
			t.Fatalf("ctx delete error = %v", err)
		}

		operator := mustTrustedOperator(t)
		guarded := testServerContext("guarded.example")
		guarded.Roles = map[string]string{operator: "reader"}
		mustSetContext(t, configPath, "guarded", guarded)
		_, err = executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-delete",
			"ctx", "delete", "guarded",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	})

	t.Run("role", func(t *testing.T) {
		configPath := isolatedContextConfig(t)
		mustSetContext(t, configPath, "dev", testServerContext("dev.example"))

		_, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-context-change",
			"ctx", "role", "set", "dev", "--target-operator", "alice", "--role", "reader",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
		if _, err := executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-role-change",
			"ctx", "role", "set", "dev", "--target-operator", "alice", "--role", "reader",
		); err != nil {
			t.Fatalf("ctx role set error = %v", err)
		}
		_, err = executeRoot(t, configPath,
			"--ticket", "TEST-1", "--yes", "--allow-role-change",
			"ctx", "role", "unset", "dev", "--target-operator", "alice",
		)
		assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	})
}

func TestCredentialMigrationAuthorizesEveryContextBeforeAnyWrite(t *testing.T) {
	configPath := isolatedContextConfig(t)
	operator := mustTrustedOperator(t)
	alpha := testServerContext("alpha.example")
	alpha.Password = "alpha-secret"
	alpha.Roles = map[string]string{operator: "admin"}
	bravo := testServerContext("bravo.example")
	bravo.Password = "bravo-secret"
	bravo.Roles = map[string]string{"spoofed-admin": "admin"}
	mustSetContext(t, configPath, "alpha", alpha)
	mustSetContext(t, configPath, "bravo", bravo)

	backend := newMemoryCredentialBackend()
	restore := replaceCredentialBackendFactory(backend)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "migrate-credentials", "--to", "encrypted-file",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
	if backend.putCalls != 0 || len(backend.values) != 0 {
		t.Fatalf("credential writes = %d / %#v, want none", backend.putCalls, backend.values)
	}
	cfg, loadErr := srvgovctx.Load()
	if loadErr != nil {
		t.Fatalf("Load() error = %v", loadErr)
	}
	if cfg.Contexts["alpha"].Password != "alpha-secret" || cfg.Contexts["bravo"].Password != "bravo-secret" {
		t.Fatalf("contexts partially migrated: %#v", cfg.Contexts)
	}
}

func TestCredentialMigrationRollsBackBackendWritesOnFailure(t *testing.T) {
	configPath := isolatedContextConfig(t)
	alpha := testServerContext("alpha.example")
	alpha.Password = "alpha-secret"
	bravo := testServerContext("bravo.example")
	bravo.Password = "bravo-secret"
	mustSetContext(t, configPath, "alpha", alpha)
	mustSetContext(t, configPath, "bravo", bravo)

	backend := newMemoryCredentialBackend()
	backend.values["alpha"] = "previous-alpha"
	backend.failPut = "bravo"
	restore := replaceCredentialBackendFactory(backend)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "migrate-credentials", "--to", "encrypted-file",
	)
	assertAppError(t, err, apperrors.CodeCredentialStoreError, 6)
	if len(backend.values) != 1 || backend.values["alpha"] != "previous-alpha" {
		t.Fatalf("credential rollback values = %#v", backend.values)
	}
	cfg, loadErr := srvgovctx.Load()
	if loadErr != nil {
		t.Fatalf("Load() error = %v", loadErr)
	}
	if cfg.Contexts["alpha"].Password != "alpha-secret" || cfg.Contexts["bravo"].Password != "bravo-secret" {
		t.Fatalf("contexts partially migrated: %#v", cfg.Contexts)
	}
}

func TestCredentialMigrationReportsUncertainBackendWhenCompensationFails(t *testing.T) {
	configPath := isolatedContextConfig(t)
	alpha := testServerContext("alpha.example")
	alpha.Password = "alpha-secret"
	bravo := testServerContext("bravo.example")
	bravo.Password = "bravo-secret"
	mustSetContext(t, configPath, "alpha", alpha)
	mustSetContext(t, configPath, "bravo", bravo)

	backend := newMemoryCredentialBackend()
	backend.values["alpha"] = "previous-alpha"
	backend.failPut = "bravo"
	backend.failDelete = "bravo"
	restore := replaceCredentialBackendFactory(backend)
	t.Cleanup(restore)

	_, err := executeRoot(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "migrate-credentials", "--to", "encrypted-file",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	if !strings.Contains(apperrors.AsAppError(err).Suggestion, "before any retry") {
		t.Fatalf("suggestion = %q, want inspect-before-retry guidance", apperrors.AsAppError(err).Suggestion)
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeCredentialMigrate), "alpha", "R3")
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Outcome == nil ||
		outcome.Outcome.Uncertain != 2 ||
		outcome.Outcome.Failed != 0 {
		t.Fatalf("credential migration outcome = %#v", outcome)
	}
}

func TestCredentialMigrationReportsUncertainBackendWhenCanceledCompensationFails(t *testing.T) {
	configPath := isolatedContextConfig(t)
	item := testServerContext("dev.example")
	item.Password = "legacy-password"
	mustSetContext(t, configPath, "dev", item)

	commandContext, cancel := context.WithCancel(context.Background())
	backend := newMemoryCredentialBackend()
	backend.cancelOnPut = "dev"
	backend.cancel = cancel
	backend.failDelete = "dev"
	restore := replaceCredentialBackendFactory(backend)
	t.Cleanup(restore)

	var output bytes.Buffer
	root := NewRootCmd()
	root.SetContext(commandContext)
	root.SetOut(&output)
	root.SetErr(&output)
	root.SetArgs([]string{
		"--config", configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "migrate-credentials", "--to", "encrypted-file", "--context", "dev",
	})
	err := root.Execute()
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	if !strings.Contains(apperrors.AsAppError(err).Suggestion, "before any retry") {
		t.Fatalf("suggestion = %q, want inspect-before-retry guidance", apperrors.AsAppError(err).Suggestion)
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeCredentialMigrate), "dev", "R3")
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Outcome == nil ||
		outcome.Outcome.Uncertain != 1 ||
		outcome.Outcome.Failed != 0 {
		t.Fatalf("credential migration outcome = %#v", outcome)
	}
}

func TestCredentialMigrationDoesNotBlindlyCompensateUnknownConfigCommit(t *testing.T) {
	configPath := isolatedContextConfig(t)
	item := testServerContext("dev.example")
	item.Password = "legacy-password"
	item.IdentityPassphrase = "legacy-passphrase"
	item.CredentialBackend = "plain-yaml"
	mustSetContext(t, configPath, "dev", item)

	backend := newMemoryCredentialBackend()
	restoreBackend := replaceCredentialBackendFactory(backend)
	t.Cleanup(restoreBackend)
	previousUpdate := updateCredentialMigrationContexts
	updateCredentialMigrationContexts = func(fn func(*srvgovctx.Config) error) error {
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
	t.Cleanup(func() { updateCredentialMigrationContexts = previousUpdate })

	_, err := executeRoot(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-context-change",
		"ctx", "migrate-credentials", "--to", "encrypted-file", "--context", "dev",
	)
	assertAppError(t, err, apperrors.CodePartialFailure, 11)
	if !strings.Contains(apperrors.AsAppError(err).Suggestion, "before any retry") {
		t.Fatalf("suggestion = %q, want verify-before-retry guidance", apperrors.AsAppError(err).Suggestion)
	}
	if backend.values["dev"] != "legacy-password" ||
		backend.values["dev#identity"] != "legacy-passphrase" {
		t.Fatalf("credentials were blindly compensated: %#v", backend.values)
	}
	cfg, loadErr := srvgovctx.Load()
	if loadErr != nil {
		t.Fatalf("Load() error = %v", loadErr)
	}
	if cfg.Contexts["dev"].Password != "legacy-password" ||
		cfg.Contexts["dev"].IdentityPassphrase != "legacy-passphrase" {
		t.Fatalf("test configuration unexpectedly committed: %#v", cfg.Contexts["dev"])
	}
	events := readAuditEvents(t)
	_, outcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeCredentialMigrate), "dev", "R3")
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Outcome == nil ||
		outcome.Outcome.Uncertain != 1 ||
		outcome.Outcome.Failed != 0 {
		t.Fatalf("credential migration outcome = %#v", outcome)
	}
}

func mustTrustedOperator(t *testing.T) string {
	t.Helper()
	operator, err := resolveOSOperator()
	if err != nil {
		t.Fatalf("resolveOSOperator() error = %v", err)
	}
	return operator
}

func isolatedContextConfig(t *testing.T) string {
	t.Helper()
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	if err := createPrivateMutationAuditDirectory(filepath.Join(home, ".srvgov")); err != nil {
		t.Fatalf("create isolated audit directory: %v", err)
	}
	configPath := filepath.Join(home, "config.yaml")
	srvgovctx.SetConfigPath(configPath)
	return configPath
}

func testServerContext(host string) srvgovctx.Context {
	return srvgovctx.Context{
		Base: corectx.Base{
			OTLPRedact: true,
			Username:   "alice",
		},
		Host: host,
		Port: 22,
	}
}

func mustSetContext(t *testing.T, configPath, name string, item srvgovctx.Context) {
	t.Helper()
	srvgovctx.SetConfigPath(configPath)
	if err := srvgovctx.SetContext(name, item); err != nil {
		t.Fatalf("SetContext(%q) error = %v", name, err)
	}
}

type memoryCredentialBackend struct {
	values      map[string]string
	failPut     string
	failDelete  string
	cancelOnPut string
	cancel      context.CancelFunc
	putCalls    int
}

func newMemoryCredentialBackend() *memoryCredentialBackend {
	return &memoryCredentialBackend{values: map[string]string{}}
}

func (b *memoryCredentialBackend) Name() string { return "memory" }

func (b *memoryCredentialBackend) Get(_ context.Context, name string) (string, error) {
	value, ok := b.values[name]
	if !ok {
		return "", credstore.ErrNotFound
	}
	return value, nil
}

func (b *memoryCredentialBackend) Put(_ context.Context, name, value string) error {
	b.putCalls++
	if name == b.failPut {
		return errors.New("injected put failure")
	}
	b.values[name] = value
	if name == b.cancelOnPut && b.cancel != nil {
		b.cancel()
	}
	return nil
}

func (b *memoryCredentialBackend) Delete(_ context.Context, name string) error {
	if name == b.failDelete {
		return errors.New("injected delete failure")
	}
	if _, ok := b.values[name]; !ok {
		return credstore.ErrNotFound
	}
	delete(b.values, name)
	return nil
}

func (b *memoryCredentialBackend) Available() error { return nil }

func replaceCredentialBackendFactory(backend credstore.Backend) func() {
	previous := newCredentialBackend
	newCredentialBackend = func(string) (credstore.Backend, error) {
		return backend, nil
	}
	return func() {
		newCredentialBackend = previous
	}
}
