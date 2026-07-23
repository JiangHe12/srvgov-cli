package srvgovctx

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
)

func TestContextNormalizeFromServer(t *testing.T) {
	ctx := Context{
		Base: corectx.Base{Server: "ssh://alice@example.com:2222"},
	}

	if err := ctx.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if ctx.Host != "example.com" || ctx.Port != 2222 || ctx.Username != "alice" {
		t.Fatalf("Normalize() = host %q port %d username %q", ctx.Host, ctx.Port, ctx.Username)
	}
}

func TestContextNormalizeDefaultsAndBuildsServer(t *testing.T) {
	ctx := Context{
		Base: corectx.Base{Username: "root"},
		Host: "server.internal",
	}

	if err := ctx.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if ctx.Port != 22 {
		t.Fatalf("Port = %d, want 22", ctx.Port)
	}
	if ctx.Server != "ssh://root@server.internal:22" {
		t.Fatalf("Server = %q", ctx.Server)
	}
	if len(ctx.AuthMethods) != 3 ||
		ctx.AuthMethods[0] != AuthPrivateKey ||
		ctx.AuthMethods[1] != AuthAgent ||
		ctx.AuthMethods[2] != AuthPassword {
		t.Fatalf("AuthMethods = %v", ctx.AuthMethods)
	}
}

func TestContextNormalizeRejectsInvalidServer(t *testing.T) {
	ctx := Context{Base: corectx.Base{Server: "mysql://example.com:3306"}}
	if err := ctx.Normalize(); err == nil {
		t.Fatal("Normalize() error = nil")
	}
}

func TestContextNormalizeRejectsCredentialsInServerURI(t *testing.T) {
	ctx := Context{Base: corectx.Base{Server: "ssh://alice:uri-secret@example.com:22"}}
	if err := ctx.Normalize(); err == nil {
		t.Fatal("Normalize() error = nil")
	}
}

func TestContextNormalizeCanonicalizesServer(t *testing.T) {
	ctx := Context{
		Base: corectx.Base{Server: "ssh://alice@example.com:2222"},
		Port: 2200,
	}
	if err := ctx.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if ctx.Server != "ssh://alice@example.com:2200" {
		t.Fatalf("Server = %q", ctx.Server)
	}
}

func TestContextNormalizeCanonicalizesAuthenticationOrder(t *testing.T) {
	ctx := Context{
		Host:        "example.com",
		AuthMethods: []string{AuthPassword, AuthPrivateKey},
	}
	if err := ctx.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if len(ctx.AuthMethods) != 2 || ctx.AuthMethods[0] != AuthPrivateKey || ctx.AuthMethods[1] != AuthPassword {
		t.Fatalf("AuthMethods = %v", ctx.AuthMethods)
	}
}

func TestContextNormalizeDoesNotMutateSharedAuthenticationBackingArray(t *testing.T) {
	shared := []string{AuthPassword, AuthPrivateKey}
	ctx := Context{
		Host:        "example.com",
		AuthMethods: shared,
	}
	if err := ctx.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	if shared[0] != AuthPassword || shared[1] != AuthPrivateKey {
		t.Fatalf("shared AuthMethods mutated to %v", shared)
	}
	if len(ctx.AuthMethods) != 2 || ctx.AuthMethods[0] != AuthPrivateKey || ctx.AuthMethods[1] != AuthPassword {
		t.Fatalf("normalized AuthMethods = %v", ctx.AuthMethods)
	}
}

func TestStoreLifecycle(t *testing.T) {
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	t.Cleanup(func() {
		corectx.Configure(corectx.Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
	})
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	SetConfigPath(configPath)
	t.Cleanup(func() { SetConfigPath("") })

	item := Context{
		Base:         corectx.Base{Username: "alice", Password: "not-for-output"},
		Host:         "127.0.0.1",
		Port:         2222,
		IdentityFile: "/tmp/id_test",
	}
	if err := SetContext("dev", item); err != nil {
		t.Fatalf("SetContext() error = %v", err)
	}
	if err := UseContext("dev"); err != nil {
		t.Fatalf("UseContext() error = %v", err)
	}

	current, name, err := Current()
	if err != nil {
		t.Fatalf("Current() error = %v", err)
	}
	if name != "dev" || current.Host != item.Host || current.IdentityFile != item.IdentityFile {
		t.Fatalf("Current() = %q %#v", name, current)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.APIVersion != SupportedContextAPIVersion {
		t.Fatalf("APIVersion = %q", cfg.APIVersion)
	}

	if err := DeleteContext("dev"); err != nil {
		t.Fatalf("DeleteContext() error = %v", err)
	}
}

func TestLoadTranslatesLegacyContextAPIVersionWithoutWriting(t *testing.T) {
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	t.Cleanup(func() {
		corectx.Configure(corectx.Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
		SetConfigPath("")
	})
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`apiVersion: srvgov.io/context/v1
current-context: dev
contexts:
    dev:
        host: 127.0.0.1
        port: 22
`), 0o600); err != nil {
		t.Fatal(err)
	}
	SetConfigPath(configPath)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.APIVersion != SupportedContextAPIVersion {
		t.Fatalf("APIVersion = %q, want %q", cfg.APIVersion, SupportedContextAPIVersion)
	}
	if _, name, err := Current(); err != nil || name != "dev" {
		t.Fatalf("Current() = %q, %v", name, err)
	}
	unchanged, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unchanged), legacyContextAPIVersion) || strings.Contains(string(unchanged), SupportedContextAPIVersion) {
		t.Fatalf("read-only load rewrote legacy context file:\n%s", unchanged)
	}
}

func TestLegacyContextAPIVersionMigratesAtomicallyOnWrite(t *testing.T) {
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	t.Cleanup(func() {
		corectx.Configure(corectx.Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
		SetConfigPath("")
	})
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte(`apiVersion: srvgov.io/context/v1
current-context: dev
contexts:
    dev:
        host: 127.0.0.1
        port: 22
`), 0o600); err != nil {
		t.Fatal(err)
	}
	SetConfigPath(configPath)

	if err := SetContext("staging", Context{Host: "127.0.0.2", Port: 22}); err != nil {
		t.Fatalf("SetContext() error = %v", err)
	}
	updated, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), legacyContextAPIVersion) || !strings.Contains(string(updated), SupportedContextAPIVersion) {
		t.Fatalf("context file was not migrated on write:\n%s", updated)
	}
	if leftovers, err := filepath.Glob(filepath.Join(dir, ".config-migrate-*.tmp")); err != nil || len(leftovers) != 0 {
		t.Fatalf("migration temp files = %v, error = %v", leftovers, err)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(configPath)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o600 {
			t.Fatalf("context mode = %#o, want 0600", got)
		}
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Contexts) != 2 || cfg.Contexts["staging"].Host != "127.0.0.2" {
		t.Fatalf("contexts after migration = %#v", cfg.Contexts)
	}
}

func TestRejectedLegacyUpdateDoesNotMigrateOrRewrite(t *testing.T) {
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	t.Cleanup(func() {
		corectx.Configure(corectx.Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
		SetConfigPath("")
	})
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	legacy := []byte(`apiVersion: srvgov.io/context/v1
current-context: dev
contexts:
    dev:
        host: 127.0.0.1
        port: 22
`)
	if err := os.WriteFile(configPath, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	SetConfigPath(configPath)

	err := Update(func(*Config) error {
		return apperrors.New(apperrors.CodeAuthorizationRequired, "test denial", nil)
	})
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeAuthorizationRequired {
		t.Fatalf("Update() code = %s, want %s; error = %v", got, apperrors.CodeAuthorizationRequired, err)
	}
	unchanged, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(unchanged) != string(legacy) {
		t.Fatalf("rejected update rewrote legacy config:\n%s", unchanged)
	}
}

func TestConcurrentWritesDoNotLoseContextsDuringLegacyMigration(t *testing.T) {
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	t.Cleanup(func() {
		corectx.Configure(corectx.Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
		SetConfigPath("")
	})
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(configPath, []byte(`apiVersion: srvgov.io/context/v1
current-context: dev
contexts:
    dev:
        host: 127.0.0.1
        port: 22
`), 0o600); err != nil {
		t.Fatal(err)
	}
	SetConfigPath(configPath)

	const writers = 12
	errs := make(chan error, writers)
	var group sync.WaitGroup
	for i := 0; i < writers; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			errs <- SetContext(
				fmt.Sprintf("node-%02d", index),
				Context{Host: fmt.Sprintf("192.0.2.%d", index+1), Port: 22},
			)
		}(i)
	}
	group.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent SetContext() error = %v", err)
		}
	}
	cfg, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if got := len(cfg.Contexts); got != writers+1 {
		t.Fatalf("contexts = %d, want %d: %#v", got, writers+1, cfg.Contexts)
	}
}

func TestLegacyLoadRejectsInsecurePermissionsWithoutWriting(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX permission bits are not authoritative on Windows")
	}
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	t.Cleanup(func() {
		corectx.Configure(corectx.Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
		SetConfigPath("")
	})
	configPath := filepath.Join(t.TempDir(), "config.yaml")
	legacy := []byte("apiVersion: " + legacyContextAPIVersion + "\ncontexts: {}\n")
	if err := os.WriteFile(configPath, legacy, 0o644); err != nil {
		t.Fatal(err)
	}
	SetConfigPath(configPath)

	_, err := Load()
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("Load() code = %s, want %s; error = %v", got, apperrors.CodeLocalIOError, err)
	}
	if !strings.Contains(err.Error(), "secure file has mode 0644; want 0600") {
		t.Fatalf("Load() error = %v, want insecure mode rejection", err)
	}
	unchanged, readErr := os.ReadFile(configPath)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(unchanged) != string(legacy) {
		t.Fatalf("insecure legacy file was rewritten: %q", unchanged)
	}
}

func TestLegacyContextMigrationRejectsSymlink(t *testing.T) {
	corectx.Configure(corectx.Options{APIVersion: SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	t.Cleanup(func() {
		corectx.Configure(corectx.Options{APIVersion: "opskit-core.io/context/v1", ConfigDirName: ".opskit"})
		SetConfigPath("")
	})
	dir := t.TempDir()
	target := filepath.Join(dir, "legacy.yaml")
	legacy := []byte("apiVersion: " + legacyContextAPIVersion + "\ncontexts: {}\n")
	if err := os.WriteFile(target, legacy, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.Symlink(target, configPath); err != nil {
		t.Skipf("symlink creation is unavailable: %v", err)
	}
	SetConfigPath(configPath)

	if _, err := Load(); apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
		t.Fatalf("Load() error = %v, want LOCAL_IO_ERROR", err)
	}
	if err := SetContext("dev", Context{Host: "127.0.0.1", Port: 22}); apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
		t.Fatalf("SetContext() error = %v, want LOCAL_IO_ERROR", err)
	}
	unchanged, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(unchanged) != string(legacy) {
		t.Fatalf("legacy symlink target was rewritten: %q", unchanged)
	}
}
