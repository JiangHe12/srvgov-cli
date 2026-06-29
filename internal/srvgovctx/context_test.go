package srvgovctx

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	corectx "github.com/JiangHe12/opskit-core/ctx"
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

func TestLoadMigratesLegacyContextAPIVersion(t *testing.T) {
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
	updated, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(updated), legacyContextAPIVersion) || !strings.Contains(string(updated), SupportedContextAPIVersion) {
		t.Fatalf("context file was not migrated:\n%s", updated)
	}
}
