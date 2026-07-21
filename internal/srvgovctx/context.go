// Package srvgovctx defines and persists srvgov server contexts.
package srvgovctx

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
	"gopkg.in/yaml.v3"
)

const (
	SupportedContextAPIVersion = "srvgov-cli.io/context/v1"
	legacyContextAPIVersion    = "srvgov.io/context/v1"
	AuthPrivateKey             = "private-key"
	AuthAgent                  = "agent"
	AuthPassword               = "password"
)

var defaultAuthMethods = []string{AuthPrivateKey, AuthAgent, AuthPassword}

// Context is one governed SSH target.
type Context struct {
	corectx.Base `yaml:",inline"`

	Host               string            `yaml:"host"`
	Port               int               `yaml:"port"`
	IdentityFile       string            `yaml:"identityFile,omitempty"`
	IdentityPassphrase string            `yaml:"identityPassphrase,omitempty"`
	AuthMethods        []string          `yaml:"authMethods,omitempty"`
	Labels             map[string]string `yaml:"labels,omitempty"`
}

var (
	configPathOverride string
	store              = corectx.NewStore(func(c *Context) *corectx.Base { return &c.Base })
	contextStoreMu     sync.Mutex
)

// Config is the srvgov context configuration.
type Config = corectx.Config[Context]

// Normalize derives SSH fields and validates the context.
func (c *Context) Normalize() error {
	if c.Server != "" {
		if err := c.applyServer(); err != nil {
			return err
		}
	}
	if c.Host == "" {
		return apperrors.New(apperrors.CodeUsageError, "SSH host is required", nil)
	}
	if c.Port == 0 {
		c.Port = 22
	}
	if c.Port < 1 || c.Port > 65535 {
		return apperrors.New(apperrors.CodeUsageError, "SSH port must be between 1 and 65535", nil)
	}
	c.Server = sshServer(c.Username, c.Host, c.Port)
	if len(c.AuthMethods) == 0 {
		c.AuthMethods = append([]string(nil), defaultAuthMethods...)
	}
	enabledMethods := make(map[string]bool, len(c.AuthMethods))
	for _, method := range c.AuthMethods {
		switch method {
		case AuthPrivateKey, AuthAgent, AuthPassword:
			enabledMethods[method] = true
		default:
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("unsupported SSH auth method %q", method), nil)
		}
	}
	normalizedMethods := make([]string, 0, len(enabledMethods))
	for _, method := range defaultAuthMethods {
		if enabledMethods[method] {
			normalizedMethods = append(normalizedMethods, method)
		}
	}
	c.AuthMethods = normalizedMethods
	return nil
}

// ResolveIdentityPassphraseContext resolves a literal or credstore-backed key passphrase.
func (c Context) ResolveIdentityPassphraseContext(ctx context.Context, contextName string) (string, error) {
	base := c.Base
	base.Password = c.IdentityPassphrase
	return base.ResolvePasswordContext(ctx, contextName+"#identity")
}

func (c *Context) applyServer() error {
	parsed, err := url.Parse(c.Server)
	if err != nil {
		return apperrors.New(apperrors.CodeUsageError, "invalid SSH server URI", err)
	}
	if err := validateServerURI(parsed); err != nil {
		return err
	}
	if c.Host == "" {
		c.Host = parsed.Hostname()
	}
	if c.Username == "" && parsed.User != nil {
		c.Username = parsed.User.Username()
	}
	if c.Port == 0 && parsed.Port() != "" {
		port, err := strconv.Atoi(parsed.Port())
		if err != nil {
			return apperrors.New(apperrors.CodeUsageError, "invalid SSH server port", err)
		}
		c.Port = port
	}
	return nil
}

func validateServerURI(parsed *url.URL) error {
	if parsed.Scheme != "ssh" || parsed.Hostname() == "" {
		return apperrors.New(apperrors.CodeUsageError, "SSH server must use ssh:// with a host", nil)
	}
	if parsed.User != nil {
		if _, hasPassword := parsed.User.Password(); hasPassword {
			return apperrors.New(apperrors.CodeUsageError, "SSH server URI must not contain a password", nil)
		}
	}
	if parsed.Path != "" && parsed.Path != "/" || parsed.RawQuery != "" || parsed.Fragment != "" {
		return apperrors.New(apperrors.CodeUsageError, "SSH server URI must not contain a path, query, or fragment", nil)
	}
	return nil
}

func sshServer(username, host string, port int) string {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	server := &url.URL{Scheme: "ssh", Host: address}
	if username != "" {
		server.User = url.User(username)
	}
	return server.String()
}

// Address returns the canonical host:port used for dialing and host-key pins.
func (c Context) Address() string {
	return net.JoinHostPort(strings.TrimSpace(c.Host), strconv.Itoa(c.Port))
}

// SetConfigPath overrides the core context file path for this process.
func SetConfigPath(path string) {
	configPathOverride = path
	corectx.SetConfigPath(path)
}

// Load loads all contexts. Legacy apiVersion values are translated in memory;
// read-only callers never rewrite the context file.
func Load() (*Config, error) {
	contextStoreMu.Lock()
	defer contextStoreMu.Unlock()

	cfg, err := store.Load()
	if err == nil || apperrors.AsAppError(err).Code != apperrors.CodeUnsupportedProtocol {
		return cfg, err
	}
	return loadLegacyContextConfig()
}

// SetContext adds or updates a normalized context.
func SetContext(name string, item Context) error {
	if err := item.Normalize(); err != nil {
		return err
	}
	return Update(func(cfg *Config) error {
		cfg.Contexts[name] = item
		return nil
	})
}

// Update performs one locked read-modify-write cycle for multi-context changes.
func Update(fn func(cfg *Config) error) error {
	contextStoreMu.Lock()
	defer contextStoreMu.Unlock()

	_, err := store.Load()
	if err == nil {
		return store.Update(fn)
	}
	if apperrors.AsAppError(err).Code != apperrors.CodeUnsupportedProtocol {
		return err
	}
	handled, err := updateLegacyContextConfig(fn)
	if err != nil || handled {
		return err
	}
	// A concurrent process upgraded or removed the legacy file while this
	// process waited for the core lock. Let core perform a fresh update.
	return store.Update(fn)
}

// UseContext switches the active context.
func UseContext(name string) error {
	return Update(func(cfg *Config) error {
		if _, ok := cfg.Contexts[name]; !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
		}
		cfg.CurrentContext = name
		return nil
	})
}

// Current returns the active context.
func Current() (*Context, string, error) {
	cfg, err := Load()
	if err != nil {
		return nil, "", err
	}
	if cfg.CurrentContext == "" {
		return nil, "", apperrors.New(apperrors.CodeUsageError, "no current context set", nil)
	}
	item, ok := cfg.Contexts[cfg.CurrentContext]
	if !ok {
		return nil, "", apperrors.New(
			apperrors.CodeUsageError,
			fmt.Sprintf("context %q not found", cfg.CurrentContext),
			nil,
		)
	}
	return &item, cfg.CurrentContext, nil
}

// DeleteContext removes a context.
func DeleteContext(name string) error {
	return Update(func(cfg *Config) error {
		if _, ok := cfg.Contexts[name]; !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
		}
		delete(cfg.Contexts, name)
		if cfg.CurrentContext == name {
			cfg.CurrentContext = ""
		}
		return nil
	})
}

func loadLegacyContextConfig() (*Config, error) {
	path, err := configPath()
	if err != nil {
		return nil, err
	}
	lock := lockfile.New(filepath.Join(filepath.Dir(path), "config"))
	if err := lock.Acquire(); err != nil {
		return nil, err
	}
	defer func() { _ = lock.Release() }()
	if _, err := inspectContextConfigPath(path); err != nil {
		return nil, err
	}

	// Re-read after taking the same lock used by core context mutations. A
	// concurrent writer may already have upgraded or removed the file.
	cfg, loadErr := store.Load()
	if loadErr == nil || apperrors.AsAppError(loadErr).Code != apperrors.CodeUnsupportedProtocol {
		return cfg, loadErr
	}
	data, err := os.ReadFile(path) //nolint:gosec // The configured file was permission-checked by store.Load under the lock.
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read context file", err)
	}
	return decodeLegacyContextConfig(data, loadErr)
}

func decodeLegacyContextConfig(data []byte, unsupportedErr error) (*Config, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to parse context file", err)
	}
	if cfg.APIVersion != legacyContextAPIVersion {
		return nil, unsupportedErr
	}
	cfg.APIVersion = SupportedContextAPIVersion
	if cfg.Contexts == nil {
		cfg.Contexts = make(map[string]Context)
	}
	applyLegacyContextDefaults(data, &cfg)
	for name, item := range cfg.Contexts {
		ref := credstore.ParseRef(item.Password)
		if ref.IsRef && ref.BackendName == "" {
			return nil, apperrors.New(
				apperrors.CodeUsageError,
				fmt.Sprintf("context %q has empty credential store reference", name),
				nil,
			)
		}
	}
	return &cfg, nil
}

func applyLegacyContextDefaults(data []byte, cfg *Config) {
	if cfg == nil || len(cfg.Contexts) == 0 {
		return
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(data, &doc); err != nil || len(doc.Content) == 0 {
		return
	}
	contexts := yamlMappingValue(doc.Content[0], "contexts")
	if contexts == nil || contexts.Kind != yaml.MappingNode {
		return
	}
	for name, item := range cfg.Contexts {
		itemNode := yamlMappingValue(contexts, name)
		if itemNode != nil && itemNode.Kind == yaml.MappingNode && yamlMappingValue(itemNode, "otlpRedact") == nil {
			item.OTLPRedact = true
		}
		if item.OTLPEndpointSource == "" {
			item.OTLPEndpointSource = "auto"
		}
		if item.OTLPMetricsSource == "" {
			item.OTLPMetricsSource = "auto"
		}
		if item.BackupKeep == 0 && yamlMappingValue(itemNode, "backupKeep") == nil {
			item.BackupKeep = 10
		}
		cfg.Contexts[name] = item
	}
}

// updateLegacyContextConfig applies the caller's complete mutation and schema
// upgrade in one locked atomic replacement. A rejected callback leaves the
// legacy file byte-for-byte unchanged.
func updateLegacyContextConfig(fn func(cfg *Config) error) (bool, error) {
	path, err := configPath()
	if err != nil {
		return true, err
	}
	if exists, err := inspectContextConfigPath(path); err != nil {
		return true, err
	} else if !exists {
		return false, nil
	}
	dir := filepath.Dir(path)
	lock := lockfile.New(filepath.Join(dir, "config"))
	if err := lock.Acquire(); err != nil {
		return true, err
	}
	defer func() { _ = lock.Release() }()
	if exists, err := inspectContextConfigPath(path); err != nil {
		return true, err
	} else if !exists {
		return false, nil
	}

	_, loadErr := store.Load()
	if loadErr == nil {
		return false, nil
	}
	if apperrors.AsAppError(loadErr).Code != apperrors.CodeUnsupportedProtocol {
		return true, loadErr
	}
	data, err := os.ReadFile(path) //nolint:gosec // The configured file was permission-checked by store.Load under the lock.
	if err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "failed to read context file", err)
	}
	cfg, err := decodeLegacyContextConfig(data, loadErr)
	if err != nil {
		return true, err
	}
	if err := fn(cfg); err != nil {
		return true, err
	}
	cfg.APIVersion = SupportedContextAPIVersion
	if cfg.Contexts == nil {
		cfg.Contexts = make(map[string]Context)
	}
	updated, err := yaml.Marshal(cfg)
	if err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "failed to migrate context apiVersion", err)
	}
	if err := replaceContextConfigAtomically(path, updated); err != nil {
		return true, err
	}
	// Validate the replacement and apply the core platform-specific permission
	// hardening (including owner-only ACLs on Windows) before releasing the lock.
	_, err = store.Load()
	return true, err
}

func inspectContextConfigPath(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect context file", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, apperrors.New(
			apperrors.CodeLocalIOError,
			fmt.Sprintf("context path %q must be a regular file", path),
			nil,
		)
	}
	return true, nil
}

func replaceContextConfigAtomically(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-migrate-*.tmp")
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create migrated context temp file", err)
	}
	tmpPath := tmp.Name()
	defer func() { _ = os.Remove(tmpPath) }()
	if err := tmp.Chmod(0o600); err != nil {
		_ = tmp.Close()
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure migrated context temp file", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write migrated context temp file", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return apperrors.New(apperrors.CodeLocalIOError, "failed to sync migrated context temp file", err)
	}
	if err := tmp.Close(); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to close migrated context temp file", err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to replace migrated context file", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure migrated context file", err)
	}
	return nil
}

func yamlMappingValue(node *yaml.Node, key string) *yaml.Node {
	if node == nil || node.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(node.Content); i += 2 {
		if node.Content[i].Value == key {
			return node.Content[i+1]
		}
	}
	return nil
}

func configPath() (string, error) {
	if configPathOverride != "" {
		return configPathOverride, nil
	}
	dir, err := corectx.ConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "config.yaml"), nil
}
