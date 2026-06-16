// Package srvgovctx defines and persists srvgov server contexts.
package srvgovctx

import (
	"context"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"

	"github.com/JiangHe12/opskit-core/apperrors"
	corectx "github.com/JiangHe12/opskit-core/ctx"
)

const (
	AuthPrivateKey = "private-key"
	AuthAgent      = "agent"
	AuthPassword   = "password"
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

var store = corectx.NewStore(func(c *Context) *corectx.Base { return &c.Base })

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
	c.AuthMethods = c.AuthMethods[:0]
	for _, method := range defaultAuthMethods {
		if enabledMethods[method] {
			c.AuthMethods = append(c.AuthMethods, method)
		}
	}
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
func SetConfigPath(path string) { corectx.SetConfigPath(path) }

// Load loads all contexts.
func Load() (*Config, error) { return store.Load() }

// SetContext adds or updates a normalized context.
func SetContext(name string, item Context) error {
	if err := item.Normalize(); err != nil {
		return err
	}
	return store.SetContext(name, item)
}

// UseContext switches the active context.
func UseContext(name string) error { return store.UseContext(name) }

// Current returns the active context.
func Current() (*Context, string, error) { return store.Current() }

// DeleteContext removes a context.
func DeleteContext(name string) error { return store.DeleteContext(name) }
