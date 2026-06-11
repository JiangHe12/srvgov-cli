// Package sshexec provides strict-TOFU, non-PTY SSH command transport.
package sshexec

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/JiangHe12/opskit-core/apperrors"
	corectx "github.com/JiangHe12/opskit-core/ctx"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

// Result is the unredacted result of one remote command.
type Result struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// Client configures SSH transport dependencies.
type Client struct {
	KnownHostsPath string
	OnTOFU         func(Pin)
	AgentDial      func(context.Context) (net.Conn, error)
	Timeout        time.Duration
}

// Run connects to target, executes command without a PTY, and captures output.
func (c Client) Run(ctx context.Context, contextName string, target srvgovctx.Context, command string) (Result, error) {
	return c.run(ctx, contextName, target, command, nil, true)
}

// RunWithStdin executes command with streamed stdin and intentionally discards
// stdout so tee-style write content cannot be echoed into memory or logs.
func (c Client) RunWithStdin(
	ctx context.Context,
	contextName string,
	target srvgovctx.Context,
	command string,
	stdin io.Reader,
) (Result, error) {
	return c.run(ctx, contextName, target, command, stdin, false)
}

func (c Client) run(
	ctx context.Context,
	contextName string,
	target srvgovctx.Context,
	command string,
	stdin io.Reader,
	captureStdout bool,
) (Result, error) {
	if err := target.Normalize(); err != nil {
		return Result{}, err
	}
	if target.Username == "" {
		return Result{}, apperrors.New(apperrors.CodeUsageError, "SSH username is required", nil)
	}
	authMethods, cleanup, err := c.authMethods(ctx, contextName, target)
	if err != nil {
		return Result{}, err
	}
	defer cleanup()
	if len(authMethods) == 0 {
		return Result{}, apperrors.New(apperrors.CodeCredentialStoreMissing, "no usable SSH authentication method", nil)
	}

	knownHostsPath, err := c.knownHostsPath()
	if err != nil {
		return Result{}, err
	}
	address := target.Address()
	config := &ssh.ClientConfig{
		User: target.Username,
		Auth: authMethods,
		HostKeyCallback: func(_ string, _ net.Addr, key ssh.PublicKey) error {
			return verifyOrPin(knownHostsPath, address, key, c.OnTOFU)
		},
		Timeout: c.timeout(),
	}
	client, err := dial(ctx, address, config, c.timeout())
	if err != nil {
		var changed *HostKeyChangedError
		if errors.As(err, &changed) {
			return Result{}, changed
		}
		var changedType *HostKeyTypeChangedError
		if errors.As(err, &changedType) {
			return Result{}, changedType
		}
		return Result{}, apperrors.New(apperrors.CodeAuthFailed, "SSH connection or authentication failed", err)
	}
	defer func() { _ = client.Close() }()

	session, err := client.NewSession()
	if err != nil {
		return Result{}, apperrors.New(apperrors.CodeBackendError, "failed to create SSH session", err)
	}
	defer func() { _ = session.Close() }()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	if captureStdout {
		session.Stdout = &stdout
	} else {
		session.Stdout = io.Discard
	}
	session.Stderr = &stderr
	session.Stdin = stdin
	runDone := make(chan error, 1)
	go func() {
		runDone <- session.Run(command)
	}()

	select {
	case <-ctx.Done():
		_ = client.Close()
		<-runDone
		return Result{}, apperrors.New(apperrors.CodeNetworkError, "SSH command canceled", ctx.Err())
	case runErr := <-runDone:
		result := Result{Stdout: stdout.String(), Stderr: stderr.String()}
		if runErr == nil {
			return result, nil
		}
		var exitErr *ssh.ExitError
		if errors.As(runErr, &exitErr) {
			result.ExitCode = exitErr.ExitStatus()
			return result, nil
		}
		return Result{}, apperrors.New(apperrors.CodeBackendError, "SSH command execution failed", runErr)
	}
}

func (c Client) authMethods(ctx context.Context, contextName string, target srvgovctx.Context) ([]ssh.AuthMethod, func(), error) {
	var methods []ssh.AuthMethod
	var closers []net.Conn
	cleanup := func() {
		for _, closer := range closers {
			_ = closer.Close()
		}
	}
	for _, method := range target.AuthMethods {
		switch method {
		case srvgovctx.AuthPrivateKey:
			auth, err := privateKeyAuth(ctx, contextName, target)
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			if auth != nil {
				methods = append(methods, auth)
			}
		case srvgovctx.AuthAgent:
			auth, connection := c.agentAuth(ctx)
			if auth != nil {
				methods = append(methods, auth)
				closers = append(closers, connection)
			}
		case srvgovctx.AuthPassword:
			auth, err := passwordAuth(ctx, contextName, target)
			if err != nil {
				cleanup()
				return nil, func() {}, err
			}
			if auth != nil {
				methods = append(methods, auth)
			}
		}
	}
	return methods, cleanup, nil
}

func privateKeyAuth(ctx context.Context, contextName string, target srvgovctx.Context) (ssh.AuthMethod, error) {
	if target.IdentityFile == "" {
		return nil, nil
	}
	data, err := os.ReadFile(target.IdentityFile) //nolint:gosec // Context-controlled private key path.
	if err != nil {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to read SSH identity file", err)
	}
	signer, err := ssh.ParsePrivateKey(data)
	if err == nil {
		return ssh.PublicKeys(signer), nil
	}
	var missing *ssh.PassphraseMissingError
	if !errors.As(err, &missing) {
		return nil, apperrors.New(apperrors.CodeCredentialStoreError, "failed to parse SSH identity file", err)
	}
	passphrase, resolveErr := target.ResolveIdentityPassphraseContext(ctx, contextName)
	if resolveErr != nil {
		return nil, resolveErr
	}
	if passphrase == "" {
		return nil, apperrors.New(apperrors.CodeCredentialStoreMissing, "SSH identity passphrase is required", nil)
	}
	signer, err = ssh.ParsePrivateKeyWithPassphrase(data, []byte(passphrase))
	if err != nil {
		return nil, apperrors.New(apperrors.CodeAuthFailed, "failed to unlock SSH identity file", err)
	}
	return ssh.PublicKeys(signer), nil
}

func passwordAuth(ctx context.Context, contextName string, target srvgovctx.Context) (ssh.AuthMethod, error) {
	if target.Password == "" {
		return nil, nil
	}
	password, err := target.ResolvePasswordContext(ctx, contextName)
	if err != nil {
		return nil, err
	}
	if password == "" {
		return nil, nil
	}
	return ssh.Password(password), nil
}

func (c Client) agentAuth(ctx context.Context) (ssh.AuthMethod, net.Conn) {
	dial := c.AgentDial
	if dial == nil {
		dial = defaultAgentDial
	}
	connection, err := dial(ctx)
	if err != nil {
		return nil, nil
	}
	agentClient := agent.NewClient(connection)
	if _, err := agentClient.List(); err != nil {
		_ = connection.Close()
		return nil, nil
	}
	return ssh.PublicKeysCallback(agentClient.Signers), connection
}

func defaultAgentDial(ctx context.Context) (net.Conn, error) {
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, apperrors.New(apperrors.CodeCredentialStoreMissing, "SSH agent is unavailable", nil)
	}
	var dialer net.Dialer
	return dialer.DialContext(ctx, "unix", socket)
}

func (c Client) knownHostsPath() (string, error) {
	if c.KnownHostsPath != "" {
		return c.KnownHostsPath, nil
	}
	return KnownHostsPath()
}

// KnownHostsPath returns the default srvgov host-key pin path.
func KnownHostsPath() (string, error) {
	dir, err := corectx.ConfigDir()
	if err != nil {
		return "", apperrors.New(apperrors.CodeLocalIOError, "failed to resolve SSH trust directory", err)
	}
	return filepath.Join(dir, "known_hosts"), nil
}

func (c Client) timeout() time.Duration {
	if c.Timeout > 0 {
		return c.Timeout
	}
	return 15 * time.Second
}

func dial(ctx context.Context, address string, config *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	return ssh.NewClient(clientConnection, channels, requests), nil
}
