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

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

// Result is the unredacted result of one remote command.
type Result struct {
	Stdout          string
	Stderr          string
	ExitCode        int
	StdoutTruncated bool
	StderrTruncated bool
}

// Client configures SSH transport dependencies.
type Client struct {
	KnownHostsPath          string
	OnTOFU                  func(Pin)
	AgentDial               func(context.Context) (net.Conn, error)
	Timeout                 time.Duration
	MaxOutputBytesPerStream int
}

type authenticationState struct {
	agentContexts []<-chan struct{}
}

func (s authenticationState) agentContextEnded() bool {
	for _, ended := range s.agentContexts {
		if channelClosed(ended) {
			return true
		}
	}
	return false
}

const defaultMaxOutputBytesPerStream = (16 << 20) + 1

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

//nolint:gocyclo // SSH setup, cancellation, bounded streams, and exit-status mapping share one lifecycle.
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
	authMethods, cleanup, authState, err := c.authMethods(ctx, contextName, target)
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
		if authState.agentContextEnded() {
			return Result{}, apperrors.New(
				apperrors.CodeNetworkError,
				"SSH agent communication timed out or was canceled during authentication",
				err,
			)
		}
		var networkErr net.Error
		if errors.Is(err, context.Canceled) ||
			errors.Is(err, context.DeadlineExceeded) ||
			(errors.As(err, &networkErr) && networkErr.Timeout()) {
			return Result{}, apperrors.New(apperrors.CodeNetworkError, "SSH connection timed out or was canceled", err)
		}
		return Result{}, apperrors.New(apperrors.CodeAuthFailed, "SSH connection or authentication failed", err)
	}
	defer func() { _ = client.Close() }()

	session, err := openSession(ctx, client, c.timeout())
	if err != nil {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return Result{}, apperrors.New(apperrors.CodeNetworkError, "SSH session setup timed out or was canceled", err)
		}
		return Result{}, apperrors.New(apperrors.CodeBackendError, "failed to create SSH session", err)
	}
	defer func() { _ = session.Close() }()

	stdout := newBoundedBuffer(c.maxOutputBytesPerStream())
	stderr := newBoundedBuffer(c.maxOutputBytesPerStream())
	if captureStdout {
		session.Stdout = stdout
	} else {
		session.Stdout = io.Discard
	}
	session.Stderr = stderr
	session.Stdin = stdin
	contextCloseDone := make(chan struct{})
	stopContextClose := context.AfterFunc(ctx, func() {
		defer close(contextCloseDone)
		_ = session.Signal(ssh.SIGTERM)
		_ = session.Close()
		_ = client.Close()
	})
	runErr := session.Run(command)
	if stopContextClose() {
		close(contextCloseDone)
	}
	<-contextCloseDone
	if ctx.Err() != nil {
		return Result{}, apperrors.New(apperrors.CodeNetworkError, "SSH command canceled", ctx.Err())
	}
	result := Result{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: captureStdout && stdout.Truncated(),
		StderrTruncated: stderr.Truncated(),
	}
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

func (c Client) authMethods(
	ctx context.Context,
	contextName string,
	target srvgovctx.Context,
) ([]ssh.AuthMethod, func(), authenticationState, error) {
	var methods []ssh.AuthMethod
	var cleanups []func()
	state := authenticationState{}
	cleanup := func() {
		for _, close := range cleanups {
			close()
		}
	}
	for _, method := range target.AuthMethods {
		switch method {
		case srvgovctx.AuthPrivateKey:
			auth, err := privateKeyAuth(ctx, contextName, target)
			if err != nil {
				cleanup()
				return nil, func() {}, state, err
			}
			if auth != nil {
				methods = append(methods, auth)
			}
		case srvgovctx.AuthAgent:
			auth, closeAgent, agentContextEnded, err := c.agentAuth(ctx)
			if err != nil {
				cleanup()
				return nil, func() {}, state, err
			}
			if auth != nil {
				methods = append(methods, auth)
				cleanups = append(cleanups, closeAgent)
				state.agentContexts = append(state.agentContexts, agentContextEnded)
			}
		case srvgovctx.AuthPassword:
			auth, err := passwordAuth(ctx, contextName, target)
			if err != nil {
				cleanup()
				return nil, func() {}, state, err
			}
			if auth != nil {
				methods = append(methods, auth)
			}
		}
	}
	return methods, cleanup, state, nil
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

func (c Client) agentAuth(ctx context.Context) (ssh.AuthMethod, func(), <-chan struct{}, error) {
	dial := c.AgentDial
	if dial == nil {
		dial = defaultAgentDial
	}
	agentCtx, cancel := context.WithTimeout(ctx, c.timeout())
	connection, err := dial(agentCtx)
	if err != nil {
		timeoutErr := sshAgentTimeoutError(agentCtx, err, false)
		cancel()
		if timeoutErr != nil {
			return nil, func() {}, nil, timeoutErr
		}
		return nil, func() {}, nil, nil
	}
	agentContextEnded := make(chan struct{})
	stopClose := context.AfterFunc(agentCtx, func() {
		close(agentContextEnded)
		_ = connection.Close()
	})
	cleanup := func() {
		stopClose()
		cancel()
		_ = connection.Close()
	}
	agentClient := agent.NewClient(connection)
	signers, err := agentClient.Signers()
	if err != nil {
		timeoutErr := sshAgentTimeoutError(agentCtx, err, channelClosed(agentContextEnded))
		cleanup()
		if timeoutErr != nil {
			return nil, func() {}, nil, timeoutErr
		}
		return nil, func() {}, nil, nil
	}
	if err := agentCtx.Err(); err != nil {
		cleanup()
		return nil, func() {}, nil, sshAgentTimeoutError(agentCtx, err, true)
	}
	return ssh.PublicKeys(signers...), cleanup, agentContextEnded, nil
}

func sshAgentTimeoutError(ctx context.Context, cause error, agentContextEnded bool) error {
	var networkErr net.Error
	if !agentContextEnded &&
		ctx.Err() == nil &&
		(!errors.As(cause, &networkErr) || !networkErr.Timeout()) {
		return nil
	}
	return apperrors.New(
		apperrors.CodeNetworkError,
		"SSH agent communication timed out or was canceled",
		cause,
	)
}

func channelClosed(channel <-chan struct{}) bool {
	select {
	case <-channel:
		return true
	default:
		return false
	}
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

func (c Client) maxOutputBytesPerStream() int {
	if c.MaxOutputBytesPerStream > 0 {
		return c.MaxOutputBytesPerStream
	}
	return defaultMaxOutputBytesPerStream
}

func openSession(ctx context.Context, client *ssh.Client, timeout time.Duration) (*ssh.Session, error) {
	setupCtx, cancel := context.WithTimeout(ctx, timeout)
	stopContextClose := context.AfterFunc(setupCtx, func() {
		_ = client.Close()
	})
	session, err := client.NewSession()
	stopped := stopContextClose()
	cancel()
	if !stopped {
		_ = client.Close()
		if session != nil {
			_ = session.Close()
		}
		if setupCtx.Err() != nil {
			return nil, setupCtx.Err()
		}
	}
	if err != nil {
		return nil, err
	}
	return session, nil
}

func dial(ctx context.Context, address string, config *ssh.ClientConfig, timeout time.Duration) (*ssh.Client, error) {
	dialer := net.Dialer{Timeout: timeout}
	connection, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(timeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := connection.SetDeadline(deadline); err != nil {
		_ = connection.Close()
		return nil, err
	}
	stopContextClose := context.AfterFunc(ctx, func() {
		_ = connection.Close()
	})
	clientConnection, channels, requests, err := ssh.NewClientConn(connection, address, config)
	if !stopContextClose() {
		_ = connection.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	if err != nil {
		_ = connection.Close()
		return nil, err
	}
	if err := connection.SetDeadline(time.Time{}); err != nil {
		_ = clientConnection.Close()
		return nil, err
	}
	return ssh.NewClient(clientConnection, channels, requests), nil
}

type boundedBuffer struct {
	buffer    bytes.Buffer
	maxBytes  int
	truncated bool
}

func newBoundedBuffer(maxBytes int) *boundedBuffer {
	return &boundedBuffer{maxBytes: maxBytes}
}

func (b *boundedBuffer) Write(data []byte) (int, error) {
	written := len(data)
	remaining := b.maxBytes - b.buffer.Len()
	if remaining <= 0 {
		b.truncated = b.truncated || written > 0
		return written, nil
	}
	if len(data) > remaining {
		data = data[:remaining]
		b.truncated = true
	}
	_, _ = b.buffer.Write(data)
	return written, nil
}

func (b *boundedBuffer) String() string {
	return b.buffer.String()
}

func (b *boundedBuffer) Truncated() bool {
	return b.truncated
}
