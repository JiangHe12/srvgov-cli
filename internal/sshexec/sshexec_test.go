package sshexec

import (
	"context"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/credstore"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestRunPinsUnknownHostReusesPinAndRejectsChangedKey(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	var pins []Pin
	client := Client{
		KnownHostsPath: knownHostsPath,
		OnTOFU: func(pin Pin) {
			pins = append(pins, pin)
		},
	}

	first, err := client.Run(context.Background(), "dev", target, "ignored")
	if err != nil {
		t.Fatalf("first Run() error = %v", err)
	}
	if first.Stdout != "stdout-data" || first.Stderr != "stderr-data" || first.ExitCode != 7 {
		t.Fatalf("first result = %#v", first)
	}
	if len(pins) != 1 {
		t.Fatalf("TOFU notifications = %d, want 1", len(pins))
	}

	if _, err := client.Run(context.Background(), "dev", target, "ignored"); err != nil {
		t.Fatalf("second Run() error = %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("TOFU notifications after second run = %d, want 1", len(pins))
	}

	server.setHostKey(newTestSigner(t))
	_, err = client.Run(context.Background(), "dev", target, "ignored")
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("changed-key error = %T %v", err, err)
	}
}

func TestVerifyOrPinTruthTableByAddress(t *testing.T) {
	path := filepath.Join(t.TempDir(), "known_hosts")
	address := "server.example:22"
	ed25519Key := newTestSigner(t).PublicKey()

	var pins []Pin
	if err := verifyOrPin(path, address, ed25519Key, func(pin Pin) {
		pins = append(pins, pin)
	}); err != nil {
		t.Fatalf("unknown address verifyOrPin() error = %v", err)
	}
	if len(pins) != 1 {
		t.Fatalf("TOFU notifications = %d, want 1", len(pins))
	}

	if err := verifyOrPin(path, address, ed25519Key, nil); err != nil {
		t.Fatalf("same key verifyOrPin() error = %v", err)
	}

	differentEd25519 := newTestSigner(t).PublicKey()
	err := verifyOrPin(path, address, differentEd25519, nil)
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) {
		t.Fatalf("different same-type error = %T %v", err, err)
	}

	rsaKey := newTestRSASigner(t).PublicKey()
	err = verifyOrPin(path, address, rsaKey, nil)
	var changedType *HostKeyTypeChangedError
	if !errors.As(err, &changedType) {
		t.Fatalf("new key-type error = %T %v", err, err)
	}
	if changedType.ActualKeyType != rsaKey.Type() {
		t.Fatalf("ActualKeyType = %q, want %q", changedType.ActualKeyType, rsaKey.Type())
	}

	stored := readKnownHostPins(t, path)
	if len(stored) != 1 || stored[0].KeyType != ed25519Key.Type() {
		t.Fatalf("stored pins = %#v, want only original ed25519 pin", stored)
	}
	wantLine := address + "\t" + ed25519Key.Type() + "\t" + ssh.FingerprintSHA256(ed25519Key) + "\t" + base64.StdEncoding.EncodeToString(ed25519Key.Marshal()) + "\n"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	if string(data) != wantLine {
		t.Fatalf("known_hosts = %q, want %q", data, wantLine)
	}
}

func TestRunRejectsNewHostKeyTypeForPinnedAddress(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})
	path := filepath.Join(t.TempDir(), "known_hosts")
	client := Client{KnownHostsPath: path}

	if _, err := client.Run(context.Background(), "dev", target, "ignored"); err != nil {
		t.Fatalf("initial Run() error = %v", err)
	}
	server.setHostKey(newTestRSASigner(t))

	_, err := client.Run(context.Background(), "dev", target, "ignored")
	var changedType *HostKeyTypeChangedError
	if !errors.As(err, &changedType) {
		t.Fatalf("RSA replacement error = %T %v", err, err)
	}
	if changedType.Address != target.Address() {
		t.Fatalf("Address = %q, want %q", changedType.Address, target.Address())
	}

	stored := readKnownHostPins(t, path)
	if len(stored) != 1 || stored[0].KeyType != ssh.KeyAlgoED25519 {
		t.Fatalf("stored pins after rejected rotation = %#v", stored)
	}
}

func TestKnownHostsFileModeIsOwnerOnly(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})
	path := filepath.Join(t.TempDir(), "known_hosts")

	if _, err := (Client{KnownHostsPath: path}).Run(context.Background(), "dev", target, "ignored"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	exists, err := CheckKnownHostsPermissions(path)
	if err != nil {
		t.Fatalf("CheckKnownHostsPermissions() error = %v", err)
	}
	if !exists {
		t.Fatal("CheckKnownHostsPermissions() exists = false")
	}
}

func TestVerifyOrPinRejectsSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows symlink creation requires privileges not guaranteed in local test runs")
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target_known_hosts")
	path := filepath.Join(dir, "known_hosts")
	const original = "referent-must-not-change"
	if err := os.WriteFile(target, []byte(original), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err := verifyOrPin(path, "server.example:22", newTestSigner(t).PublicKey(), nil)
	if err == nil {
		t.Fatal("verifyOrPin() error = nil, want symlink rejection")
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("verifyOrPin() code = %s, want %s; error = %v", got, apperrors.CodeLocalIOError, err)
	}
	if !strings.Contains(err.Error(), "failed to open secure file") {
		t.Fatalf("verifyOrPin() error = %v, want no-follow open rejection", err)
	}
	info, statErr := os.Lstat(path)
	if statErr != nil {
		t.Fatalf("Lstat() error = %v", statErr)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("pin path mode = %v, want symlink unchanged", info.Mode())
	}
	data, readErr := os.ReadFile(target)
	if readErr != nil {
		t.Fatalf("ReadFile(target) error = %v", readErr)
	}
	if string(data) != original {
		t.Fatalf("target = %q, want %q", data, original)
	}
}

func TestRunDoesNotRequestPTY(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})

	if _, err := (Client{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}).
		Run(context.Background(), "dev", target, "ignored"); err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if server.ptyRequested.Load() {
		t.Fatal("server received pty-req")
	}
}

func TestRunWithStdinStreamsInputWithoutCapturingStdout(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})

	result, err := (Client{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}).
		RunWithStdin(context.Background(), "dev", target, "tee -- '/tmp/file'", strings.NewReader("password=write-secret\n"))
	if err != nil {
		t.Fatalf("RunWithStdin() error = %v", err)
	}
	if server.stdin() != "password=write-secret\n" {
		t.Fatalf("server stdin = %q", server.stdin())
	}
	if result.Stdout != "" || result.Stderr != "stderr-data" || result.ExitCode != 7 {
		t.Fatalf("result = %#v", result)
	}
	if server.ptyRequested.Load() {
		t.Fatal("server received pty-req")
	}
}

func TestRunStillCapturesOutputWithoutStdin(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})

	result, err := (Client{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}).
		Run(context.Background(), "dev", target, "ignored")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if server.stdin() != "" || result.Stdout != "stdout-data" || result.Stderr != "stderr-data" || result.ExitCode != 7 {
		t.Fatalf("stdin = %q; result = %#v", server.stdin(), result)
	}
}

func TestRunBoundsCapturedOutputPerStream(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	server.setOutput("0123456789abcdef", "abcdefghijklmnop")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})

	result, err := (Client{
		KnownHostsPath:          filepath.Join(t.TempDir(), "known_hosts"),
		MaxOutputBytesPerStream: 8,
	}).Run(context.Background(), "dev", target, "ignored")
	if err != nil {
		t.Fatalf("Run() error = %v", err)
	}
	if result.Stdout != "01234567" || result.Stderr != "abcdefgh" {
		t.Fatalf("bounded result = %#v", result)
	}
	if !result.StdoutTruncated || !result.StderrTruncated {
		t.Fatalf("truncation flags = stdout:%t stderr:%t, want both true", result.StdoutTruncated, result.StderrTruncated)
	}
}

func TestRunWithStdinBoundsStderrAndDoesNotFlagDiscardedStdout(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	server.setOutput(strings.Repeat("x", 32), strings.Repeat("y", 32))
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})

	result, err := (Client{
		KnownHostsPath:          filepath.Join(t.TempDir(), "known_hosts"),
		MaxOutputBytesPerStream: 5,
	}).RunWithStdin(context.Background(), "dev", target, "tee -- '/tmp/file'", strings.NewReader("payload"))
	if err != nil {
		t.Fatalf("RunWithStdin() error = %v", err)
	}
	if result.Stdout != "" || result.StdoutTruncated {
		t.Fatalf("discarded stdout result = %#v", result)
	}
	if result.Stderr != "yyyyy" || !result.StderrTruncated {
		t.Fatalf("bounded stderr result = %#v", result)
	}
}

func TestDialAppliesDeadlineToSSHHandshake(t *testing.T) {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	release := make(chan struct{})
	defer close(release)
	accepted := make(chan struct{})
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		close(accepted)
		<-release
	}()

	config := &ssh.ClientConfig{
		User: "alice",
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			return nil
		},
	}
	started := time.Now()
	_, err = dial(context.Background(), listener.Addr().String(), config, 75*time.Millisecond)
	elapsed := time.Since(started)
	if err == nil {
		t.Fatal("dial() error = nil, want handshake timeout")
	}
	select {
	case <-accepted:
	default:
		t.Fatal("server did not accept the TCP connection")
	}
	var networkErr net.Error
	if !errors.As(err, &networkErr) || !networkErr.Timeout() {
		t.Fatalf("dial() error = %T %v, want timeout", err, err)
	}
	if elapsed > time.Second {
		t.Fatalf("dial() elapsed = %s, want bounded handshake", elapsed)
	}
}

func TestDialCancelsBlockedSSHHandshake(t *testing.T) {
	var listenConfig net.ListenConfig
	listener, err := listenConfig.Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("Listen() error = %v", err)
	}
	defer func() { _ = listener.Close() }()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	release := make(chan struct{})
	defer close(release)
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			return
		}
		defer func() { _ = connection.Close() }()
		cancel()
		<-release
	}()

	config := &ssh.ClientConfig{
		User: "alice",
		HostKeyCallback: func(string, net.Addr, ssh.PublicKey) error {
			return nil
		},
	}
	started := time.Now()
	_, err = dial(ctx, listener.Addr().String(), config, 5*time.Second)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("dial() error = %T %v, want context.Canceled", err, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("dial() elapsed = %s, want prompt cancellation", elapsed)
	}
}

func TestRunTimesOutBlockedSessionOpen(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	server.setBlockSessionOpen(true)
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})
	client := Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        75 * time.Millisecond,
	}

	started := time.Now()
	_, err := client.Run(context.Background(), "dev", target, "ignored")
	if err == nil {
		t.Fatal("Run() error = nil, want session-open timeout")
	}
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNetworkError {
		t.Fatalf("Run() code = %s, want %s; error=%v", got, apperrors.CodeNetworkError, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Run() elapsed = %s, want bounded session setup", elapsed)
	}
}

func TestRunCancelRaceWithSessionOpenNeverReturnsBrokenSuccess(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("login-secret")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "login-secret"},
	})
	client := Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        time.Second,
	}

	for attempt := 0; attempt < 20; attempt++ {
		gate := make(chan struct{})
		requested := make(chan struct{}, 1)
		server.setSessionOpenGate(gate, requested)
		ctx, cancel := context.WithCancel(context.Background())
		resultDone := make(chan struct {
			result Result
			err    error
		}, 1)
		go func() {
			result, err := client.Run(ctx, "dev", target, "ignored")
			resultDone <- struct {
				result Result
				err    error
			}{result: result, err: err}
		}()

		select {
		case <-requested:
		case <-time.After(time.Second):
			cancel()
			close(gate)
			t.Fatal("server did not observe session-open request")
		}
		start := make(chan struct{})
		go func() {
			<-start
			cancel()
		}()
		go func() {
			<-start
			close(gate)
		}()
		close(start)

		outcome := <-resultDone
		server.setSessionOpenGate(nil, nil)
		if outcome.err == nil {
			if outcome.result.Stdout != "stdout-data" || outcome.result.ExitCode != 7 {
				t.Fatalf("attempt %d returned broken success: %#v", attempt, outcome.result)
			}
			continue
		}
		if got := apperrors.AsAppError(outcome.err).Code; got != apperrors.CodeNetworkError {
			t.Fatalf("attempt %d code = %s, want %s; error=%v", attempt, got, apperrors.CodeNetworkError, outcome.err)
		}
	}
}

func TestRunTimesOutUnresponsiveAgent(t *testing.T) {
	server := newTestSSHServer(t)
	target := contextForServer(t, server, srvgovctx.Context{
		Base:        corectx.Base{Username: "alice"},
		AuthMethods: []string{srvgovctx.AuthAgent},
	})
	clientConn, agentConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = agentConn.Close()
	})
	client := Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		AgentDial: func(context.Context) (net.Conn, error) {
			return clientConn, nil
		},
		Timeout: 75 * time.Millisecond,
	}

	started := time.Now()
	_, err := client.Run(context.Background(), "dev", target, "ignored")
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNetworkError {
		t.Fatalf("Run() code = %s, want %s; error=%v", got, apperrors.CodeNetworkError, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Run() elapsed = %s, want bounded agent communication", elapsed)
	}
}

func TestRunCancelsUnresponsiveAgent(t *testing.T) {
	server := newTestSSHServer(t)
	target := contextForServer(t, server, srvgovctx.Context{
		Base:        corectx.Base{Username: "alice"},
		AuthMethods: []string{srvgovctx.AuthAgent},
	})
	clientConn, agentConn := net.Pipe()
	t.Cleanup(func() {
		_ = clientConn.Close()
		_ = agentConn.Close()
	})
	client := Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		AgentDial: func(context.Context) (net.Conn, error) {
			return clientConn, nil
		},
		Timeout: 5 * time.Second,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	started := time.Now()
	_, err := client.Run(ctx, "dev", target, "ignored")
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNetworkError {
		t.Fatalf("Run() code = %s, want %s; error=%v", got, apperrors.CodeNetworkError, err)
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("Run() elapsed = %s, want prompt agent cancellation", elapsed)
	}
}

func TestRunMapsBlockedAgentSignTimeoutToNetworkError(t *testing.T) {
	server := newTestSSHServer(t)
	privateKey, signer := newTestKey(t)
	server.setPublicKey(signer.PublicKey())
	target := contextForServer(t, server, srvgovctx.Context{
		Base:        corectx.Base{Username: "alice"},
		AuthMethods: []string{srvgovctx.AuthAgent},
	})
	keyring := agent.NewKeyring()
	if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
		t.Fatalf("agent Add() error = %v", err)
	}
	blockedAgent := &blockingSignAgent{
		Agent:   keyring,
		started: make(chan struct{}),
		release: make(chan struct{}),
	}
	clientConn, serverConn := net.Pipe()
	t.Cleanup(func() {
		close(blockedAgent.release)
		_ = clientConn.Close()
		_ = serverConn.Close()
	})
	go func() {
		_ = agent.ServeAgent(blockedAgent, serverConn)
	}()
	client := Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		AgentDial: func(context.Context) (net.Conn, error) {
			return clientConn, nil
		},
		Timeout: time.Second,
	}

	started := time.Now()
	_, err := client.Run(context.Background(), "dev", target, "ignored")
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNetworkError {
		t.Fatalf("Run() code = %s, want %s; error=%v", got, apperrors.CodeNetworkError, err)
	}
	select {
	case <-blockedAgent.started:
	default:
		t.Fatal("SSH handshake never requested an agent signature")
	}
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("Run() elapsed = %s, want bounded agent signing", elapsed)
	}
}

func TestDefaultOutputLimitCoversMaximumFileReadProbe(t *testing.T) {
	const maximumFileReadProbe = (16 << 20) + 1
	if got := (Client{}).maxOutputBytesPerStream(); got < maximumFileReadProbe {
		t.Fatalf("default output limit = %d, want at least %d", got, maximumFileReadProbe)
	}
}

func TestAuthenticationChainPrivateKeyThenAgentThenPassword(t *testing.T) {
	t.Run("private key", func(t *testing.T) {
		server := newTestSSHServer(t)
		privateKey, signer := newTestKey(t)
		server.setPublicKey(signer.PublicKey())
		keyPath := writePrivateKey(t, privateKey, nil)
		target := contextForServer(t, server, srvgovctx.Context{
			Base:         corectx.Base{Username: "alice", Password: "unused-password"},
			IdentityFile: keyPath,
		})

		if _, err := (Client{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}).
			Run(context.Background(), "dev", target, "ignored"); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if server.authentication() != "publickey" {
			t.Fatalf("authentication = %q", server.authentication())
		}
	})

	t.Run("encrypted private key", func(t *testing.T) {
		server := newTestSSHServer(t)
		privateKey, signer := newTestKey(t)
		server.setPublicKey(signer.PublicKey())
		keyPath := writePrivateKey(t, privateKey, []byte("key-secret"))
		target := contextForServer(t, server, srvgovctx.Context{
			Base:               corectx.Base{Username: "alice"},
			IdentityFile:       keyPath,
			IdentityPassphrase: credstore.EncodeRef(registerTestCredentialBackend(map[string]string{"dev#identity": "key-secret"})),
		})

		if _, err := (Client{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}).
			Run(context.Background(), "dev", target, "ignored"); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if server.authentication() != "publickey" {
			t.Fatalf("authentication = %q", server.authentication())
		}
	})

	t.Run("agent", func(t *testing.T) {
		server := newTestSSHServer(t)
		privateKey, signer := newTestKey(t)
		server.setPublicKey(signer.PublicKey())
		target := contextForServer(t, server, srvgovctx.Context{
			Base: corectx.Base{Username: "alice", Password: "unused-password"},
		})

		keyring := agent.NewKeyring()
		if err := keyring.Add(agent.AddedKey{PrivateKey: privateKey}); err != nil {
			t.Fatalf("agent Add() error = %v", err)
		}
		client := Client{
			KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
			AgentDial:      pipeAgentDialer(t, keyring),
		}
		if _, err := client.Run(context.Background(), "dev", target, "ignored"); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if server.authentication() != "publickey" {
			t.Fatalf("authentication = %q", server.authentication())
		}
	})

	t.Run("password", func(t *testing.T) {
		server := newTestSSHServer(t)
		server.setPassword("login-secret")
		target := contextForServer(t, server, srvgovctx.Context{
			Base: corectx.Base{
				Username: "alice",
				Password: credstore.EncodeRef(registerTestCredentialBackend(map[string]string{"dev": "login-secret"})),
			},
		})

		if _, err := (Client{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}).
			Run(context.Background(), "dev", target, "ignored"); err != nil {
			t.Fatalf("Run() error = %v", err)
		}
		if server.authentication() != "password" {
			t.Fatalf("authentication = %q", server.authentication())
		}
	})
}

func TestCredentialValuesDoNotLeakInErrors(t *testing.T) {
	server := newTestSSHServer(t)
	server.setPassword("correct-password")
	target := contextForServer(t, server, srvgovctx.Context{
		Base: corectx.Base{Username: "alice", Password: "wrong-super-secret"},
	})

	_, err := (Client{KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts")}).
		Run(context.Background(), "dev", target, "ignored")
	if err == nil {
		t.Fatal("Run() error = nil")
	}
	if strings.Contains(err.Error(), "wrong-super-secret") || strings.Contains(err.Error(), "correct-password") {
		t.Fatalf("error leaked credential: %v", err)
	}
}

func contextForServer(t *testing.T, server *testSSHServer, item srvgovctx.Context) srvgovctx.Context {
	t.Helper()
	host, port, err := net.SplitHostPort(server.address())
	if err != nil {
		t.Fatalf("SplitHostPort() error = %v", err)
	}
	item.Host = host
	item.Port, err = strconv.Atoi(port)
	if err != nil {
		t.Fatalf("parse port error = %v", err)
	}
	if err := item.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	return item
}

func writePrivateKey(t *testing.T, privateKey any, passphrase []byte) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, encodePrivateKey(t, privateKey, passphrase), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	return path
}

func pipeAgentDialer(t *testing.T, keyring agent.Agent) func(context.Context) (net.Conn, error) {
	t.Helper()
	return func(context.Context) (net.Conn, error) {
		client, server := net.Pipe()
		go func() {
			_ = agent.ServeAgent(keyring, server)
			_ = server.Close()
		}()
		return client, nil
	}
}

type blockingSignAgent struct {
	agent.Agent
	started chan struct{}
	release chan struct{}
}

func (a *blockingSignAgent) Sign(ssh.PublicKey, []byte) (*ssh.Signature, error) {
	close(a.started)
	<-a.release
	return nil, errors.New("blocking test agent released")
}

var errRejectedAuth = errors.New("authentication rejected")

func encodePrivateKey(t *testing.T, privateKey any, passphrase []byte) []byte {
	t.Helper()
	var (
		block *pem.Block
		err   error
	)
	if len(passphrase) == 0 {
		block, err = ssh.MarshalPrivateKey(privateKey, "test")
	} else {
		block, err = ssh.MarshalPrivateKeyWithPassphrase(privateKey, "test", passphrase)
	}
	if err != nil {
		t.Fatalf("MarshalPrivateKey() error = %v", err)
	}
	return pem.EncodeToMemory(block)
}

type testCredentialBackend struct {
	name   string
	values map[string]string
}

func (b *testCredentialBackend) Name() string { return b.name }

func (b *testCredentialBackend) Get(_ context.Context, contextName string) (string, error) {
	value, ok := b.values[contextName]
	if !ok {
		return "", credstore.ErrNotFound
	}
	return value, nil
}

func (b *testCredentialBackend) Put(context.Context, string, string) error {
	return errors.New("not implemented")
}

func (b *testCredentialBackend) Delete(context.Context, string) error {
	return errors.New("not implemented")
}

func (b *testCredentialBackend) Available() error { return nil }

func registerTestCredentialBackend(values map[string]string) string {
	const name = "sshexec-test"
	credstore.Register(name, func() credstore.Backend {
		return &testCredentialBackend{name: name, values: values}
	})
	return name
}

func readKnownHostPins(t *testing.T, path string) []Pin {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile(%s) error = %v", path, err)
	}
	text := strings.TrimSpace(string(data))
	if text == "" {
		return nil
	}
	var pins []Pin
	for _, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			t.Fatalf("known_hosts line %q has %d fields, want 4", line, len(fields))
		}
		pins = append(pins, Pin{
			Address:     fields[0],
			KeyType:     fields[1],
			Fingerprint: fields[2],
			PublicKey:   fields[3],
		})
	}
	return pins
}
