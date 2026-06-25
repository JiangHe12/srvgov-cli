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

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"

	"github.com/JiangHe12/opskit-core/credstore"
	corectx "github.com/JiangHe12/opskit-core/ctx"

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
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatalf("Symlink() error = %v", err)
	}

	err := verifyOrPin(path, "server.example:22", newTestSigner(t).PublicKey(), nil)
	if err == nil {
		t.Fatal("verifyOrPin() error = nil, want symlink rejection")
	}
	if !strings.Contains(err.Error(), "SSH host-key pin path must be a regular file") {
		t.Fatalf("verifyOrPin() error = %v", err)
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
