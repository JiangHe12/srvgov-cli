//go:build integration

package sshexec

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestIntegrationOpenSSHRealServerTOFUStdinAndShellQuoting(t *testing.T) {
	addr := os.Getenv("SRVGOV_IT_SSH_ADDR")
	if addr == "" {
		t.Skip("set SRVGOV_IT_SSH_ADDR to run")
	}
	user := os.Getenv("SRVGOV_IT_SSH_USER")
	if user == "" {
		t.Fatal("set SRVGOV_IT_SSH_USER to run")
	}
	keyPath := os.Getenv("SRVGOV_IT_SSH_KEY")
	if keyPath == "" {
		t.Fatal("set SRVGOV_IT_SSH_KEY to run")
	}

	target := integrationContext(t, addr, user, keyPath)
	knownHostsPath := filepath.Join(t.TempDir(), "known_hosts")
	client := Client{KnownHostsPath: knownHostsPath, Timeout: 10 * time.Second}
	ctx := context.Background()
	prefix := integrationName(t)
	remoteFile := "/tmp/" + prefix + "-stdin.txt"
	injectionMarker := "/tmp/" + prefix + "-injected"
	cleanupClient := Client{KnownHostsPath: filepath.Join(t.TempDir(), "cleanup_known_hosts"), Timeout: 10 * time.Second}
	t.Cleanup(func() {
		_, _ = cleanupClient.Run(context.Background(), "it", target, "rm -f -- "+observe.ShellQuote(remoteFile)+" "+observe.ShellQuote(injectionMarker))
	})

	result, err := client.Run(ctx, "it", target, "echo srvgov-it-ok")
	if err != nil {
		t.Fatalf("Run(echo) error = %v", err)
	}
	if !strings.Contains(result.Stdout, "srvgov-it-ok") || result.ExitCode != 0 {
		t.Fatalf("Run(echo) = %#v, want stdout marker and exit 0", result)
	}

	failed, err := client.Run(ctx, "it", target, "sh -c 'exit 7'")
	if err != nil {
		t.Fatalf("Run(exit 7) error = %v", err)
	}
	if failed.ExitCode != 7 {
		t.Fatalf("Run(exit 7) exit = %d, want 7; result=%#v", failed.ExitCode, failed)
	}

	stderr, err := client.Run(ctx, "it", target, "sh -c 'echo err 1>&2'")
	if err != nil {
		t.Fatalf("Run(stderr) error = %v", err)
	}
	if !strings.Contains(stderr.Stderr, "err") {
		t.Fatalf("Run(stderr) stderr = %q, want marker", stderr.Stderr)
	}

	pins := readKnownHostPins(t, knownHostsPath)
	if len(pins) == 0 {
		t.Fatalf("known_hosts has no TOFU pin")
	}
	originalPin := pinForAddress(t, pins, target.Address())
	if originalPin.PublicKey == "" || originalPin.Fingerprint == "" {
		t.Fatalf("TOFU pin incomplete: %#v", originalPin)
	}

	content := "alpha\nbeta=srvgov-it\n"
	written, err := client.RunWithStdin(ctx, "it", target, "tee -- "+observe.ShellQuote(remoteFile), strings.NewReader(content))
	if err != nil {
		t.Fatalf("RunWithStdin(tee) error = %v", err)
	}
	if written.Stdout != "" {
		t.Fatalf("RunWithStdin(tee) stdout = %q, want discarded", written.Stdout)
	}
	readBack, err := client.Run(ctx, "it", target, "cat -- "+observe.ShellQuote(remoteFile))
	if err != nil {
		t.Fatalf("Run(cat) error = %v", err)
	}
	if readBack.Stdout != content {
		t.Fatalf("Run(cat) stdout = %q, want %q", readBack.Stdout, content)
	}

	payload := "literal ; touch " + injectionMarker + " ; echo pwned"
	echoed, err := client.Run(ctx, "it", target, "printf '%s\n' "+observe.ShellQuote(payload))
	if err != nil {
		t.Fatalf("Run(quoted payload) error = %v", err)
	}
	if echoed.Stdout != payload+"\n" {
		t.Fatalf("Run(quoted payload) stdout = %q, want literal %q", echoed.Stdout, payload+"\n")
	}
	marker, err := client.Run(ctx, "it", target, "test -e "+observe.ShellQuote(injectionMarker))
	if err != nil {
		t.Fatalf("Run(test marker) error = %v", err)
	}
	if marker.ExitCode == 0 {
		t.Fatalf("quoted payload created injection marker %s", injectionMarker)
	}

	beforeTamper, err := os.ReadFile(knownHostsPath)
	if err != nil {
		t.Fatalf("ReadFile(known_hosts) error = %v", err)
	}
	tampered := tamperedPinLine(t, originalPin)
	if err := os.WriteFile(knownHostsPath, []byte(tampered), 0o600); err != nil {
		t.Fatalf("tamper known_hosts error = %v", err)
	}
	_, err = client.Run(ctx, "it", target, "echo should-not-run")
	if err == nil {
		t.Fatal("Run(after host-key tamper) error = nil, want host-key rejection")
	}
	var changed *HostKeyChangedError
	if !errors.As(err, &changed) && apperrors.AsAppError(err).Code != apperrors.CodeAuthFailed {
		t.Fatalf("Run(after host-key tamper) error = %T %v, want HostKeyChangedError or CodeAuthFailed", err, err)
	}
	afterTamper, readErr := os.ReadFile(knownHostsPath)
	if readErr != nil {
		t.Fatalf("ReadFile(tampered known_hosts) error = %v", readErr)
	}
	if string(afterTamper) != tampered {
		t.Fatalf("known_hosts was overwritten after rejected host key:\nbefore=%q\nfirst-pin=%q\nafter=%q", beforeTamper, tampered, afterTamper)
	}
}

func integrationContext(t *testing.T, addr, user, keyPath string) srvgovctx.Context {
	t.Helper()
	host, portText, err := net.SplitHostPort(addr)
	if err != nil {
		t.Fatalf("SRVGOV_IT_SSH_ADDR must be host:port: %v", err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatalf("SRVGOV_IT_SSH_ADDR port is invalid: %v", err)
	}
	target := srvgovctx.Context{
		Base:         corectx.Base{Username: user},
		Host:         host,
		Port:         port,
		IdentityFile: keyPath,
		AuthMethods:  []string{srvgovctx.AuthPrivateKey},
	}
	if err := target.Normalize(); err != nil {
		t.Fatalf("Normalize() error = %v", err)
	}
	return target
}

func pinForAddress(t *testing.T, pins []Pin, address string) Pin {
	t.Helper()
	for _, pin := range pins {
		if pin.Address == address {
			return pin
		}
	}
	t.Fatalf("TOFU pins = %#v, want address %q", pins, address)
	return Pin{}
}

func tamperedPinLine(t *testing.T, original Pin) string {
	t.Helper()
	_, signer := newTestKey(t)
	replacementKey := signer.PublicKey()
	replacement := Pin{
		Address:     original.Address,
		KeyType:     replacementKey.Type(),
		Fingerprint: ssh.FingerprintSHA256(replacementKey),
		PublicKey:   base64.StdEncoding.EncodeToString(replacementKey.Marshal()),
	}
	replacement.KeyType = original.KeyType
	return fmt.Sprintf("%s\t%s\t%s\t%s\n", replacement.Address, replacement.KeyType, replacement.Fingerprint, replacement.PublicKey)
}

func integrationName(t *testing.T) string {
	t.Helper()
	name := strings.NewReplacer("/", "-", "\\", "-", "_", "-", " ", "-").Replace(strings.ToLower(t.Name()))
	if len(name) > 24 {
		name = name[:24]
	}
	return "srvgov-it-" + strconv.FormatInt(time.Now().UnixNano(), 36) + "-" + strings.Trim(name, "-")
}
