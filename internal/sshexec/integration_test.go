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
	target := integrationTarget(t)
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

func TestIntegrationOpenSSHRealServerCancellationAndDeadline(t *testing.T) {
	target := integrationTarget(t)
	client := Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        10 * time.Second,
	}
	probeClient := Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "probe_known_hosts"),
		Timeout:        10 * time.Second,
	}

	tests := []struct {
		name       string
		newContext func() (context.Context, context.CancelFunc)
		cancel     bool
	}{
		{
			name: "explicit cancellation",
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithCancel(context.Background())
			},
			cancel: true,
		},
		{
			name: "context deadline",
			newContext: func() (context.Context, context.CancelFunc) {
				return context.WithTimeout(context.Background(), 2*time.Second)
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			prefix := integrationName(t)
			startedPath := "/tmp/" + prefix + "-started"
			finishedPath := "/tmp/" + prefix + "-finished"
			shellIdentityPath := "/tmp/" + prefix + "-shell-identity"
			childIdentityPath := "/tmp/" + prefix + "-child-identity"
			cleanupRemoteProcesses(
				t,
				probeClient,
				target,
				[]string{childIdentityPath, shellIdentityPath},
				startedPath,
				finishedPath,
			)

			script := "shell_pid=$$; shell_start=$(awk '{print $22}' \"/proc/$shell_pid/stat\") || exit 71" +
				"; printf '%s %s\\n' \"$shell_pid\" \"$shell_start\" > " + observe.ShellQuote(shellIdentityPath) +
				"; sleep 30 & child_pid=$!" +
				"; child_start=$(awk '{print $22}' \"/proc/$child_pid/stat\") || exit 71" +
				"; printf '%s %s\\n' \"$child_pid\" \"$child_start\" > " + observe.ShellQuote(childIdentityPath) +
				"; touch -- " + observe.ShellQuote(startedPath) +
				"; if wait \"$child_pid\"; then touch -- " + observe.ShellQuote(finishedPath) + "; fi"
			ctx, cancel := test.newContext()
			defer cancel()
			outcome := make(chan error, 1)
			go func() {
				_, err := client.Run(ctx, "it", target, "sh -c "+observe.ShellQuote(script))
				outcome <- err
			}()

			waitForRemotePath(t, probeClient, target, startedPath, 5*time.Second)
			if test.cancel {
				cancel()
			}
			started := time.Now()
			select {
			case err := <-outcome:
				if err == nil {
					t.Fatal("Run(long command) error = nil, want cancellation")
				}
				if got := apperrors.AsAppError(err).Code; got != apperrors.CodeNetworkError {
					t.Fatalf("Run(long command) code = %s, want %s; error=%v", got, apperrors.CodeNetworkError, err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("Run(long command) did not return after cancellation")
			}
			if elapsed := time.Since(started); elapsed > 5*time.Second {
				t.Fatalf("Run(long command) cancellation took %s", elapsed)
			}
			processes := []integrationProcessIdentity{
				readIntegrationProcessIdentity(t, probeClient, target, shellIdentityPath),
				readIntegrationProcessIdentity(t, probeClient, target, childIdentityPath),
			}
			waitForRemoteProcessesExit(t, probeClient, target, processes, 5*time.Second)

			probeCtx, probeCancel := context.WithTimeout(context.Background(), 2*time.Second)
			result, err := probeClient.Run(
				probeCtx,
				"it",
				target,
				"test ! -e "+observe.ShellQuote(finishedPath),
			)
			probeCancel()
			if err != nil {
				t.Fatalf("Run(check unfinished marker) error = %v", err)
			}
			if result.ExitCode != 0 {
				t.Fatalf("long command reached its completion marker after cancellation: %#v", result)
			}
		})
	}
}

func TestIntegrationProcessIdentityParsing(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		wantErr bool
	}{
		{name: "valid", value: "123 456\n"},
		{name: "missing newline", value: "123 456", wantErr: true},
		{name: "extra field", value: "123 456 789\n", wantErr: true},
		{name: "extra line", value: "123 456\n789 101\n", wantErr: true},
		{name: "non-decimal pid", value: "12x 456\n", wantErr: true},
		{name: "unsafe pid", value: "1 456\n", wantErr: true},
		{name: "zero start time", value: "123 0\n", wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := parseIntegrationProcessIdentity(test.value)
			if (err != nil) != test.wantErr {
				t.Fatalf("parseIntegrationProcessIdentity(%q) error = %v, wantErr %v", test.value, err, test.wantErr)
			}
		})
	}
}

func integrationTarget(t *testing.T) srvgovctx.Context {
	t.Helper()
	addr := os.Getenv("SRVGOV_IT_SSH_ADDR")
	if addr == "" {
		if os.Getenv("SRVGOV_IT_REQUIRED") == "1" {
			t.Fatal("set SRVGOV_IT_SSH_ADDR when SRVGOV_IT_REQUIRED=1")
		}
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
	return integrationContext(t, addr, user, keyPath)
}

func waitForRemotePath(
	t *testing.T,
	client Client,
	target srvgovctx.Context,
	remotePath string,
	timeout time.Duration,
) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		result, err := client.Run(ctx, "it", target, "test -e "+observe.ShellQuote(remotePath))
		cancel()
		if err == nil && result.ExitCode == 0 {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("remote path %q was not created within %s", remotePath, timeout)
}

type integrationProcessIdentity struct {
	PID       uint64
	StartTime uint64
}

func readIntegrationProcessIdentity(
	t *testing.T,
	client Client,
	target srvgovctx.Context,
	identityPath string,
) integrationProcessIdentity {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := client.Run(ctx, "it", target, "cat -- "+observe.ShellQuote(identityPath))
	if err != nil {
		t.Fatalf("Run(read process identity %q) error = %v", identityPath, err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Run(read process identity %q) exit = %d; stderr=%q", identityPath, result.ExitCode, result.Stderr)
	}
	identity, err := parseIntegrationProcessIdentity(result.Stdout)
	if err != nil {
		t.Fatalf("parse process identity %q: %v", identityPath, err)
	}
	return identity
}

func parseIntegrationProcessIdentity(value string) (integrationProcessIdentity, error) {
	var identity integrationProcessIdentity
	fields, err := fmt.Sscanf(value, "%d %d\n", &identity.PID, &identity.StartTime)
	if err != nil || fields != 2 || identity.PID <= 1 || identity.StartTime == 0 ||
		value != fmt.Sprintf("%d %d\n", identity.PID, identity.StartTime) {
		return integrationProcessIdentity{}, fmt.Errorf("identity must be one canonical PID/starttime line")
	}
	return identity, nil
}

func waitForRemoteProcessesExit(
	t *testing.T,
	client Client,
	target srvgovctx.Context,
	processes []integrationProcessIdentity,
	timeout time.Duration,
) {
	t.Helper()
	command := remoteProcessesGoneCommand(processes)
	deadline := time.Now().Add(timeout)
	lastStatus := "matching process identity still exists"
	for time.Now().Before(deadline) {
		remaining := time.Until(deadline)
		probeTimeout := time.Second
		if remaining < probeTimeout {
			probeTimeout = remaining
		}
		ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
		result, err := client.Run(ctx, "it", target, command)
		cancel()
		if err != nil {
			lastStatus = err.Error()
		} else if result.ExitCode == 0 {
			return
		} else if result.ExitCode != 1 {
			lastStatus = fmt.Sprintf("process identity probe exited %d: %s", result.ExitCode, result.Stderr)
		}
		remaining = time.Until(deadline)
		if remaining <= 0 {
			break
		}
		delay := 25 * time.Millisecond
		if remaining < delay {
			delay = remaining
		}
		time.Sleep(delay)
	}
	t.Fatalf("remote processes did not exit within %s (%s)", timeout, lastStatus)
}

func remoteProcessesGoneCommand(processes []integrationProcessIdentity) string {
	command := `process_gone() {
	proc=$1
	expected=$2
	[ -e "$proc" ] || return 0
	current=$(awk '{print $22}' "$proc" 2>/dev/null) || {
		[ -e "$proc" ] || return 0
		return 2
	}
	case "$current" in ''|*[!0-9]*) return 2 ;; esac
	[ "$current" != "$expected" ]
}`
	for _, process := range processes {
		procPath := "/proc/" + strconv.FormatUint(process.PID, 10) + "/stat"
		command += "\nprocess_gone " + observe.ShellQuote(procPath) + " " +
			strconv.FormatUint(process.StartTime, 10) + " || exit $?"
	}
	return command
}

func cleanupRemoteProcesses(
	t *testing.T,
	client Client,
	target srvgovctx.Context,
	identityPaths []string,
	paths ...string,
) {
	t.Helper()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		command := `terminate_identity() {
	identity_path=$1
	[ -f "$identity_path" ] || return 0
	pid=
	expected=
	extra=
	IFS=' ' read -r pid expected extra < "$identity_path" || return 0
	case "$pid" in ''|*[!0-9]*) return 0 ;; esac
	case "$expected" in ''|*[!0-9]*) return 0 ;; esac
	[ -z "$extra" ] || return 0
	[ "$pid" -gt 1 ] 2>/dev/null || return 0
	[ "$expected" -gt 0 ] 2>/dev/null || return 0
	proc=/proc/$pid/stat
	[ -e "$proc" ] || return 0
	current=$(awk '{print $22}' "$proc" 2>/dev/null) || return 0
	[ "$current" = "$expected" ] || return 0
	kill -TERM "$pid" 2>/dev/null || true
}`
		for _, identityPath := range identityPaths {
			command += "\nterminate_identity " + observe.ShellQuote(identityPath)
		}
		command += "\nrm -f --"
		for _, identityPath := range identityPaths {
			command += " " + observe.ShellQuote(identityPath)
		}
		for _, remotePath := range paths {
			command += " " + observe.ShellQuote(remotePath)
		}
		_, _ = client.Run(ctx, "it", target, command)
	})
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
