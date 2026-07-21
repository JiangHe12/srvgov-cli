//go:build integration

package cmd

import (
	"bytes"
	"context"
	"crypto/sha256"
	"io"
	"net"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	corectx "github.com/JiangHe12/opskit-core/v2/ctx"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

func TestIntegrationOpenSSHRealServerFileCorePaths(t *testing.T) {
	target := integrationFileTarget(t)
	client := sshexec.Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "known_hosts"),
		Timeout:        10 * time.Second,
	}
	cleanupClient := sshexec.Client{
		KnownHostsPath: filepath.Join(t.TempDir(), "cleanup_known_hosts"),
		Timeout:        10 * time.Second,
	}
	suffix := strconv.FormatInt(time.Now().UnixNano(), 36)
	remoteDir := "/tmp/srvgov-file-it-" + suffix
	markerName := "srvgov-file-injected-" + suffix
	base := "app'; touch " + markerName + "; #"
	remoteFile := path.Join(remoteDir, base)
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = cleanupClient.Run(
			ctx,
			"it",
			target,
			"rm -rf -- "+observe.ShellQuote(remoteDir)+"; rm -f -- "+observe.ShellQuote(markerName),
		)
	})

	runIntegrationSSH(t, client, target, "mkdir -m 700 -- "+observe.ShellQuote(remoteDir))
	initial := "old-data\n"
	runIntegrationSSH(
		t,
		client,
		target,
		"umask 077; printf '%s' "+observe.ShellQuote(initial)+" > "+observe.ShellQuote(remoteFile)+
			"; chmod 640 -- "+observe.ShellQuote(remoteFile),
	)

	directory, parsedBase, err := splitRemoteFileWriteTarget(remoteFile)
	if err != nil {
		t.Fatalf("splitRemoteFileWriteTarget() error = %v", err)
	}
	resolvedResult := runIntegrationSSH(t, client, target, fileWriteResolveDirectoryCommand(directory))
	resolvedDirectory, err := parseResolvedFileWriteDirectory(resolvedResult.Stdout)
	if err != nil {
		t.Fatalf("parseResolvedFileWriteDirectory() error = %v", err)
	}
	identityResult := runIntegrationSSH(t, client, target, fileWriteDirectoryIdentityCommand(resolvedDirectory))
	directoryIdentity, err := parseFileWriteDirectoryIdentity(identityResult.Stdout)
	if err != nil {
		t.Fatalf("parseFileWriteDirectoryIdentity() error = %v", err)
	}
	binding := fileWriteTargetBinding{
		ResolvedDirectory: resolvedDirectory,
		Base:              parsedBase,
		DirectoryIdentity: directoryIdentity,
	}

	content := []byte("alpha\nbeta=srvgov-it\n")
	writeLimit := len(content) + 8
	writeResult := runIntegrationSSHWithStdin(
		t,
		client,
		target,
		fileWriteCommand(binding, writeLimit, content),
		bytes.NewReader(content),
	)
	if writeResult.ExitCode != 0 || writeResult.Stdout != "" {
		t.Fatalf("file write result = %#v, want exit 0 and discarded stdout", writeResult)
	}
	requireRemoteFileContent(t, client, target, remoteFile, content)

	readMax := len(content) - 3
	readResult := runIntegrationSSH(t, client, target, fileReadCommand(remoteFile, readMax))
	readData, err := fileReadData("read", remoteFile, readMax, readResult.Stdout)
	if err != nil {
		t.Fatalf("fileReadData(truncated) error = %v", err)
	}
	readView, ok := readData.(fileReadView)
	if !ok || !readView.Truncated || readView.Bytes != readMax || readView.Content != string(content[:readMax]) {
		t.Fatalf("truncated file read = %#v", readData)
	}
	fullReadResult := runIntegrationSSH(t, client, target, fileReadCommand(remoteFile, len(content)))
	fullReadData, err := fileReadData("read", remoteFile, len(content), fullReadResult.Stdout)
	if err != nil {
		t.Fatalf("fileReadData(full) error = %v", err)
	}
	fullReadView, ok := fullReadData.(fileReadView)
	if !ok || fullReadView.Truncated || fullReadView.Bytes != len(content) || fullReadView.Content != string(content) {
		t.Fatalf("full file read = %#v", fullReadData)
	}

	statResult := runIntegrationSSH(t, client, target, fileStatCommand(remoteFile))
	statView, err := parseFileStat(remoteFile, statResult.Stdout)
	if err != nil {
		t.Fatalf("parseFileStat() error = %v", err)
	}
	if statView.Type != "regular file" || statView.Size != int64(len(content)) || statView.Mode != "640" {
		t.Fatalf("file stat = %#v", statView)
	}

	listResult := runIntegrationSSH(t, client, target, fileListCommand(remoteDir))
	items, err := parseFileList(listResult.Stdout)
	if err != nil {
		t.Fatalf("parseFileList() error = %v", err)
	}
	if len(items) != 1 || items[0].Name != base || items[0].Type != "file" ||
		items[0].Size != int64(len(content)) || items[0].Mode != "640" {
		t.Fatalf("file list = %#v", items)
	}

	digestExpected := []byte("digest-A")
	digestActual := []byte("digest-B")
	digestResult := runIntegrationSSHWithStdin(
		t,
		client,
		target,
		fileWriteCommand(binding, len(digestExpected), digestExpected),
		bytes.NewReader(digestActual),
	)
	if digestResult.ExitCode != 66 {
		t.Fatalf("digest mismatch exit = %d, want 66; result=%#v", digestResult.ExitCode, digestResult)
	}
	requireRemoteFileContent(t, client, target, remoteFile, content)

	limitExpected := []byte("1234")
	limitResult := runIntegrationSSHWithStdin(
		t,
		client,
		target,
		fileWriteCommand(binding, len(limitExpected), limitExpected),
		strings.NewReader("12345"),
	)
	if limitResult.ExitCode != 66 {
		t.Fatalf("oversized write exit = %d, want 66; result=%#v", limitResult.ExitCode, limitResult)
	}
	requireRemoteFileContent(t, client, target, remoteFile, content)

	tempResult := runIntegrationSSH(
		t,
		client,
		target,
		"find "+observe.ShellQuote(remoteDir)+" -maxdepth 1 -name '.*.srvgov.*' -print",
	)
	if tempResult.Stdout != "" {
		t.Fatalf("atomic file-write temporary files remain: %q", tempResult.Stdout)
	}
	markerResult := runIntegrationSSH(t, client, target, "test ! -e "+observe.ShellQuote(markerName))
	if markerResult.ExitCode != 0 {
		t.Fatalf("quoted file path created injection marker: %#v", markerResult)
	}
}

func integrationFileTarget(t *testing.T) srvgovctx.Context {
	t.Helper()
	address := os.Getenv("SRVGOV_IT_SSH_ADDR")
	if address == "" {
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
	host, portText, err := net.SplitHostPort(address)
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

func runIntegrationSSH(
	t *testing.T,
	client sshexec.Client,
	target srvgovctx.Context,
	command string,
) sshexec.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.Run(ctx, "it", target, command)
	if err != nil {
		t.Fatalf("Run(%q) error = %v", command, err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("Run(%q) exit = %d; stderr=%q", command, result.ExitCode, result.Stderr)
	}
	return result
}

func runIntegrationSSHWithStdin(
	t *testing.T,
	client sshexec.Client,
	target srvgovctx.Context,
	command string,
	stdin io.Reader,
) sshexec.Result {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	result, err := client.RunWithStdin(ctx, "it", target, command, stdin)
	if err != nil {
		t.Fatalf("RunWithStdin() error = %v", err)
	}
	return result
}

func requireRemoteFileContent(
	t *testing.T,
	client sshexec.Client,
	target srvgovctx.Context,
	remoteFile string,
	want []byte,
) {
	t.Helper()
	result := runIntegrationSSH(t, client, target, "cat -- "+observe.ShellQuote(remoteFile))
	if result.Stdout != string(want) {
		t.Fatalf("remote file content = %q, want %q", result.Stdout, want)
	}
	digest := sha256.Sum256([]byte(result.Stdout))
	wantDigest := sha256.Sum256(want)
	if digest != wantDigest {
		t.Fatalf("remote file digest = %x, want %x", digest, wantDigest)
	}
}
