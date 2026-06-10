package sshexec

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/lockfile"
)

// Pin is one trust-on-first-use host-key record.
type Pin struct {
	Address     string
	KeyType     string
	Fingerprint string
	PublicKey   string
}

// HostKeyChangedError reports a pinned host presenting a different key.
type HostKeyChangedError struct {
	Address             string
	KeyType             string
	ExpectedFingerprint string
	ActualFingerprint   string
}

func (e *HostKeyChangedError) Error() string {
	return fmt.Sprintf(
		"SSH host key changed for %s (%s): expected %s, received %s",
		e.Address,
		e.KeyType,
		e.ExpectedFingerprint,
		e.ActualFingerprint,
	)
}

// HostKeyTypeChangedError reports a known host presenting an unpinned key type.
type HostKeyTypeChangedError struct {
	Address        string
	ActualKeyType  string
	PinnedKeyTypes []string
}

func (e *HostKeyTypeChangedError) Error() string {
	return fmt.Sprintf(
		"SSH host key type changed for %s: pinned types %s, received %s; remove the host pin manually before an authorized key rotation",
		e.Address,
		strings.Join(e.PinnedKeyTypes, ", "),
		e.ActualKeyType,
	)
}

func verifyOrPin(path, address string, key ssh.PublicKey, notify func(Pin)) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to create SSH trust directory", err)
	}
	lock := lockfile.New(path)
	if err := lock.Acquire(); err != nil {
		return err
	}
	defer func() { _ = lock.Release() }()

	if err := securePinFile(path); err != nil {
		return err
	}
	pins, err := loadPins(path)
	if err != nil {
		return err
	}
	actual := pinFor(address, key)
	addressKnown := false
	var sameTypePins []Pin
	pinnedTypes := make(map[string]bool)
	for _, existing := range pins {
		if existing.Address != address {
			continue
		}
		addressKnown = true
		pinnedTypes[existing.KeyType] = true
		if existing.KeyType != key.Type() {
			continue
		}
		sameTypePins = append(sameTypePins, existing)
		decoded, decodeErr := base64.StdEncoding.DecodeString(existing.PublicKey)
		if decodeErr != nil {
			return apperrors.New(apperrors.CodeLocalIOError, "failed to parse SSH host-key pin", decodeErr)
		}
		if bytes.Equal(decoded, key.Marshal()) {
			return nil
		}
	}
	if len(sameTypePins) > 0 {
		existing := sameTypePins[0]
		return &HostKeyChangedError{
			Address:             address,
			KeyType:             key.Type(),
			ExpectedFingerprint: existing.Fingerprint,
			ActualFingerprint:   actual.Fingerprint,
		}
	}
	if addressKnown {
		types := make([]string, 0, len(pinnedTypes))
		for keyType := range pinnedTypes {
			types = append(types, keyType)
		}
		sort.Strings(types)
		return &HostKeyTypeChangedError{
			Address:        address,
			ActualKeyType:  key.Type(),
			PinnedKeyTypes: types,
		}
	}
	if err := appendPin(path, actual); err != nil {
		return err
	}
	if notify != nil {
		notify(actual)
	}
	return nil
}

func loadPins(path string) ([]Pin, error) {
	file, err := os.Open(path) //nolint:gosec // Configured trust-store path is inspected for symlinks and locked before this call.
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to open SSH host-key pins", err)
	}
	defer func() { _ = file.Close() }()

	var pins []Pin
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Split(line, "\t")
		if len(fields) != 4 {
			return nil, apperrors.New(apperrors.CodeLocalIOError, "invalid SSH host-key pin record", nil)
		}
		pins = append(pins, Pin{
			Address:     fields[0],
			KeyType:     fields[1],
			Fingerprint: fields[2],
			PublicKey:   fields[3],
		})
	}
	if err := scanner.Err(); err != nil {
		return nil, apperrors.New(apperrors.CodeLocalIOError, "failed to read SSH host-key pins", err)
	}
	return pins, nil
}

func appendPin(path string, pin Pin) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600) //nolint:gosec // Configured trust-store path is locked and secured immediately after creation.
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to open SSH host-key pins", err)
	}
	defer func() { _ = file.Close() }()
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure SSH host-key pins", err)
	}
	if err := setPinFileACL(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure SSH host-key pins", err)
	}
	if _, err := fmt.Fprintf(file, "%s\t%s\t%s\t%s\n", pin.Address, pin.KeyType, pin.Fingerprint, pin.PublicKey); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to write SSH host-key pin", err)
	}
	return nil
}

func securePinFile(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to inspect SSH host-key pins", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return apperrors.New(apperrors.CodeLocalIOError, "SSH host-key pin path must be a regular file", nil)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure SSH host-key pins", err)
	}
	if err := setPinFileACL(path); err != nil {
		return apperrors.New(apperrors.CodeLocalIOError, "failed to secure SSH host-key pins", err)
	}
	return verifyPinFileSecurity(path)
}

// CheckKnownHostsPermissions validates an existing pin file without modifying it.
// A missing file is valid because TOFU has not initialized the store yet.
func CheckKnownHostsPermissions(path string) (bool, error) {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, apperrors.New(apperrors.CodeLocalIOError, "failed to inspect SSH host-key pins", err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return true, apperrors.New(apperrors.CodeLocalIOError, "SSH host-key pin path must be a regular file", nil)
	}
	if err := verifyPinFileSecurity(path); err != nil {
		return true, apperrors.New(apperrors.CodeLocalIOError, "SSH host-key pin permissions are insecure", err)
	}
	return true, nil
}

func pinFor(address string, key ssh.PublicKey) Pin {
	return Pin{
		Address:     address,
		KeyType:     key.Type(),
		Fingerprint: ssh.FingerprintSHA256(key),
		PublicKey:   base64.StdEncoding.EncodeToString(key.Marshal()),
	}
}
