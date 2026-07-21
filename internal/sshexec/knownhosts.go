package sshexec

import (
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/ssh"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/trust"
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
	candidate := trust.Pin{
		Address:     address,
		Algorithm:   key.Type(),
		Fingerprint: ssh.FingerprintSHA256(key),
		Material:    key.Marshal(),
	}
	var adapter func(trust.Pin)
	if notify != nil {
		adapter = func(pin trust.Pin) {
			notify(pinFromTrust(pin))
		}
	}
	return translateTrustError(trust.New(path).VerifyOrPin(address, candidate, adapter))
}

// CheckKnownHostsPermissions validates an existing pin file without modifying it.
// A missing file is valid because TOFU has not initialized the store yet.
func CheckKnownHostsPermissions(path string) (bool, error) {
	exists, err := trust.CheckPermissions(path)
	return exists, translateTrustError(err)
}

func pinFromTrust(pin trust.Pin) Pin {
	return Pin{
		Address:     pin.Address,
		KeyType:     pin.Algorithm,
		Fingerprint: pin.Fingerprint,
		PublicKey:   base64.StdEncoding.EncodeToString(pin.Material),
	}
}

func translateTrustError(err error) error {
	if err == nil {
		return nil
	}
	var changed *trust.PinChangedError
	if errors.As(err, &changed) {
		return &HostKeyChangedError{
			Address:             changed.Address,
			KeyType:             changed.Algorithm,
			ExpectedFingerprint: changed.ExpectedFingerprint,
			ActualFingerprint:   changed.ActualFingerprint,
		}
	}
	var changedType *trust.PinAlgorithmChangedError
	if errors.As(err, &changedType) {
		return &HostKeyTypeChangedError{
			Address:        changedType.Address,
			ActualKeyType:  changedType.ActualAlgorithm,
			PinnedKeyTypes: changedType.PinnedAlgorithms,
		}
	}
	var appErr *apperrors.AppError
	if errors.As(err, &appErr) {
		if message, ok := sshTrustErrorMessage(appErr.Message); ok {
			return apperrors.New(appErr.Code, message, appErr.Unwrap()).WithSuggestion(appErr.Suggestion)
		}
	}
	return err
}

func sshTrustErrorMessage(message string) (string, bool) {
	switch message {
	case "failed to create trust directory":
		return "failed to create SSH trust directory", true
	case "failed to open trust pins":
		return "failed to open SSH host-key pins", true
	case "failed to parse trust pin":
		return "failed to parse SSH host-key pin", true
	case "invalid trust pin record":
		return "invalid SSH host-key pin record", true
	case "failed to read trust pins":
		return "failed to read SSH host-key pins", true
	case "failed to secure trust pins":
		return "failed to secure SSH host-key pins", true
	case "failed to write trust pin":
		return "failed to write SSH host-key pin", true
	case "failed to inspect trust pins":
		return "failed to inspect SSH host-key pins", true
	case "trust pin path must be a regular file":
		return "SSH host-key pin path must be a regular file", true
	case "trust pin permissions are insecure":
		return "SSH host-key pin permissions are insecure", true
	default:
		return "", false
	}
}
