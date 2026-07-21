package cmd

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"filippo.io/age"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/v2/audit"
	corectx "github.com/JiangHe12/opskit-core/v2/ctx"
	"github.com/JiangHe12/opskit-core/v2/lockfile"
	"github.com/JiangHe12/opskit-core/v2/safety"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func secureAuditTestDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	secureMutationAuditTestParent(t, filepath.Dir(dir))
	secureMutationAuditTestParent(t, dir)
	return dir
}

func TestAuditQueryRedactsLegacyRecords(t *testing.T) {
	path := filepath.Join(secureAuditTestDir(t), "audit.log")
	event := srvgovaudit.Event{
		Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		EventType: srvgovaudit.EventTypeExecRun,
		Operator:  "alice",
		Context:   srvgovaudit.Context{Name: "dev"},
		Target:    srvgovaudit.Target{Host: "example.com:22"},
		Command:   "echo password=command-secret",
		RiskTier:  "R0",
		Status:    srvgovaudit.StatusSucceeded,
		Stdout:    "token=stdout-secret",
		Stderr:    "secretKey: stderr-secret",
		ExitCode:  0,
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatalf("Marshal() error = %v", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	for _, format := range []string{"json", "table"} {
		output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
			"-o", format, "audit", "query", "--path", path,
		)
		if err != nil {
			t.Fatalf("audit -o %s error = %v", format, err)
		}
		for _, secret := range []string{
			"example.com:22",
			"echo password=command-secret",
			"token=stdout-secret",
			"secretKey: stderr-secret",
		} {
			if strings.Contains(output, secret) {
				t.Fatalf("audit -o %s leaked %q: %s", format, secret, output)
			}
		}
		if !strings.Contains(output, "sha256:") {
			t.Fatalf("audit -o %s output = %q", format, output)
		}
	}
}

func TestAuditQueryClearsForgedFingerprintFields(t *testing.T) {
	path := filepath.Join(secureAuditTestDir(t), "audit.log")
	event := srvgovaudit.Event{
		Timestamp:          time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		EventType:          srvgovaudit.EventTypeExecRun,
		Context:            srvgovaudit.Context{Name: "dev"},
		TicketFingerprint:  "ticket=secret",
		TicketBytes:        13,
		CommandFingerprint: "command=secret",
		CommandBytes:       14,
		Target: srvgovaudit.Target{
			Fingerprint: "target=secret",
			Bytes:       13,
		},
		RiskTier: "R0",
		Status:   srvgovaudit.StatusSucceeded,
		Metadata: &srvgovaudit.MutationMetadata{
			PayloadFingerprint: "payload=secret",
			PayloadBytes:       14,
		},
	}
	data, err := json.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	output, err := executeRoot(
		t,
		filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "query", "--path", path,
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, secret := range []string{"ticket=secret", "command=secret", "target=secret", "payload=secret"} {
		if strings.Contains(output, secret) {
			t.Fatalf("audit query leaked forged fingerprint %q: %s", secret, output)
		}
	}
}

func TestAuditQueryFiltersEventType(t *testing.T) {
	path := filepath.Join(secureAuditTestDir(t), "audit.log")
	records := []srvgovaudit.Event{
		{
			Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeExecRun,
			Context:   srvgovaudit.Context{Name: "dev"},
			Target:    srvgovaudit.Target{Host: "example.com:22"},
			RiskTier:  "R0",
			Status:    srvgovaudit.StatusSucceeded,
		},
		{
			Timestamp: time.Date(2026, 6, 10, 12, 1, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeAuthorizationDenied,
			Context:   srvgovaudit.Context{Name: "prod"},
			Target:    srvgovaudit.Target{Host: "prod.example.com:22"},
			RiskTier:  "R3",
			Status:    srvgovaudit.StatusDenied,
		},
	}
	var content strings.Builder
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		content.Write(data)
		content.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "query", "--path", path, "--type", "authorization.denied",
	)
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	got := decodeJSONData[auditQueryResult](t, output, "AuditQueryResult")
	if len(got.Events) != 1 || got.Events[0].EventType != srvgovaudit.EventTypeAuthorizationDenied {
		t.Fatalf("events = %#v", got.Events)
	}
}

func TestAuditQueryReverseAndLimitAreAppliedAfterDecode(t *testing.T) {
	path := filepath.Join(secureAuditTestDir(t), "audit.log")
	records := []srvgovaudit.Event{
		{
			Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeExecRun,
			Operator:  "alice",
			Context:   srvgovaudit.Context{Name: "dev"},
			Target:    srvgovaudit.Target{Host: "example.com:22"},
			RiskTier:  "R0",
			Status:    srvgovaudit.StatusSucceeded,
		},
		{
			Timestamp: time.Date(2026, 6, 10, 12, 1, 0, 0, time.UTC),
			EventType: srvgovaudit.EventTypeAuditVerify,
			Operator:  "alice",
			Context:   srvgovaudit.Context{Name: "dev"},
			Target:    srvgovaudit.Target{Host: "audit.verify"},
			RiskTier:  "R0",
			Status:    srvgovaudit.StatusSucceeded,
		},
	}
	var content strings.Builder
	for _, record := range records {
		data, err := json.Marshal(record)
		if err != nil {
			t.Fatalf("Marshal() error = %v", err)
		}
		content.Write(data)
		content.WriteByte('\n')
	}
	if err := os.WriteFile(path, []byte(content.String()), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "query", "--path", path, "--reverse", "--limit", "1",
	)
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	got := decodeJSONData[auditQueryResult](t, output, "AuditQueryResult")
	if len(got.Events) != 1 || got.Events[0].EventType != srvgovaudit.EventTypeAuditVerify {
		t.Fatalf("events = %#v", got.Events)
	}
}

func TestAuditQueryAndVerifyDecryptEncryptedRecordsFromConfiguredEnvironment(t *testing.T) {
	path, identity := writeEncryptedAuditFixture(t)
	t.Setenv(srvgovAuditPrivateKeyEnv, identity.String())

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "query", "--path", path,
	)
	if err != nil {
		t.Fatalf("audit query error = %v", err)
	}
	query := decodeJSONData[auditQueryResult](t, output, "AuditQueryResult")
	if len(query.Events) != 1 || query.Events[0].EventType != srvgovaudit.EventTypeExecRun {
		t.Fatalf("query result = %#v", query)
	}

	output, err = executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "verify", "--path", path, "--strict",
	)
	if err != nil {
		t.Fatalf("audit verify error = %v", err)
	}
	verified := decodeJSONData[coreaudit.VerifyResult](t, output, "AuditVerifyResult")
	if verified.Total != 1 || verified.Valid != 1 || verified.Malformed != 0 {
		t.Fatalf("verify result = %#v", verified)
	}
}

func TestEncryptedAuditReadsFailClearlyWithoutPrivateKey(t *testing.T) {
	path, _ := writeEncryptedAuditFixture(t)
	t.Setenv(srvgovAuditPrivateKeyEnv, "")

	for _, args := range [][]string{
		{"audit", "query", "--path", path},
		{"audit", "verify", "--path", path},
	} {
		_, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"), args...)
		if got := apperrors.AsAppError(err).Code; got != apperrors.CodeCredentialStoreError {
			t.Fatalf("%v code = %s, want %s; error = %v", args, got, apperrors.CodeCredentialStoreError, err)
		}
		if !strings.Contains(err.Error(), srvgovAuditPrivateKeyEnv) {
			t.Fatalf("%v error does not name required environment: %v", args, err)
		}
	}
}

func TestEncryptedAuditReadErrorDoesNotLeakInvalidPrivateKey(t *testing.T) {
	path, _ := writeEncryptedAuditFixture(t)
	const invalidPrivateKey = "AGE-SECRET-KEY-DO-NOT-LEAK"
	t.Setenv(srvgovAuditPrivateKeyEnv, invalidPrivateKey)

	_, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"audit", "query", "--path", path,
	)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeCredentialStoreError {
		t.Fatalf("audit query code = %s, want %s; error = %v", got, apperrors.CodeCredentialStoreError, err)
	}
	if strings.Contains(err.Error(), invalidPrivateKey) {
		t.Fatalf("audit query error leaked private key: %v", err)
	}
}

func writeEncryptedAuditFixture(t *testing.T) (string, *age.X25519Identity) {
	t.Helper()
	identity, err := age.GenerateX25519Identity()
	if err != nil {
		t.Fatalf("GenerateX25519Identity() error = %v", err)
	}
	dir := secureAuditTestDir(t)
	publicKeyPath := filepath.Join(dir, "audit.age.pub")
	if err := os.WriteFile(publicKeyPath, []byte(identity.Recipient().String()+"\n"), 0o600); err != nil {
		t.Fatalf("WriteFile(public key) error = %v", err)
	}
	path := filepath.Join(dir, "audit.log")
	event := srvgovaudit.Event{
		Timestamp: time.Date(2026, 6, 10, 12, 0, 0, 0, time.UTC),
		EventType: srvgovaudit.EventTypeExecRun,
		Operator:  "alice@example",
		Context:   srvgovaudit.Context{Name: "dev"},
		Target:    srvgovaudit.Target{Host: "example.com:22"},
		Command:   "uname -a",
		RiskTier:  "R0",
		Status:    srvgovaudit.StatusSucceeded,
	}
	if err := srvgovaudit.Append(path, event, coreaudit.Options{EncryptPublicKeyPath: publicKeyPath}); err != nil {
		t.Fatalf("Append(encrypted audit) error = %v", err)
	}
	return path, identity
}

func TestAuditVerifyStrictReturnsValidationFailed(t *testing.T) {
	path := filepath.Join(secureAuditTestDir(t), "audit.log")
	if err := os.WriteFile(path, []byte("{not-json}\n"), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "verify", "--path", path, "--strict",
	)
	assertAppError(t, err, apperrors.CodeValidationFailed, 9)
	got := decodeJSONData[coreaudit.VerifyResult](t, output, "AuditVerifyResult")
	if got.Malformed != 1 {
		t.Fatalf("verify result = %#v", got)
	}
}

func TestStrictAuditVerifyRejectsEveryV2IntegrityProblem(t *testing.T) {
	results := []coreaudit.VerifyResult{
		{IntegrityErrors: 1},
		{SequenceViolations: 1},
		{CheckpointViolations: 1},
		{TruncationDetected: true},
	}
	for _, result := range results {
		if err := strictVerifyError(result, true); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
			t.Fatalf("strictVerifyError(%+v) = %v, want VALIDATION_FAILED", result, err)
		}
	}
}

func TestAuditVerifyHumanOutputCoversV2AndFileIntegrityFields(t *testing.T) {
	result := coreaudit.VerifyResult{
		Total:                    9,
		Valid:                    8,
		Malformed:                1,
		SchemaErrors:             2,
		TimestampOrderViolations: 3,
		Authenticated:            4,
		LegacyUnauthenticated:    5,
		EncryptedOpaque:          6,
		IntegrityErrors:          7,
		SequenceViolations:       8,
		CheckpointViolations:     9,
		TruncationDetected:       true,
		Lock: coreaudit.VerifyLockStatus{
			Present: true,
			Path:    "audit.lock",
			Content: "pid=42",
		},
		Files: []coreaudit.VerifyFileResult{{
			Path:                     "audit.log.20260101-000000.log",
			Total:                    9,
			Valid:                    8,
			Malformed:                1,
			SchemaError:              2,
			TimestampOrderViolations: 3,
			Authenticated:            4,
			LegacyUnauthenticated:    5,
			EncryptedOpaque:          6,
			IntegrityErrors:          7,
			SequenceViolations:       8,
			Quarantine:               "audit.log.quarantine",
			Repaired:                 true,
		}},
	}
	for _, format := range []string{"table", "plain"} {
		t.Run(format, func(t *testing.T) {
			var output strings.Builder
			if err := printAuditVerify(&cliFlags{Output: format, Out: &output}, result); err != nil {
				t.Fatal(err)
			}
			text := output.String()
			for _, want := range []string{
				"AUTHENTICATED",
				"LEGACY_UNAUTHENTICATED",
				"ENCRYPTED_OPAQUE",
				"INTEGRITY_ERRORS",
				"SEQUENCE_VIOLATIONS",
				"CHECKPOINT_VIOLATIONS",
				"TRUNCATION_DETECTED",
				"LOCK_PRESENT",
				"TIMESTAMP_ORDER_VIOLATIONS",
				"QUARANTINE",
				"audit.log.quarantine",
				"pid=42",
			} {
				if !strings.Contains(text, want) {
					t.Fatalf("%s output missing %q:\n%s", format, want, text)
				}
			}
		})
	}
}

func TestAuditPruneDeletesRotatedLogsOnlyWithConfirm(t *testing.T) {
	dir := t.TempDir()
	secureMutationAuditTestParent(t, filepath.Dir(dir))
	secureMutationAuditTestParent(t, dir)
	path := filepath.Join(dir, "audit.log")
	oldRotated := filepath.Join(dir, "audit.log.20260101-000000.log")
	newRotated := filepath.Join(dir, "audit.log.20260201-000000.log")
	for index, filePath := range []string{oldRotated, newRotated, path} {
		line := fmt.Sprintf(
			`{"timestamp":"2026-0%d-01T00:00:00Z","eventType":"test.event","operator":"test","status":"succeeded"}`+"\n",
			index+1,
		)
		if err := os.WriteFile(filePath, []byte(line), 0o600); err != nil {
			t.Fatalf("WriteFile(%s) error = %v", filePath, err)
		}
	}

	output, err := executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "audit", "prune", "--path", path, "--keep-last", "1",
	)
	if err != nil {
		t.Fatalf("audit prune dry-run error = %v", err)
	}
	preview := decodeJSONData[auditPruneResult](t, output, "AuditPruneResult")
	if !preview.DryRun || preview.Count != 1 || preview.Files[0] != oldRotated {
		t.Fatalf("preview = %#v", preview)
	}
	if _, err := os.Stat(oldRotated); err != nil {
		t.Fatalf("old rotated stat after dry-run = %v", err)
	}

	_, err = executeRoot(t, filepath.Join(t.TempDir(), "config.yaml"),
		"-o", "json", "--yes", "--ticket", "OPS-1", "--allow-audit-prune",
		"audit", "prune", "--path", path, "--keep-last", "1", "--confirm",
	)
	if err != nil {
		t.Fatalf("audit prune confirm error = %v", err)
	}
	if _, err := os.Stat(oldRotated); !os.IsNotExist(err) {
		t.Fatalf("old rotated stat after confirm = %v", err)
	}
	if _, err := os.Stat(newRotated); err != nil {
		t.Fatalf("new rotated stat after confirm = %v", err)
	}
}

func TestAuditPruneControlAuditRotatesOutsideTargetNamespace(t *testing.T) {
	operator := mustTrustedOperator(t)
	configPath, auditPath, rotated := prepareGovernedAuditPruneSequence(
		t,
		map[string]string{operator: safety.RoleAdmin},
		2,
	)
	if err := srvgovctx.Update(func(cfg *srvgovctx.Config) error {
		item := cfg.Contexts["guarded"]
		item.AuditMaxSize = 1
		cfg.Contexts["guarded"] = item
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	output, err := executeRoot(t, configPath,
		"-o", "json", "--yes", "--ticket", "OPS-1", "--allow-audit-prune",
		"audit", "prune", "--path", auditPath, "--keep-last", "1", "--confirm",
	)
	if err != nil {
		t.Fatalf("audit prune error = %v; output=%s", err, output)
	}
	if _, err := os.Stat(rotated[0]); !os.IsNotExist(err) {
		t.Fatalf("oldest target rotation still exists: %v", err)
	}
	assertAuditFileExists(t, rotated[1])

	controlPath := auditPruneControlPath(auditPath)
	controlRotated, err := coreaudit.RotatedFiles(controlPath)
	if err != nil || len(controlRotated) == 0 {
		t.Fatalf("control rotations = %v, error=%v; MaxSizeBytes=1 should rotate intent", controlRotated, err)
	}
	targetRotated, err := strictAuditRotatedFiles(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(targetRotated, []string{rotated[1]}) {
		t.Fatalf("target rotations = %v, want only %v", targetRotated, rotated[1])
	}
	for _, controlFile := range controlRotated {
		if slices.Contains(targetRotated, controlFile) {
			t.Fatalf("control rotation polluted target namespace: %s", controlFile)
		}
	}
	controlEvents, err := coreaudit.QueryRaw(controlPath, coreaudit.Filter{})
	if err != nil || len(controlEvents.Records) != 2 {
		t.Fatalf("control audit events = %+v, error=%v; want intent and outcome", controlEvents, err)
	}
}

func TestAuditPruneRequiresTrustedR3AuthorizationBeforeDeletion(t *testing.T) {
	operator := mustTrustedOperator(t)
	tests := []struct {
		name  string
		roles map[string]string
		env   string
		args  []string
	}{
		{
			name:  "missing confirmation",
			roles: map[string]string{operator: safety.RoleAdmin},
			args:  []string{"--ticket", "OPS-1", "--allow-audit-prune"},
		},
		{
			name:  "missing ticket",
			roles: map[string]string{operator: safety.RoleAdmin},
			args:  []string{"--yes", "--allow-audit-prune"},
		},
		{
			name:  "wrong allow flag",
			roles: map[string]string{operator: safety.RoleAdmin},
			args:  []string{"--yes", "--ticket", "OPS-1", "--allow-context-delete"},
		},
		{
			name: "spoofed operator flag and environment",
			roles: map[string]string{
				operator:        safety.RoleReader,
				"spoofed-admin": safety.RoleAdmin,
			},
			env:  "spoofed-admin",
			args: []string{"--operator", "spoofed-admin", "--yes", "--ticket", "OPS-1", "--allow-audit-prune"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			configPath, auditPath, rotated := prepareGovernedAuditPrune(t, tt.roles)
			t.Setenv("SRVGOV_OPERATOR", tt.env)
			args := append([]string{}, tt.args...)
			args = append(args, "audit", "prune", "--path", auditPath, "--keep-last", "0", "--confirm")
			_, runErr := executeRoot(t, configPath, args...)
			assertAppError(t, runErr, apperrors.CodeAuthorizationRequired, 8)
			assertAuditFileExists(t, rotated)
		})
	}
}

func TestAuditPruneExactAllowDeletesWithExistingConfirm(t *testing.T) {
	operator := mustTrustedOperator(t)
	configPath, auditPath, rotated := prepareGovernedAuditPrune(t, map[string]string{operator: safety.RoleAdmin})
	if out, err := executeRoot(t, configPath,
		"--yes",
		"--ticket", "OPS-1",
		"--allow-audit-prune",
		"audit", "prune", "--path", auditPath, "--keep-last", "0", "--confirm",
	); err != nil {
		t.Fatalf("audit prune error = %v; out=%s", err, out)
	}
	if _, err := os.Stat(rotated); !os.IsNotExist(err) {
		t.Fatalf("rotated audit file was not deleted: %v", err)
	}
}

func TestAuditPruneDryRunPrecedesAuthorizationAndPreservesCandidateOrder(t *testing.T) {
	operator := mustTrustedOperator(t)
	configPath, auditPath, rotated := prepareGovernedAuditPruneSequence(
		t,
		map[string]string{
			operator:        safety.RoleReader,
			"spoofed-admin": safety.RoleAdmin,
		},
		3,
	)
	output, err := executeRoot(t, configPath,
		"-o", "json",
		"--operator", "spoofed-admin",
		"audit", "prune", "--path", auditPath, "--keep-last", "1", "--dry-run",
	)
	if err != nil {
		t.Fatalf("dry-run reached authorization: %v; output=%s", err, output)
	}
	preview := decodeJSONData[auditPruneResult](t, output, "AuditPruneResult")
	want := rotated[:2]
	if !preview.DryRun || len(preview.Files) != len(want) {
		t.Fatalf("preview = %+v, want ordered candidates %v", preview, want)
	}
	for i := range want {
		if preview.Files[i] != want[i] {
			t.Fatalf("candidate order = %v, want %v", preview.Files, want)
		}
	}
	for _, filePath := range rotated {
		assertAuditFileExists(t, filePath)
	}
	_, err = executeRoot(t, configPath,
		"--ticket", "OPS-1", "--allow-audit-prune",
		"audit", "prune", "--path", auditPath, "--keep-last", "1", "--dry-run", "--confirm",
	)
	assertAppError(t, err, apperrors.CodeUsageError, 1)
	for _, filePath := range rotated {
		assertAuditFileExists(t, filePath)
	}
}

func TestAuditPruneSupportsAuthenticatedV2History(t *testing.T) {
	operator := mustTrustedOperator(t)
	configPath, auditPath, legacy := prepareGovernedAuditPrune(
		t,
		map[string]string{operator: safety.RoleAdmin},
	)
	if err := os.Remove(legacy); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(auditPath); err != nil {
		t.Fatal(err)
	}
	for index := range 4 {
		if err := coreaudit.AppendRecord(auditPath, map[string]any{
			"timestamp": time.Unix(int64(index+1), 0).UTC(),
			"eventType": "test.event",
			"operator":  "test",
			"status":    "succeeded",
		}, coreaudit.Options{MaxSizeBytes: 1}); err != nil {
			t.Fatal(err)
		}
	}
	rotated, err := coreaudit.RotatedFiles(auditPath)
	if err != nil || len(rotated) < 2 {
		t.Fatalf("authenticated rotations = %v, error=%v", rotated, err)
	}
	oldest := rotated[0]

	output, err := executeRoot(t, configPath,
		"-o", "json", "--yes", "--ticket", "OPS-1", "--allow-audit-prune",
		"audit", "prune", "--path", auditPath, "--keep-last", fmt.Sprint(len(rotated)-1), "--confirm",
	)
	if err != nil {
		t.Fatalf("authenticated audit prune error = %v; output=%s", err, output)
	}
	result := decodeJSONData[auditPruneResult](t, output, "AuditPruneResult")
	if result.Count != 1 || result.Files[0] != oldest || !result.Started ||
		result.CheckpointState != coreaudit.PruneCheckpointAdvanced {
		t.Fatalf("authenticated prune result = %+v", result)
	}
	if _, err := os.Stat(oldest); !os.IsNotExist(err) {
		t.Fatalf("oldest authenticated rotation still exists: %v", err)
	}
	verified, err := coreaudit.Verify(auditPath, coreaudit.VerifyOptions{})
	if err != nil || verified.HasProblems() {
		t.Fatalf("post-prune verify = %+v, error=%v", verified, err)
	}
}

func TestStrictAuditRotatedFilesUsesNumericOrderAndRejectsUnexpectedNames(t *testing.T) {
	auditPath := filepath.Join(secureAuditTestDir(t), "audit.log")
	paths := []string{
		auditPath + ".20260201-000000.10.log",
		auditPath + ".20260201-000000.2.log",
		auditPath + ".20260201-000000.log",
	}
	for _, path := range paths {
		writeAuditTestLine(t, path, `{}`)
	}
	got, err := strictAuditRotatedFiles(auditPath)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{paths[2], paths[1], paths[0]}
	if !slices.Equal(got, want) {
		t.Fatalf("strictAuditRotatedFiles() = %v, want %v", got, want)
	}

	unexpected := auditPath + ".20260201-000000.backup.log"
	writeAuditTestLine(t, unexpected, `{}`)
	if _, err := strictAuditRotatedFiles(auditPath); apperrors.AsAppError(err).Code != apperrors.CodeValidationFailed {
		t.Fatalf("unexpected rotation error = %v, want VALIDATION_FAILED", err)
	}
}

func TestAuditPruneRejectsTamperedRetainedHistory(t *testing.T) {
	operator := mustTrustedOperator(t)
	configPath, auditPath, rotated := prepareGovernedAuditPruneSequence(
		t,
		map[string]string{operator: safety.RoleAdmin},
		2,
	)
	candidate, retained := rotated[0], rotated[1]
	writeV2AuditEnvelope(t, retained)

	_, runErr := executeRoot(t, configPath,
		"--yes", "--ticket", "OPS-1", "--allow-audit-prune",
		"audit", "prune", "--path", auditPath, "--keep-last", "1", "--confirm",
	)
	if got := apperrors.AsAppError(runErr).Code; got != apperrors.CodeValidationFailed {
		t.Fatalf("error code = %s, want %s; err=%v", got, apperrors.CodeValidationFailed, runErr)
	}
	assertAuditFileExists(t, candidate)
	assertAuditFileExists(t, retained)
}

func TestAuditPruneLongLineAndCandidateChangeFailClosed(t *testing.T) {
	operator := mustTrustedOperator(t)
	t.Run("long line", func(t *testing.T) {
		configPath, auditPath, candidate := prepareGovernedAuditPrune(t, map[string]string{operator: safety.RoleAdmin})
		writeAuditTestLine(t, candidate, strings.Repeat("x", 4*1024*1024+1))
		_, runErr := executeRoot(t, configPath,
			"--yes", "--ticket", "OPS-1", "--allow-audit-prune",
			"audit", "prune", "--path", auditPath, "--keep-last", "0", "--confirm",
		)
		if got := apperrors.AsAppError(runErr).Code; got != apperrors.CodeLocalIOError {
			t.Fatalf("error code = %s, want %s; err=%v", got, apperrors.CodeLocalIOError, runErr)
		}
		assertAuditFileExists(t, candidate)
	})
	t.Run("candidate set changed", func(t *testing.T) {
		_, auditPath, candidate := prepareGovernedAuditPrune(t, map[string]string{operator: safety.RoleAdmin})
		rotated, err := strictAuditRotatedFiles(auditPath)
		if err != nil {
			t.Fatal(err)
		}
		preview, err := selectAuditPruneCandidates(auditPath, auditPruneOptions{keepLast: 0}, rotated)
		if err != nil {
			t.Fatal(err)
		}
		added := auditPath + ".20260201-000000.log"
		writeAuditTestLine(t, added, `{}`)
		result, err := coreaudit.PruneRotatedFiles(auditPath, preview, coreaudit.PruneOptions{
			Confirm:              true,
			ExpectedRotatedFiles: rotated,
		})
		if apperrors.AsAppError(err).Code != apperrors.CodeConflict || result.Started {
			t.Fatalf("PruneRotatedFiles() result=%+v error=%v; want CONFLICT before deletion", result, err)
		}
		assertAuditFileExists(t, candidate)
		assertAuditFileExists(t, added)
	})
}

func TestAuditPruneLockOrder(t *testing.T) {
	operator := mustTrustedOperator(t)
	configPath, auditPath, candidate := prepareGovernedAuditPrune(t, map[string]string{operator: safety.RoleAdmin})
	lock := lockfile.New(auditPath)
	if err := lock.Acquire(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = lock.Release() })
	t.Setenv("SRVGOV_LOCK_TIMEOUT", "100ms")

	if output, err := executeRoot(t, configPath,
		"-o", "json",
		"audit", "prune", "--path", auditPath, "--keep-last", "0",
	); err != nil {
		t.Fatalf("preview waited for audit lock: %v; output=%s", err, output)
	}
	_, err := executeRoot(t, configPath,
		"--yes", "--allow-audit-prune",
		"audit", "prune", "--path", auditPath, "--keep-last", "0", "--confirm",
	)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeAuthorizationRequired {
		t.Fatalf("unauthorized confirm error = %v, want AUTHORIZATION_REQUIRED before lock", err)
	}
	_, err = executeRoot(t, configPath,
		"--yes", "--ticket", "OPS-1", "--allow-audit-prune",
		"audit", "prune", "--path", auditPath, "--keep-last", "0", "--confirm",
	)
	if got := apperrors.AsAppError(err).Code; got != apperrors.CodeLocalIOError {
		t.Fatalf("authorized confirm error = %v, want LOCAL_IO_ERROR from held audit lock", err)
	}
	assertAuditFileExists(t, candidate)
}

func TestAuditPruneRejectsGovernedAliasesAndArtifactNamespaces(t *testing.T) {
	configPath := isolatedContextConfig(t)
	secureMutationAuditTestParent(t, filepath.Dir(configPath))
	if err := os.WriteFile(configPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f := &cliFlags{Config: configPath}
	if _, err := normalizeAuditPruneTarget(f, configPath); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("config target error = %v, want USAGE_ERROR", err)
	}

	defaultPath, err := coreaudit.DefaultPath()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(defaultPath), 0o700); err != nil {
		t.Fatal(err)
	}
	secureMutationAuditTestParent(t, filepath.Dir(defaultPath))
	if err := os.WriteFile(defaultPath, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	canonical, err := normalizeAuditPruneTarget(
		f,
		filepath.Join(filepath.Dir(defaultPath), ".", filepath.Base(defaultPath)),
	)
	if err != nil || canonical != defaultPath {
		t.Fatalf("canonical default target = %q, error=%v; want %q", canonical, err, defaultPath)
	}
	hardlink := filepath.Join(filepath.Dir(defaultPath), "audit-hardlink.log")
	if err := os.Link(defaultPath, hardlink); err != nil {
		t.Skipf("hardlinks unavailable: %v", err)
	}
	if _, err := normalizeAuditPruneTarget(f, hardlink); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
		t.Fatalf("hardlink alias error = %v, want USAGE_ERROR", err)
	}
	for _, path := range []string{
		defaultPath + ".checkpoint.tmp-attacker",
		defaultPath + ".hmac-key.tmp-attacker",
		defaultPath + ".20260201-000000.2.log",
	} {
		if _, err := normalizeAuditPruneTarget(f, path); apperrors.AsAppError(err).Code != apperrors.CodeUsageError {
			t.Fatalf("artifact namespace %q error = %v, want USAGE_ERROR", path, err)
		}
	}
}

func TestAuditPruneReportsIndeterminateCheckpointAsUncertain(t *testing.T) {
	err := apperrors.New(apperrors.CodePartialFailure, "injected checkpoint uncertainty", nil)
	outcome := auditPruneMutationOutcome(1, coreaudit.PruneResult{
		Started:         true,
		CheckpointState: coreaudit.PruneCheckpointIndeterminate,
	}, err)
	if outcome.Status != srvgovaudit.StatusFailed ||
		outcome.Succeeded != 0 ||
		outcome.Failed != 0 ||
		outcome.Skipped != 0 ||
		outcome.Uncertain != 1 {
		t.Fatalf("durability outcome = %#v, want one uncertain deletion", outcome)
	}
}

func prepareGovernedAuditPrune(t *testing.T, roles map[string]string) (string, string, string) {
	t.Helper()
	configPath, auditPath, rotated := prepareGovernedAuditPruneSequence(t, roles, 1)
	return configPath, auditPath, rotated[0]
}

func prepareGovernedAuditPruneSequence(t *testing.T, roles map[string]string, count int) (string, string, []string) {
	t.Helper()
	configPath := isolatedContextConfig(t)
	secureMutationAuditTestParent(t, filepath.Dir(configPath))
	item := testServerContext("guarded.example")
	item.Base = corectx.Base{
		OTLPRedact: true,
		Username:   "alice",
		Roles:      roles,
	}
	mustSetContext(t, configPath, "guarded", item)
	if err := srvgovctx.UseContext("guarded"); err != nil {
		t.Fatal(err)
	}
	auditPath := filepath.Join(filepath.Dir(configPath), "audit.log")
	if err := os.WriteFile(
		auditPath,
		[]byte(`{"timestamp":"2026-04-01T00:00:00Z","eventType":"test.event","operator":"test","status":"succeeded"}`+"\n"),
		0o600,
	); err != nil {
		t.Fatal(err)
	}
	rotated := make([]string, 0, count)
	for i := 1; i <= count; i++ {
		filePath := auditPath + "." + []string{"20260101-000000", "20260201-000000", "20260301-000000"}[i-1] + ".log"
		line := fmt.Sprintf(
			`{"timestamp":"2026-0%d-01T00:00:00Z","eventType":"test.event","operator":"test","status":"succeeded"}`+"\n",
			i,
		)
		if err := os.WriteFile(filePath, []byte(line), 0o600); err != nil {
			t.Fatal(err)
		}
		rotated = append(rotated, filePath)
	}
	return configPath, auditPath, rotated
}

func writeV2AuditEnvelope(t *testing.T, path string) {
	t.Helper()
	content := " { \"kind\": \"AuditEnvelope\", \"apiVersion\": \"opskit-core.io/audit/v2\" }\n"
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func writeAuditTestLine(t *testing.T, path, line string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(line+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func assertAuditFileExists(t *testing.T, path string) {
	t.Helper()
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("expected %s to exist: %v", path, err)
	}
}
