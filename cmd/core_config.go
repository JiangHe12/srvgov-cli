package cmd

import (
	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/credstore"
	corectx "github.com/JiangHe12/opskit-core/ctx"
	"github.com/JiangHe12/opskit-core/lockfile"
	"github.com/JiangHe12/opskit-core/printer"
	"github.com/JiangHe12/opskit-core/safety"
	"github.com/JiangHe12/opskit-core/telemetry"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func init() {
	apperrors.Configure(apperrors.Options{
		APIVersion: "srvgov-cli.io/v1",
		Suggestions: map[apperrors.ErrorCode]string{
			apperrors.CodeCredentialStoreMissing: "Re-run srvgov ctx set with a password, or configure a credential backend.",
		},
	})
	audit.Configure(audit.Config{
		APIVersion:         "srvgov-cli.io/audit/v1",
		ConfigDirName:      ".srvgov",
		PrivateKeyEnvVar:   "SRVGOV_AUDIT_PRIVATE_KEY",
		TargetTypeJSONName: "objectType",
	})
	corectx.Configure(corectx.Options{APIVersion: srvgovctx.SupportedContextAPIVersion, ConfigDirName: ".srvgov"})
	lockfile.Configure(lockfile.Options{TimeoutEnvVar: "SRVGOV_LOCK_TIMEOUT"})
	printer.Configure(printer.Options{APIVersion: "srvgov-cli.io/v1", JSONEnvelopeByDefault: true})
	safety.Configure(safety.Config{
		Prompt:                   "Proceed with remote server operation? [y/N] ",
		OperatorEnvVar:           "SRVGOV_OPERATOR",
		RoleAssignmentHintFormat: "assign an operator role for this srvgov context",
	})
	telemetry.Configure(telemetry.Config{
		ServiceName:      "srvgov",
		AttributePrefix:  "srvgov",
		MetricNamePrefix: "srvgov",
	})
	//nolint:gosec // Environment variable and file magic constants, not embedded credentials.
	credstore.Configure(credstore.Options{
		MasterPasswordEnv:  "SRVGOV_MASTER_PASSWORD",
		PromptName:         "srvgov",
		ConfigDirName:      ".srvgov",
		KeychainService:    "srvgov",
		EncryptedFileMagic: []byte("SRVGOV01"),
	})
}
