package cmd

import (
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestContextRoleLifecycleAndAudit(t *testing.T) {
	configPath := prepareExecContext(t, false)
	operator := mustTrustedOperator(t)

	runCommand(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-role-change",
		"ctx", "role", "set", "dev", "--target-operator", operator, "--role", "admin",
	)
	output := runCommand(t, configPath, "-o", "json", "ctx", "role", "list", "dev")
	roles := decodeJSONList[roleItem](t, output, "RoleList").Items
	if len(roles) != 1 || roles[0].Operator != operator || roles[0].Role != "admin" {
		t.Fatalf("roles = %#v", roles)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Contexts["dev"].Roles[operator] != "admin" {
		t.Fatalf("stored roles = %#v", cfg.Contexts["dev"].Roles)
	}

	runCommand(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-role-change",
		"ctx", "role", "unset", "dev", "--target-operator", operator,
	)
	events := readAuditEvents(t)
	assignIntent, assignOutcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeRoleAssign), "dev", "R3")
	revokeIntent, revokeOutcome := requireMutationPair(t, events, string(srvgovaudit.EventTypeRoleRevoke), "dev", "R3")
	if assignIntent.Operator != operator || assignOutcome.Operator != operator ||
		revokeIntent.Operator != operator || revokeOutcome.Operator != operator {
		t.Fatalf("mutation operators = %#v / %#v / %#v / %#v", assignIntent, assignOutcome, revokeIntent, revokeOutcome)
	}
}

func TestContextRoleAffectsExecAuthorization(t *testing.T) {
	configPath := prepareExecContext(t, false)
	operator := mustTrustedOperator(t)
	runCommand(t, configPath,
		"--ticket", "TEST-1", "--yes", "--allow-role-change",
		"ctx", "role", "set", "dev", "--target-operator", operator, "--role", "reader",
	)

	_, err := executeRoot(t, configPath,
		"--operator", "spoofed-admin", "--non-interactive", "--yes",
		"exec", "--reason", "prepare deploy", "touch ./ready",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
}
