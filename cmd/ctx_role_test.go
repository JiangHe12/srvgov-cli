package cmd

import (
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func TestContextRoleLifecycleAndAudit(t *testing.T) {
	configPath := prepareExecContext(t, false)

	runCommand(t, configPath, "ctx", "role", "set", "dev", "--target-operator", "alice", "--role", "writer")
	output := runCommand(t, configPath, "-o", "json", "ctx", "role", "list", "dev")
	roles := decodeJSONList[roleItem](t, output, "RoleList").Items
	if len(roles) != 1 || roles[0].Operator != "alice" || roles[0].Role != "writer" {
		t.Fatalf("roles = %#v", roles)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.Contexts["dev"].Roles["alice"] != "writer" {
		t.Fatalf("stored roles = %#v", cfg.Contexts["dev"].Roles)
	}

	runCommand(t, configPath, "ctx", "role", "unset", "dev", "--target-operator", "alice")
	events := readAuditEvents(t)
	if len(events) < 2 ||
		events[len(events)-2].EventType != srvgovaudit.EventTypeRoleAssign ||
		events[len(events)-1].EventType != srvgovaudit.EventTypeRoleRevoke {
		t.Fatalf("audit events = %#v", events)
	}
}

func TestContextRoleAffectsExecAuthorization(t *testing.T) {
	configPath := prepareExecContext(t, false)
	runCommand(t, configPath, "ctx", "role", "set", "dev", "--target-operator", "alice", "--role", "reader")

	_, err := executeRoot(t, configPath,
		"--operator", "alice", "--non-interactive", "--yes",
		"exec", "--reason", "prepare deploy", "touch ./ready",
	)
	assertAppError(t, err, apperrors.CodeAuthorizationRequired, 8)
}
