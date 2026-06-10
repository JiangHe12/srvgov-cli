package cmd

import (
	"fmt"
	"sort"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

type roleOptions struct {
	targetOperator string
	role           string
}

type roleItem struct {
	Operator string `json:"operator"`
	Role     string `json:"role"`
}

func ctxRoleCmd(f *cliFlags) *cobra.Command {
	command := &cobra.Command{
		Use:   "role",
		Short: "Manage context RBAC roles",
	}
	command.AddCommand(ctxRoleSetCmd(f), ctxRoleUnsetCmd(f), ctxRoleListCmd(f))
	return command
}

func ctxRoleSetCmd(f *cliFlags) *cobra.Command {
	var opts roleOptions
	command := &cobra.Command{
		Use:   "set <context>",
		Short: "Assign an operator role for a context",
		Args:  requireExactArgs("ctx role set"),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxRoleSet(f, args[0], opts)
		},
	}
	command.Flags().StringVar(&opts.targetOperator, "target-operator", "", "Operator identity to assign")
	command.Flags().StringVar(&opts.role, "role", "", "Role: reader, writer, admin")
	return command
}

func ctxRoleUnsetCmd(f *cliFlags) *cobra.Command {
	var opts roleOptions
	command := &cobra.Command{
		Use:   "unset <context>",
		Short: "Remove an operator role from a context",
		Args:  requireExactArgs("ctx role unset"),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxRoleUnset(f, args[0], opts)
		},
	}
	command.Flags().StringVar(&opts.targetOperator, "target-operator", "", "Operator identity to remove")
	return command
}

func ctxRoleListCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "list <context>",
		Short: "List operator roles for a context",
		Args:  requireExactArgs("ctx role list"),
		RunE: func(_ *cobra.Command, args []string) error {
			return runCtxRoleList(f, args[0])
		},
	}
}

func runCtxRoleSet(f *cliFlags, contextName string, opts roleOptions) error {
	if opts.targetOperator == "" {
		return apperrors.New(apperrors.CodeUsageError, "--target-operator is required", nil)
	}
	if !validRole(opts.role) {
		return apperrors.New(apperrors.CodeUsageError, "--role must be reader, writer, or admin", nil)
	}
	item, err := loadContextForRole(contextName)
	if err != nil {
		return err
	}
	if item.Roles == nil {
		item.Roles = map[string]string{}
	}
	item.Roles[opts.targetOperator] = opts.role
	if err := srvgovctx.SetContext(contextName, item); err != nil {
		return err
	}
	event := roleAuditEvent(f, srvgovaudit.EventTypeRoleAssign, contextName, opts.targetOperator)
	event.Command = opts.role
	emitAudit(event, nil)
	newPrinter(f).Success(fmt.Sprintf("role %q assigned to %q in context %q", opts.role, opts.targetOperator, contextName))
	return nil
}

func runCtxRoleUnset(f *cliFlags, contextName string, opts roleOptions) error {
	if opts.targetOperator == "" {
		return apperrors.New(apperrors.CodeUsageError, "--target-operator is required", nil)
	}
	item, err := loadContextForRole(contextName)
	if err != nil {
		return err
	}
	if item.Roles != nil {
		delete(item.Roles, opts.targetOperator)
		if len(item.Roles) == 0 {
			item.Roles = nil
		}
	}
	if err := srvgovctx.SetContext(contextName, item); err != nil {
		return err
	}
	emitAudit(roleAuditEvent(f, srvgovaudit.EventTypeRoleRevoke, contextName, opts.targetOperator), nil)
	newPrinter(f).Success(fmt.Sprintf("role removed from %q in context %q", opts.targetOperator, contextName))
	return nil
}

func runCtxRoleList(f *cliFlags, contextName string) error {
	item, err := loadContextForRole(contextName)
	if err != nil {
		return err
	}
	items := roleItems(item.Roles)
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONList("RoleList", items, len(items), 1, len(items), false)
	}
	if len(items) == 0 {
		p.Info("(no roles assigned)")
		return nil
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{item.Operator, item.Role})
	}
	p.Table([]string{"OPERATOR", "ROLE"}, rows)
	return nil
}

func loadContextForRole(name string) (srvgovctx.Context, error) {
	cfg, err := srvgovctx.Load()
	if err != nil {
		return srvgovctx.Context{}, err
	}
	item, ok := cfg.Contexts[name]
	if !ok {
		return srvgovctx.Context{}, apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", name), nil)
	}
	return item, nil
}

func validRole(role string) bool {
	return role == safety.RoleReader || role == safety.RoleWriter || role == safety.RoleAdmin
}

func roleItems(roles map[string]string) []roleItem {
	operators := make([]string, 0, len(roles))
	for operator := range roles {
		operators = append(operators, operator)
	}
	sort.Strings(operators)
	items := make([]roleItem, 0, len(operators))
	for _, operator := range operators {
		items = append(items, roleItem{Operator: operator, Role: roles[operator]})
	}
	return items
}

func roleAuditEvent(f *cliFlags, eventType srvgovaudit.EventType, contextName, operator string) srvgovaudit.Event {
	return srvgovaudit.Event{
		EventType: eventType,
		Operator:  resolveOperator(f.Operator),
		Context:   srvgovaudit.Context{Name: contextName},
		Target:    srvgovaudit.Target{Host: operator},
		Command:   string(eventType),
		RiskTier:  "R0",
		Status:    srvgovaudit.StatusSucceeded,
	}
}
