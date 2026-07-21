package cmd

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/safety"

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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCtxRoleSet(cmd, f, args[0], opts)
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
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCtxRoleUnset(cmd, f, args[0], opts)
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

func runCtxRoleSet(cmd *cobra.Command, f *cliFlags, contextName string, opts roleOptions) error {
	opts.targetOperator = strings.TrimSpace(opts.targetOperator)
	if opts.targetOperator == "" {
		return apperrors.New(apperrors.CodeUsageError, "--target-operator is required", nil)
	}
	if !validRole(opts.role) {
		return apperrors.New(apperrors.CodeUsageError, "--role must be reader, writer, or admin", nil)
	}
	var auditHandle *mutationAuditHandle
	updateErr := srvgovctx.Update(func(cfg *srvgovctx.Config) error {
		item, ok := cfg.Contexts[contextName]
		if !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", contextName), nil)
		}
		if authErr := authorizeControlChange(
			cmd,
			f,
			item,
			contextName,
			"role.assign",
			allowRoleChange,
			f.AllowRoleChange,
		); authErr != nil {
			return authErr
		}
		var auditErr error
		auditHandle, auditErr = beginControlMutationAudit(
			f,
			"role.assign",
			contextName,
			opts.targetOperator,
			item,
			item,
		)
		if auditErr != nil {
			return auditErr
		}
		item.Roles = cloneRoles(item.Roles)
		if item.Roles == nil {
			item.Roles = map[string]string{}
		}
		item.Roles[opts.targetOperator] = opts.role
		cfg.Contexts[contextName] = item
		return nil
	})
	if err := finishControlMutationAudit(auditHandle, updateErr); err != nil {
		return err
	}
	return newPrinter(f).Success(fmt.Sprintf("role %q assigned to %q in context %q", opts.role, opts.targetOperator, contextName))
}

func runCtxRoleUnset(cmd *cobra.Command, f *cliFlags, contextName string, opts roleOptions) error {
	opts.targetOperator = strings.TrimSpace(opts.targetOperator)
	if opts.targetOperator == "" {
		return apperrors.New(apperrors.CodeUsageError, "--target-operator is required", nil)
	}
	var auditHandle *mutationAuditHandle
	updateErr := srvgovctx.Update(func(cfg *srvgovctx.Config) error {
		item, ok := cfg.Contexts[contextName]
		if !ok {
			return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("context %q not found", contextName), nil)
		}
		if authErr := authorizeControlChange(
			cmd,
			f,
			item,
			contextName,
			"role.revoke",
			allowRoleChange,
			f.AllowRoleChange,
		); authErr != nil {
			return authErr
		}
		var auditErr error
		auditHandle, auditErr = beginControlMutationAudit(
			f,
			"role.revoke",
			contextName,
			opts.targetOperator,
			item,
			item,
		)
		if auditErr != nil {
			return auditErr
		}
		item.Roles = cloneRoles(item.Roles)
		delete(item.Roles, opts.targetOperator)
		if len(item.Roles) == 0 {
			item.Roles = nil
		}
		cfg.Contexts[contextName] = item
		return nil
	})
	if err := finishControlMutationAudit(auditHandle, updateErr); err != nil {
		return err
	}
	return newPrinter(f).Success(fmt.Sprintf("role removed from %q in context %q", opts.targetOperator, contextName))
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
		return p.Info("(no roles assigned)")
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{item.Operator, item.Role})
	}
	return p.Table([]string{"OPERATOR", "ROLE"}, rows)
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

func cloneRoles(roles map[string]string) map[string]string {
	if len(roles) == 0 {
		return nil
	}
	cloned := make(map[string]string, len(roles))
	for operator, role := range roles {
		cloned[operator] = role
	}
	return cloned
}
