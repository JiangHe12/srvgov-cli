package cmd

import (
	"encoding/json"
	"fmt"
	"time"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	coreaudit "github.com/JiangHe12/opskit-core/audit"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
)

type auditQueryOptions struct {
	since    string
	until    string
	operator string
	event    string
	status   string
	context  string
	limit    int
	reverse  bool
	path     string
}

type auditVerifyOptions struct {
	strict bool
	path   string
}

type auditQueryResult struct {
	Events    []srvgovaudit.Event `json:"events"`
	Malformed int                 `json:"malformed"`
}

func newAuditCmd(f *cliFlags) *cobra.Command {
	command := &cobra.Command{
		Use:   "audit",
		Short: "Query and verify srvgov audit logs",
	}
	command.AddCommand(auditQueryCmd(f), auditVerifyCmd(f), auditPruneCmd(f))
	return command
}

func auditQueryCmd(f *cliFlags) *cobra.Command {
	var opts auditQueryOptions
	command := &cobra.Command{
		Use:   "query",
		Short: "Query audit events",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAuditQuery(f, opts)
		},
	}
	command.Flags().StringVar(&opts.since, "since", "", "Only include events at or after this time")
	command.Flags().StringVar(&opts.until, "until", "", "Only include events at or before this time")
	command.Flags().StringVar(&opts.operator, "operator", "", "Filter by operator")
	command.Flags().StringVar(&opts.event, "type", "", "Filter by event type")
	command.Flags().StringVar(&opts.status, "status", "", "Filter by status")
	command.Flags().StringVar(&opts.context, "context", "", "Filter by context name")
	command.Flags().IntVar(&opts.limit, "limit", 0, "Limit results after all filters")
	command.Flags().BoolVar(&opts.reverse, "reverse", false, "Return newest matching events first")
	command.Flags().StringVar(&opts.path, "path", "", "Audit log path")
	return command
}

func auditVerifyCmd(f *cliFlags) *cobra.Command {
	var opts auditVerifyOptions
	command := &cobra.Command{
		Use:   "verify",
		Short: "Verify audit log integrity",
		Args:  cobra.NoArgs,
		RunE: func(_ *cobra.Command, _ []string) error {
			return runAuditVerify(f, opts)
		},
	}
	command.Flags().BoolVar(&opts.strict, "strict", false, "Fail when verification reports malformed, schema, or timestamp violations")
	command.Flags().StringVar(&opts.path, "path", "", "Audit log path")
	return command
}

func runAuditQuery(f *cliFlags, opts auditQueryOptions) error {
	if err := authorizeRead(f); err != nil {
		return err
	}
	path, err := auditPath(opts.path)
	if err != nil {
		emitAudit(f, auditCommandEvent(f, srvgovaudit.EventTypeAuditQuery), err)
		return err
	}
	filter, err := auditRawFilter(opts)
	if err != nil {
		emitAudit(f, auditCommandEvent(f, srvgovaudit.EventTypeAuditQuery), err)
		return err
	}
	raw, err := coreaudit.QueryRaw(path, filter)
	if err != nil {
		emitAudit(f, auditCommandEvent(f, srvgovaudit.EventTypeAuditQuery), err)
		return err
	}
	result := auditQueryResult{Events: []srvgovaudit.Event{}, Malformed: raw.MalformedEntries}
	for _, record := range raw.Records {
		var event srvgovaudit.Event
		if err := json.Unmarshal([]byte(record.Line), &event); err != nil {
			result.Malformed++
			continue
		}
		event = srvgovaudit.Sanitize(event)
		if !matchesSrvGovAuditFilter(event, opts) {
			continue
		}
		result.Events = append(result.Events, event)
	}
	if opts.reverse {
		reverseAuditEvents(result.Events)
	}
	if opts.limit > 0 && len(result.Events) > opts.limit {
		result.Events = result.Events[:opts.limit]
	}
	emitAudit(f, auditCommandEvent(f, srvgovaudit.EventTypeAuditQuery), nil)
	return printAuditQuery(f, result)
}

func runAuditVerify(f *cliFlags, opts auditVerifyOptions) error {
	if err := authorizeRead(f); err != nil {
		return err
	}
	path, err := auditPath(opts.path)
	if err != nil {
		emitAudit(f, auditCommandEvent(f, srvgovaudit.EventTypeAuditVerify), err)
		return err
	}
	result, err := coreaudit.Verify(path, coreaudit.VerifyOptions{})
	strictErr := strictVerifyError(result, opts.strict)
	event := auditCommandEvent(f, srvgovaudit.EventTypeAuditVerify)
	if err != nil {
		emitAudit(f, event, err)
		return err
	}
	emitAudit(f, event, strictErr)
	if printErr := printAuditVerify(f, result); printErr != nil {
		return printErr
	}
	return strictErr
}

func auditPath(path string) (string, error) {
	if path != "" {
		return path, nil
	}
	return coreaudit.DefaultPath()
}

func auditRawFilter(opts auditQueryOptions) (coreaudit.Filter, error) {
	now := time.Now().UTC()
	filter := coreaudit.Filter{
		EventType:   opts.event,
		Operator:    opts.operator,
		ContextName: opts.context,
		Status:      opts.status,
	}
	if opts.since != "" {
		since, err := coreaudit.ParseTime(opts.since, now)
		if err != nil {
			return filter, err
		}
		filter.Since = &since
	}
	if opts.until != "" {
		until, err := coreaudit.ParseTime(opts.until, now)
		if err != nil {
			return filter, err
		}
		filter.Until = &until
	}
	return filter, nil
}

func matchesSrvGovAuditFilter(event srvgovaudit.Event, opts auditQueryOptions) bool {
	if opts.status != "" && event.Status != opts.status {
		return false
	}
	if opts.context != "" && event.Context.Name != opts.context {
		return false
	}
	return true
}

func reverseAuditEvents(events []srvgovaudit.Event) {
	for i, j := 0, len(events)-1; i < j; i, j = i+1, j-1 {
		events[i], events[j] = events[j], events[i]
	}
}

func strictVerifyError(result coreaudit.VerifyResult, strict bool) error {
	if !strict {
		return nil
	}
	if result.Malformed > 0 || result.SchemaErrors > 0 || result.TimestampOrderViolations > 0 {
		return apperrors.New(apperrors.CodeValidationFailed, "audit verification failed", nil)
	}
	return nil
}

func auditCommandEvent(f *cliFlags, eventType srvgovaudit.EventType) srvgovaudit.Event {
	return srvgovaudit.Event{
		EventType: eventType,
		Operator:  resolveOperator(f.Operator),
		Target:    srvgovaudit.Target{Host: string(eventType)},
		Command:   string(eventType),
		RiskTier:  "R0",
		Status:    srvgovaudit.StatusSucceeded,
	}
}

func printAuditQuery(f *cliFlags, result auditQueryResult) error {
	if result.Events == nil {
		result.Events = []srvgovaudit.Event{}
	}
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("AuditQueryResult", result)
	}
	rows := make([][]string, 0, len(result.Events))
	for _, event := range result.Events {
		rows = append(rows, []string{
			event.Timestamp.UTC().Format(time.RFC3339),
			string(event.EventType),
			event.Operator,
			event.Context.Name,
			event.Target.Host,
			event.RiskTier,
			event.Status,
			fmt.Sprintf("%d", event.ExitCode),
			event.Command,
		})
	}
	p.Table(
		[]string{"TIMESTAMP", "TYPE", "OPERATOR", "CONTEXT", "TARGET", "RISK", "STATUS", "EXIT", "COMMAND"},
		rows,
	)
	if result.Malformed > 0 {
		_, _ = fmt.Fprintf(p.Out, "\nMalformed entries skipped: %d\n", result.Malformed)
	}
	return nil
}

func printAuditVerify(f *cliFlags, result coreaudit.VerifyResult) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("AuditVerifyResult", result)
	}
	p.Table([]string{"TOTAL", "VALID", "MALFORMED", "SCHEMA_ERRORS", "TIMESTAMP_ORDER_VIOLATIONS"}, [][]string{{
		fmt.Sprint(result.Total),
		fmt.Sprint(result.Valid),
		fmt.Sprint(result.Malformed),
		fmt.Sprint(result.SchemaErrors),
		fmt.Sprint(result.TimestampOrderViolations),
	}})
	return nil
}

func authorizeRead(f *cliFlags) error {
	return safety.Authorize(safety.R0, safety.Options{
		NonInteractive: f.NonInteractive,
		Operator:       resolveOperator(f.Operator),
	})
}

func emitAudit(f *cliFlags, event srvgovaudit.Event, eventErr error) {
	path, err := coreaudit.DefaultPath()
	if err != nil {
		warnAuditFailure(f, err)
		return
	}
	if eventErr != nil {
		appErr := apperrors.AsAppError(eventErr)
		event.Status = srvgovaudit.StatusFailed
		event.Error = &srvgovaudit.ErrorInfo{Code: string(appErr.Code), Message: appErr.Message}
	}
	if err := srvgovaudit.Append(path, event, coreaudit.Options{}); err != nil {
		warnAuditFailure(f, err)
	}
}
