package cmd

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"
	"github.com/JiangHe12/opskit-core/redact"
	"github.com/JiangHe12/opskit-core/safety"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

const defaultFanoutConcurrency = 5

type fanoutSummary struct {
	Total     int `json:"total"`
	Succeeded int `json:"succeeded"`
	Failed    int `json:"failed"`
}

type fanoutErrorView struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type fanoutResultView struct {
	Target string           `json:"target"`
	Host   string           `json:"host"`
	OK     bool             `json:"ok"`
	Data   any              `json:"data,omitempty"`
	Error  *fanoutErrorView `json:"error,omitempty"`
}

type fanoutView struct {
	Targets              []string           `json:"targets"`
	Concurrency          int                `json:"concurrency"`
	MaxEffectiveRiskTier string             `json:"maxEffectiveRiskTier,omitempty"`
	Summary              fanoutSummary      `json:"summary"`
	Results              []fanoutResultView `json:"results"`
}

type fanoutFlags struct {
	Targets     string
	Selector    string
	Concurrency int
}

func bindFanoutFlags(command *cobra.Command, flags *fanoutFlags) {
	command.Flags().StringVar(&flags.Targets, "targets", "", "Comma-separated server context names")
	command.Flags().StringVar(&flags.Selector, "selector", "", "Label selector key=value,key2=value2")
	command.Flags().IntVar(&flags.Concurrency, "concurrency", defaultFanoutConcurrency, "Maximum concurrent targets")
}

func fanoutDryRunResults(plans []governedFanoutPlan, command string) []fanout.Result {
	results := make([]fanout.Result, 0, len(plans))
	for _, plan := range plans {
		results = append(results, fanout.Result{
			Target: plan.Target.Name,
			Host:   plan.Target.Host,
			Data: execDryRunView{
				Context:               plan.Target.Name,
				Host:                  plan.Target.Host,
				Command:               redact.String(command),
				RiskTier:              riskName(plan.Risk.Base),
				EffectiveRiskTier:     riskName(plan.Risk.Effective),
				RequiredAuthorization: requiredAuthorization(plan.Risk.Effective),
				DryRun:                true,
			},
		})
	}
	return results
}

func printFanoutDryRun(
	cmd *cobra.Command,
	f *cliFlags,
	targets []fanout.Target[srvgovctx.Context],
	concurrency int,
	plans []governedFanoutPlan,
	command string,
	maxEffective safety.Risk,
) error {
	view := buildFanoutView(targets, concurrency, fanoutDryRunResults(plans, command))
	view.MaxEffectiveRiskTier = riskName(maxEffective)
	return printFanout(cmd, f, view)
}

func runReadOnlyObservation[T any](
	cmd *cobra.Command,
	f *cliFlags,
	flags fanoutFlags,
	probes []observe.Probe,
	runTarget func(*cobra.Command, *cliFlags, srvgovctx.Context, string) (T, error),
	printSingle func(*cliFlags, T) error,
) error {
	if fanoutRequested(cmd) {
		targets, err := loadFanoutTargetsForCommand(cmd, flags)
		if err != nil {
			return err
		}
		commands := make([]string, 0, len(probes))
		for _, probe := range probes {
			commands = append(commands, probe.Command)
		}
		if err := requireFanoutR0(targets, commands); err != nil {
			return err
		}
		results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
			return runTarget(cmd, f, target.Value, target.Name)
		})
		return printFanout(cmd, f, buildFanoutView(targets, flags.Concurrency, results))
	}

	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	value, err := runTarget(cmd, f, *item, contextName)
	if err != nil {
		return err
	}
	return printSingle(f, value)
}

func fanoutRequested(cmd *cobra.Command) bool {
	return cmd.Flags().Changed("targets") || cmd.Flags().Changed("selector")
}

func loadFanoutTargetsForCommand(cmd *cobra.Command, flags fanoutFlags) ([]fanout.Target[srvgovctx.Context], error) {
	return loadFanoutTargets(flags, cmd.Flags().Changed("context"), cmd.Flags().Changed("targets"), cmd.Flags().Changed("selector"))
}

func loadFanoutTargets(flags fanoutFlags, selectedContextSet, targetsSet, selectorSet bool) ([]fanout.Target[srvgovctx.Context], error) {
	if selectedContextSet && (targetsSet || selectorSet) {
		return nil, apperrors.New(apperrors.CodeUsageError, "--targets, --selector, and --context are mutually exclusive", nil)
	}
	if targetsSet && selectorSet {
		return nil, apperrors.New(apperrors.CodeUsageError, "--targets and --selector are mutually exclusive", nil)
	}
	if flags.Concurrency < 1 {
		return nil, apperrors.New(apperrors.CodeUsageError, "--concurrency must be at least 1", nil)
	}
	cfg, err := srvgovctx.Load()
	if err != nil {
		return nil, err
	}
	names, err := fanoutTargetNames(cfg, flags, selectorSet)
	if err != nil {
		return nil, err
	}
	sortedNames := make([]string, 0, len(names))
	for name := range names {
		sortedNames = append(sortedNames, name)
	}
	sort.Strings(sortedNames)

	targets := make([]fanout.Target[srvgovctx.Context], 0, len(sortedNames))
	for _, name := range sortedNames {
		item, ok := cfg.Contexts[name]
		if !ok {
			return nil, apperrors.New(
				apperrors.CodeResourceNotFound,
				fmt.Sprintf("context %q not found", redact.String(name)),
				nil,
			)
		}
		if err := item.Normalize(); err != nil {
			return nil, err
		}
		targets = append(targets, fanout.Target[srvgovctx.Context]{
			Name:  name,
			Host:  item.Address(),
			Value: item,
		})
	}
	return targets, nil
}

func fanoutTargetNames(cfg *srvgovctx.Config, flags fanoutFlags, selectorSet bool) (map[string]struct{}, error) {
	if selectorSet {
		selector, err := parseSelector(flags.Selector)
		if err != nil {
			return nil, err
		}
		names := make(map[string]struct{})
		for name, item := range cfg.Contexts {
			if labelsMatch(item.Labels, selector) {
				names[name] = struct{}{}
			}
		}
		if len(names) == 0 {
			return nil, apperrors.New(apperrors.CodeResourceNotFound, "no contexts match selector", nil)
		}
		return names, nil
	}

	names := make(map[string]struct{})
	for _, value := range strings.Split(flags.Targets, ",") {
		if name := strings.TrimSpace(value); name != "" {
			names[name] = struct{}{}
		}
	}
	if len(names) == 0 {
		return nil, apperrors.New(apperrors.CodeUsageError, "--targets requires at least one target", nil)
	}
	return names, nil
}

func parseSelector(raw string) (map[string]string, error) {
	selector := make(map[string]string)
	for _, part := range strings.Split(raw, ",") {
		key, value, ok := strings.Cut(part, "=")
		key = strings.TrimSpace(key)
		value = strings.TrimSpace(value)
		if !ok || key == "" || value == "" {
			return nil, apperrors.New(apperrors.CodeUsageError, "--selector must be key=value pairs with non-empty keys and values", nil)
		}
		selector[key] = value
	}
	if len(selector) == 0 {
		return nil, apperrors.New(apperrors.CodeUsageError, "--selector must be key=value pairs with non-empty keys and values", nil)
	}
	return selector, nil
}

func labelsMatch(labels map[string]string, selector map[string]string) bool {
	for key, value := range selector {
		if labels[key] != value {
			return false
		}
	}
	return true
}

func requireFanoutR0(targets []fanout.Target[srvgovctx.Context], commands []string) error {
	for _, target := range targets {
		for _, command := range commands {
			risk := classifyGovernedCommand(target.Value, target.Name, command)
			if risk.Effective > safety.R0 {
				return apperrors.New(
					apperrors.CodeUsageError,
					fmt.Sprintf(
						"target %q has effective risk %s; fanout only allows R0 commands",
						redact.String(target.Name),
						riskName(risk.Effective),
					),
					nil,
				)
			}
		}
	}
	return nil
}

func buildFanoutView(targets []fanout.Target[srvgovctx.Context], concurrency int, results []fanout.Result) fanoutView {
	view := fanoutView{
		Targets:     make([]string, 0, len(targets)),
		Concurrency: concurrency,
		Summary:     fanoutSummary{Total: len(results)},
		Results:     make([]fanoutResultView, 0, len(results)),
	}
	for _, target := range targets {
		view.Targets = append(view.Targets, redact.String(target.Name))
	}
	for _, result := range results {
		item := fanoutResultView{
			Target: redact.String(result.Target),
			Host:   redact.String(result.Host),
			OK:     result.Err == nil,
			Data:   result.Data,
		}
		if result.Err == nil {
			view.Summary.Succeeded++
		} else {
			appErr := apperrors.AsAppError(result.Err)
			item.Data = nil
			item.Error = &fanoutErrorView{
				Code:    string(appErr.Code),
				Message: redact.String(appErr.Message),
			}
			view.Summary.Failed++
		}
		view.Results = append(view.Results, item)
	}
	return view
}

func printFanout(_ *cobra.Command, f *cliFlags, view fanoutView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		if err := p.JSONData("FanoutResult", view); err != nil {
			return err
		}
	} else {
		p.KV([][2]string{
			{"Targets", strings.Join(view.Targets, ", ")},
			{"Concurrency", fmt.Sprintf("%d", view.Concurrency)},
			{"Succeeded", fmt.Sprintf("%d", view.Summary.Succeeded)},
			{"Failed", fmt.Sprintf("%d", view.Summary.Failed)},
		})
		rows := make([][]string, 0, len(view.Results))
		for _, result := range view.Results {
			errorMessage := ""
			if result.Error != nil {
				errorMessage = result.Error.Message
			}
			rows = append(rows, []string{
				result.Target,
				result.Host,
				fmt.Sprintf("%t", result.OK),
				errorMessage,
			})
		}
		p.Table([]string{"TARGET", "HOST", "OK", "ERROR"}, rows)
	}
	if view.Summary.Failed > 0 {
		return apperrors.New(apperrors.CodeBackendError, "one or more fanout targets failed", nil)
	}
	return nil
}
