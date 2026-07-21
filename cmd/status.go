package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
)

func newStatusCmd(f *cliFlags) *cobra.Command {
	flags := fanoutFlags{Concurrency: defaultFanoutConcurrency}
	command := &cobra.Command{
		Use:   "status",
		Short: "Show structured read-only server status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd, f, flags)
		},
	}
	bindFanoutFlags(command, &flags)
	return command
}

func runStatus(cmd *cobra.Command, f *cliFlags, flags fanoutFlags) error {
	return runReadOnlyObservation(cmd, f, flags, observe.StatusProbes(), runStatusForTarget, printStatus)
}

func runStatusForTarget(cmd *cobra.Command, f *cliFlags, item srvgovctx.Context, contextName string) (observe.Status, error) {
	values := make(map[string]string)
	successes := 0
	for _, probe := range observe.StatusProbes() {
		result, _, runErr := runGovernedCommand(cmd, f, item, contextName, probe.Command, "", false, srvgovaudit.EventTypeStatusObserve)
		if runErr == nil {
			values[probe.Name] = result.Stdout
			successes++
			continue
		}
		if result.ExitCode != 0 {
			continue
		}
		return observe.Status{}, runErr
	}
	if successes == 0 {
		return observe.Status{}, apperrors.New(apperrors.CodeResourceNotFound, "no supported server status source is available", nil)
	}
	return observe.ParseStatus(values), nil
}

func printStatus(f *cliFlags, value observe.Status) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ServerStatus", value)
	}
	if err := p.KV([][2]string{
		{"Hostname", value.Hostname},
		{"Uptime Seconds", strconv.FormatFloat(value.Uptime, 'f', -1, 64)},
		{"Load 1/5/15", fmt.Sprintf("%g / %g / %g", value.Load.One, value.Load.Five, value.Load.Fifteen)},
		{"CPU", value.CPU.Model},
		{"CPU Cores", strconv.Itoa(value.CPU.Cores)},
		{"Memory Total", strconv.FormatInt(value.Mem.Total, 10)},
		{"Memory Used", strconv.FormatInt(value.Mem.Used, 10)},
		{"Memory Free", strconv.FormatInt(value.Mem.Free, 10)},
		{"Kernel", value.Kernel},
	}); err != nil {
		return err
	}
	rows := make([][]string, 0, len(value.Disk))
	for _, disk := range value.Disk {
		rows = append(rows, []string{
			disk.Mount,
			strconv.FormatInt(disk.Size, 10),
			strconv.FormatInt(disk.Used, 10),
			strconv.FormatInt(disk.Avail, 10),
			strconv.Itoa(disk.UsePct),
		})
	}
	return p.Table([]string{"MOUNT", "SIZE", "USED", "AVAIL", "USE_PCT"}, rows)
}
