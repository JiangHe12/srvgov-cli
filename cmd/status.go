package cmd

import (
	"fmt"
	"strconv"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
)

func newStatusCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show structured read-only server status",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runStatus(cmd, f)
		},
	}
}

func runStatus(cmd *cobra.Command, f *cliFlags) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	values := make(map[string]string)
	successes := 0
	for _, probe := range observe.StatusProbes() {
		result, _, runErr := runGovernedCommand(cmd, f, *item, contextName, probe.Command, "", false, srvgovaudit.EventTypeStatusObserve)
		if runErr == nil {
			values[probe.Name] = result.Stdout
			successes++
			continue
		}
		if result.ExitCode != 0 {
			continue
		}
		return runErr
	}
	if successes == 0 {
		return apperrors.New(apperrors.CodeResourceNotFound, "no supported server status source is available", nil)
	}
	return printStatus(f, observe.ParseStatus(values))
}

func printStatus(f *cliFlags, value observe.Status) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("ServerStatus", value)
	}
	p.KV([][2]string{
		{"Hostname", value.Hostname},
		{"Uptime Seconds", strconv.FormatFloat(value.Uptime, 'f', -1, 64)},
		{"Load 1/5/15", fmt.Sprintf("%g / %g / %g", value.Load.One, value.Load.Five, value.Load.Fifteen)},
		{"CPU", value.CPU.Model},
		{"CPU Cores", strconv.Itoa(value.CPU.Cores)},
		{"Memory Total", strconv.FormatInt(value.Mem.Total, 10)},
		{"Memory Used", strconv.FormatInt(value.Mem.Used, 10)},
		{"Memory Free", strconv.FormatInt(value.Mem.Free, 10)},
		{"Kernel", value.Kernel},
	})
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
	p.Table([]string{"MOUNT", "SIZE", "USED", "AVAIL", "USE_PCT"}, rows)
	return nil
}
