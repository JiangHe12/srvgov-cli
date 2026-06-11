package cmd

import (
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
)

func newPortsCmd(f *cliFlags) *cobra.Command {
	return &cobra.Command{
		Use:   "ports",
		Short: "Show structured listening ports",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return runPorts(cmd, f)
		},
	}
}

func runPorts(cmd *cobra.Command, f *cliFlags) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	probes := observe.PortProbes()
	for index, probe := range probes {
		result, _, runErr := runGovernedCommand(cmd, f, *item, contextName, probe.Command, "", false, srvgovaudit.EventTypePortsObserve)
		if runErr != nil {
			if commandUnavailable(result) {
				continue
			}
			return runErr
		}
		ports, parseErr := observe.ParsePorts(probe.Name, result.Stdout)
		if parseErr != nil {
			return parseErr
		}
		if len(ports) == 0 && strings.TrimSpace(result.Stdout) != "" {
			if index+1 < len(probes) {
				continue
			}
			return apperrors.New(apperrors.CodeValidationFailed, "unable to parse ss or netstat output", nil)
		}
		return printPorts(f, ports)
	}
	return apperrors.New(apperrors.CodeResourceNotFound, "neither ss nor netstat is available", nil)
}

func printPorts(f *cliFlags, ports []observe.Port) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONList("Ports", ports, len(ports), 1, len(ports), false)
	}
	rows := make([][]string, 0, len(ports))
	for _, port := range ports {
		pid := ""
		if port.PID != 0 {
			pid = strconv.Itoa(port.PID)
		}
		rows = append(rows, []string{
			port.Proto,
			port.LocalAddr,
			strconv.Itoa(port.LocalPort),
			port.State,
			pid,
			port.Process,
		})
	}
	p.Table([]string{"PROTO", "LOCAL_ADDR", "LOCAL_PORT", "STATE", "PID", "PROCESS"}, rows)
	return nil
}
