package cmd

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
	"github.com/JiangHe12/opskit-core/v2/redact"

	"github.com/JiangHe12/srvgov-cli/internal/fanout"
	"github.com/JiangHe12/srvgov-cli/internal/observe"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovaudit"
	"github.com/JiangHe12/srvgov-cli/internal/srvgovctx"
	"github.com/JiangHe12/srvgov-cli/internal/sshexec"
)

const (
	defaultDockerLogTail = 100
	maxDockerLogTail     = 10000
)

var dockerActions = map[string]bool{
	"start":   true,
	"stop":    true,
	"restart": true,
	"rm":      true,
}

type dockerListItem struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Image     string `json:"image"`
	State     string `json:"state"`
	Status    string `json:"status"`
	Ports     string `json:"ports"`
	CreatedAt string `json:"createdAt"`
}

type dockerPort struct {
	ContainerPort string `json:"containerPort"`
	HostIP        string `json:"hostIP"`
	HostPort      string `json:"hostPort"`
}

type dockerMount struct {
	Type        string `json:"type"`
	Source      string `json:"source"`
	Destination string `json:"destination"`
	Mode        string `json:"mode"`
	RW          bool   `json:"rw"`
}

type dockerInspectView struct {
	ID            string        `json:"id"`
	Name          string        `json:"name"`
	Image         string        `json:"image"`
	State         string        `json:"state"`
	Status        string        `json:"status"`
	RestartPolicy string        `json:"restartPolicy"`
	Ports         []dockerPort  `json:"ports"`
	Mounts        []dockerMount `json:"mounts"`
	CreatedAt     string        `json:"createdAt"`
}

type dockerLogsView struct {
	Lines []observe.LogLine `json:"lines"`
	Meta  dockerLogsMeta    `json:"meta"`
}

type dockerLogsMeta struct {
	Backend        string `json:"backend"`
	Container      string `json:"container"`
	RequestedLines int    `json:"requestedLines"`
	ReturnedLines  int    `json:"returnedLines"`
}

type dockerActionView struct {
	Container string `json:"container"`
	Action    string `json:"action"`
	Success   bool   `json:"success"`
	ExitCode  int    `json:"exitCode"`
}

type dockerInspectRaw struct {
	ID            string                         `json:"id"`
	Name          string                         `json:"name"`
	Image         string                         `json:"image"`
	State         string                         `json:"state"`
	Status        string                         `json:"status"`
	RestartPolicy string                         `json:"restartPolicy"`
	Ports         map[string][]dockerPortBinding `json:"ports"`
	Mounts        []dockerInspectRawMount        `json:"mounts"`
	CreatedAt     string                         `json:"createdAt"`
}

type dockerPortBinding struct {
	HostIP   string `json:"HostIp"`
	HostPort string `json:"HostPort"`
}

type dockerInspectRawMount struct {
	Type        string `json:"Type"`
	Source      string `json:"Source"`
	Destination string `json:"Destination"`
	Mode        string `json:"Mode"`
	RW          bool   `json:"RW"`
}

func newDockerCmd(f *cliFlags) *cobra.Command {
	var (
		tail   int
		reason string
		allow  bool
		dryRun bool
		flags  fanoutFlags
	)
	command := &cobra.Command{
		Use:   "docker <ps|list|inspect|logs|start|stop|restart|rm> [container]",
		Short: "Inspect or control one Docker container",
		Args: func(_ *cobra.Command, args []string) error {
			if len(args) < 1 || len(args) > 2 {
				return apperrors.New(apperrors.CodeUsageError, "docker requires an action and optional container", nil)
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			action := strings.ToLower(args[0])
			if action == "ps" || action == "list" {
				if len(args) != 1 {
					return apperrors.New(apperrors.CodeUsageError, "docker ps/list does not accept a container", nil)
				}
				if fanoutRequested(cmd) {
					return runDockerFanout(cmd, f, flags, "list", "", tail, "", false, dryRun)
				}
				if dryRun {
					return runDockerDryRun(f, dockerListCommand())
				}
				return runDockerList(cmd, f)
			}
			if len(args) != 2 {
				return apperrors.New(apperrors.CodeUsageError, "docker action requires one container", nil)
			}
			switch action {
			case "inspect":
				if fanoutRequested(cmd) {
					return runDockerFanout(cmd, f, flags, action, args[1], tail, "", false, dryRun)
				}
				if dryRun {
					return runDockerDryRun(f, dockerInspectCommand(args[1]))
				}
				return runDockerInspect(cmd, f, args[1])
			case "logs":
				if tail < 1 || tail > maxDockerLogTail {
					return apperrors.New(apperrors.CodeUsageError, "--tail must be between 1 and 10000", nil)
				}
				if fanoutRequested(cmd) {
					return runDockerFanout(cmd, f, flags, action, args[1], tail, "", false, dryRun)
				}
				if dryRun {
					return runDockerDryRun(f, dockerLogsCommand(args[1], tail))
				}
				return runDockerLogs(cmd, f, args[1], tail)
			default:
				if !dockerActions[action] {
					return apperrors.New(apperrors.CodeUsageError, fmt.Sprintf("unsupported docker action %q", args[0]), nil)
				}
				if fanoutRequested(cmd) {
					return runDockerFanout(cmd, f, flags, action, args[1], tail, reason, allow, dryRun)
				}
				if dryRun {
					return runDockerDryRun(f, dockerActionCommand(action, args[1]))
				}
				return runDockerAction(cmd, f, action, args[1], reason, allow)
			}
		},
	}
	command.Flags().IntVar(&tail, "tail", defaultDockerLogTail, "Maximum Docker log lines")
	command.Flags().StringVar(&reason, "reason", "", "Human reason for a governed container change")
	command.Flags().BoolVar(&allow, "allow-destructive", false, "Explicitly allow an authorized R3 container change")
	command.Flags().BoolVar(&dryRun, "dry-run", false, "Classify and show required authorization without connecting")
	bindFanoutFlags(command, &flags)
	return command
}

func runDockerDryRun(f *cliFlags, command string) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	risk := classifyGovernedCommand(*item, contextName, command)
	return printExecDryRun(f, contextName, *item, command, risk.Base, risk.Effective)
}

func runDockerFanout(
	cmd *cobra.Command,
	f *cliFlags,
	flags fanoutFlags,
	action, container string,
	tail int,
	reason string,
	allow, dryRun bool,
) error {
	if action == "logs" && (tail < 1 || tail > maxDockerLogTail) {
		return apperrors.New(apperrors.CodeUsageError, "--tail must be between 1 and 10000", nil)
	}
	targets, err := loadFanoutTargetsForCommand(cmd, flags)
	if err != nil {
		return err
	}
	command, eventType := dockerGovernedCommand(action, container, tail)
	plans, maxEffective := planGovernedFanout(targets, command)
	if dryRun {
		return printFanoutDryRun(cmd, f, targets, flags.Concurrency, plans, command, maxEffective)
	}
	if err := authorizeGovernedFanout(cmd, f, plans, command, reason, allow, maxEffective); err != nil {
		return err
	}
	var batchAudit *mutationAuditHandle
	if eventType == srvgovaudit.EventTypeDockerAction {
		batchAudit, err = beginFanoutMutationAudit(
			f,
			targets,
			string(eventType),
			command,
			reason,
			maxEffective,
		)
		if err != nil {
			return err
		}
	}
	results := fanout.Run(cmd.Context(), targets, flags.Concurrency, func(_ context.Context, target fanout.Target[srvgovctx.Context]) (any, error) {
		targetFlags := *f
		targetFlags.NonInteractive = true
		return runDockerTarget(cmd, &targetFlags, target.Value, target.Name, action, container, tail, reason, allow, command, eventType)
	})
	if err := finishFanoutMutationAudit(batchAudit, results); err != nil {
		return err
	}
	return printFanout(cmd, f, buildFanoutView(targets, flags.Concurrency, results))
}

func dockerGovernedCommand(action, container string, tail int) (string, srvgovaudit.EventType) {
	switch action {
	case "list":
		return dockerListCommand(), srvgovaudit.EventTypeDockerList
	case "inspect":
		return dockerInspectCommand(container), srvgovaudit.EventTypeDockerInspect
	case "logs":
		return dockerLogsCommand(container, tail), srvgovaudit.EventTypeDockerLogs
	default:
		return dockerActionCommand(action, container), srvgovaudit.EventTypeDockerAction
	}
}

func runDockerTarget(
	cmd *cobra.Command,
	f *cliFlags,
	item srvgovctx.Context,
	contextName, action, container string,
	tail int,
	reason string,
	allow bool,
	command string,
	eventType srvgovaudit.EventType,
) (any, error) {
	result, _, runErr := runGovernedCommand(cmd, f, item, contextName, command, reason, allow, eventType)
	if commandUnavailable(result) {
		return nil, apperrors.New(apperrors.CodeResourceNotFound, "docker is not available", nil)
	}
	if action == "list" {
		if runErr != nil {
			return nil, runErr
		}
		return parseDockerList(result.Stdout)
	}
	if action == "inspect" {
		if runErr != nil {
			return nil, runErr
		}
		return parseDockerInspect(result.Stdout)
	}
	if action == "logs" {
		if runErr != nil {
			return nil, runErr
		}
		lines := observe.ParseDockerLines(result.Stdout, result.Stderr)
		return dockerLogsView{
			Lines: lines,
			Meta: dockerLogsMeta{
				Backend:        "docker",
				Container:      redact.String(container),
				RequestedLines: tail,
				ReturnedLines:  len(lines),
			},
		}, nil
	}
	if runErr != nil && result.ExitCode == 0 {
		return nil, runErr
	}
	return dockerActionView{
		Container: redact.String(container),
		Action:    action,
		Success:   runErr == nil,
		ExitCode:  result.ExitCode,
	}, runErr
}

func runDockerList(cmd *cobra.Command, f *cliFlags) error {
	result, err := runDockerRead(cmd, f, dockerListCommand(), srvgovaudit.EventTypeDockerList)
	if err != nil {
		return err
	}
	items, err := parseDockerList(result.Stdout)
	if err != nil {
		return err
	}
	return printDockerList(f, items)
}

func runDockerInspect(cmd *cobra.Command, f *cliFlags, container string) error {
	result, err := runDockerRead(cmd, f, dockerInspectCommand(container), srvgovaudit.EventTypeDockerInspect)
	if err != nil {
		return err
	}
	value, err := parseDockerInspect(result.Stdout)
	if err != nil {
		return err
	}
	return printDockerInspect(f, value)
}

func runDockerLogs(cmd *cobra.Command, f *cliFlags, container string, tail int) error {
	if tail < 1 || tail > maxDockerLogTail {
		return apperrors.New(apperrors.CodeUsageError, "--tail must be between 1 and 10000", nil)
	}
	result, err := runDockerRead(cmd, f, dockerLogsCommand(container, tail), srvgovaudit.EventTypeDockerLogs)
	if err != nil {
		return err
	}
	lines := observe.ParseDockerLines(result.Stdout, result.Stderr)
	return printDockerLogs(f, dockerLogsView{
		Lines: lines,
		Meta: dockerLogsMeta{
			Backend:        "docker",
			Container:      redact.String(container),
			RequestedLines: tail,
			ReturnedLines:  len(lines),
		},
	})
}

func runDockerAction(cmd *cobra.Command, f *cliFlags, action, container, reason string, allow bool) error {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return err
	}
	command := dockerActionCommand(action, container)
	result, _, runErr := runGovernedCommand(cmd, f, *item, contextName, command, reason, allow, srvgovaudit.EventTypeDockerAction)
	if commandUnavailable(result) {
		return apperrors.New(apperrors.CodeResourceNotFound, "docker is not available", nil)
	}
	if runErr != nil && result.ExitCode == 0 {
		return runErr
	}
	view := dockerActionView{
		Container: redact.String(container),
		Action:    action,
		Success:   runErr == nil,
		ExitCode:  result.ExitCode,
	}
	if err := printDockerAction(f, view); err != nil {
		return err
	}
	return runErr
}

func runDockerRead(
	cmd *cobra.Command,
	f *cliFlags,
	command string,
	eventType srvgovaudit.EventType,
) (sshexec.Result, error) {
	item, contextName, err := loadSelectedContext(f.Context)
	if err != nil {
		return sshexec.Result{}, err
	}
	result, _, runErr := runGovernedCommand(cmd, f, *item, contextName, command, "", false, eventType)
	if commandUnavailable(result) {
		return sshexec.Result{}, apperrors.New(apperrors.CodeResourceNotFound, "docker is not available", nil)
	}
	return result, runErr
}

func dockerListCommand() string {
	return "docker ps --no-trunc --format '{{json .}}'"
}

func dockerInspectCommand(container string) string {
	const projection = `{"id":{{json .Id}},"name":{{json .Name}},"image":{{json .Config.Image}},` +
		`"state":{{json .State.Status}},"status":{{json .State.Status}},` +
		`"restartPolicy":{{json .HostConfig.RestartPolicy.Name}},` +
		`"ports":{{json .NetworkSettings.Ports}},"mounts":{{json .Mounts}},` +
		`"createdAt":{{json .Created}}}`
	return "docker inspect --format '" + projection + "' -- " + observe.ShellQuote(container)
}

func dockerLogsCommand(container string, tail int) string {
	return fmt.Sprintf("docker logs --timestamps --tail %d -- %s", tail, observe.ShellQuote(container))
}

func dockerActionCommand(action, container string) string {
	return "docker " + action + " " + observe.ShellQuote(container)
}

func parseDockerList(output string) ([]dockerListItem, error) {
	items := make([]dockerListItem, 0)
	scanner := bufio.NewScanner(strings.NewReader(output))
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var raw struct {
			ID        string `json:"ID"`
			Name      string `json:"Names"`
			Image     string `json:"Image"`
			State     string `json:"State"`
			Status    string `json:"Status"`
			Ports     string `json:"Ports"`
			CreatedAt string `json:"CreatedAt"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &raw); err != nil {
			return nil, apperrors.New(apperrors.CodeValidationFailed, "unable to parse docker ps output", err)
		}
		items = append(items, dockerListItem{
			ID:        redact.String(raw.ID),
			Name:      redact.String(raw.Name),
			Image:     redact.String(raw.Image),
			State:     redact.String(raw.State),
			Status:    redact.String(raw.Status),
			Ports:     redact.String(raw.Ports),
			CreatedAt: redact.String(raw.CreatedAt),
		})
	}
	return items, nil
}

func parseDockerInspect(output string) (dockerInspectView, error) {
	var raw dockerInspectRaw
	if err := json.Unmarshal([]byte(output), &raw); err != nil {
		return dockerInspectView{}, apperrors.New(apperrors.CodeValidationFailed, "unable to parse docker inspect output", err)
	}
	ports := make([]dockerPort, 0)
	for containerPort, bindings := range raw.Ports {
		if len(bindings) == 0 {
			ports = append(ports, dockerPort{ContainerPort: redact.String(containerPort)})
			continue
		}
		for _, binding := range bindings {
			ports = append(ports, dockerPort{
				ContainerPort: redact.String(containerPort),
				HostIP:        redact.String(binding.HostIP),
				HostPort:      redact.String(binding.HostPort),
			})
		}
	}
	sort.Slice(ports, func(i, j int) bool {
		return ports[i].ContainerPort+ports[i].HostIP+ports[i].HostPort <
			ports[j].ContainerPort+ports[j].HostIP+ports[j].HostPort
	})
	mounts := make([]dockerMount, 0, len(raw.Mounts))
	for _, mount := range raw.Mounts {
		mounts = append(mounts, dockerMount{
			Type:        redact.String(mount.Type),
			Source:      redact.String(mount.Source),
			Destination: redact.String(mount.Destination),
			Mode:        redact.String(mount.Mode),
			RW:          mount.RW,
		})
	}
	return dockerInspectView{
		ID:            redact.String(raw.ID),
		Name:          redact.String(strings.TrimPrefix(raw.Name, "/")),
		Image:         redact.String(raw.Image),
		State:         redact.String(raw.State),
		Status:        redact.String(raw.Status),
		RestartPolicy: redact.String(raw.RestartPolicy),
		Ports:         ports,
		Mounts:        mounts,
		CreatedAt:     redact.String(raw.CreatedAt),
	}, nil
}

func printDockerList(f *cliFlags, items []dockerListItem) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONList("DockerList", items, len(items), 1, len(items), false)
	}
	rows := make([][]string, 0, len(items))
	for _, item := range items {
		rows = append(rows, []string{item.ID, item.Name, item.Image, item.State, item.Status, item.Ports, item.CreatedAt})
	}
	return p.Table([]string{"ID", "NAME", "IMAGE", "STATE", "STATUS", "PORTS", "CREATED_AT"}, rows)
}

func printDockerInspect(f *cliFlags, value dockerInspectView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("DockerInspect", value)
	}
	return p.KV([][2]string{
		{"ID", value.ID},
		{"Name", value.Name},
		{"Image", value.Image},
		{"State", value.State},
		{"Status", value.Status},
		{"Restart Policy", value.RestartPolicy},
		{"Ports", strconv.Itoa(len(value.Ports))},
		{"Mounts", strconv.Itoa(len(value.Mounts))},
		{"Created At", value.CreatedAt},
	})
}

func printDockerLogs(f *cliFlags, value dockerLogsView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("DockerLogs", value)
	}
	if err := p.KV([][2]string{
		{"Backend", value.Meta.Backend},
		{"Container", value.Meta.Container},
		{"Requested Lines", strconv.Itoa(value.Meta.RequestedLines)},
		{"Returned Lines", strconv.Itoa(value.Meta.ReturnedLines)},
	}); err != nil {
		return err
	}
	rows := make([][]string, 0, len(value.Lines))
	for _, line := range value.Lines {
		rows = append(rows, []string{line.Timestamp, line.Hostname, line.Unit, line.Priority, line.Message})
	}
	return p.Table([]string{"TIMESTAMP", "HOSTNAME", "UNIT", "PRIORITY", "MESSAGE"}, rows)
}

func printDockerAction(f *cliFlags, value dockerActionView) error {
	p := newPrinter(f)
	if f.Output == "json" {
		return p.JSONData("DockerAction", value)
	}
	return p.KV([][2]string{
		{"Container", value.Container},
		{"Action", value.Action},
		{"Success", strconv.FormatBool(value.Success)},
		{"Exit Code", strconv.Itoa(value.ExitCode)},
	})
}
