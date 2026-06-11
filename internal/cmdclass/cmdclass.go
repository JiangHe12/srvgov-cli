// Package cmdclass classifies shell commands by governance risk.
package cmdclass

import (
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/JiangHe12/opskit-core/safety"
)

type itemKind uint8

const (
	wordItem itemKind = iota
	operatorItem
)

type item struct {
	kind itemKind
	text string
}

var readOnlyCommands = map[string]bool{
	"cat":        true,
	"date":       true,
	"df":         true,
	"du":         true,
	"echo":       true,
	"free":       true,
	"grep":       true,
	"head":       true,
	"hostname":   true,
	"id":         true,
	"journalctl": true,
	"ls":         true,
	"netstat":    true,
	"pgrep":      true,
	"printf":     true,
	"ps":         true,
	"pwd":        true,
	"stat":       true,
	"tail":       true,
	"uname":      true,
	"uptime":     true,
	"wc":         true,
	"whoami":     true,
}

var dangerousCommands = map[string]bool{
	"bash":           true,
	"busybox":        true,
	"chrt":           true,
	"command":        true,
	"dash":           true,
	"dd":             true,
	"doas":           true,
	"docker-compose": true,
	"expect":         true,
	"fdisk":          true,
	"firewall-cmd":   true,
	"flock":          true,
	"halt":           true,
	"init":           true,
	"ionice":         true,
	"iptables":       true,
	"ksh":            true,
	"lua":            true,
	"luajit":         true,
	"lvremove":       true,
	"mkfs":           true,
	"ncat":           true,
	"nc":             true,
	"nice":           true,
	"nohup":          true,
	"parted":         true,
	"php":            true,
	"php-cgi":        true,
	"pkexec":         true,
	"poweroff":       true,
	"reboot":         true,
	"setsid":         true,
	"shutdown":       true,
	"sh":             true,
	"socat":          true,
	"stdbuf":         true,
	"su":             true,
	"sudo":           true,
	"taskset":        true,
	"tclsh":          true,
	"time":           true,
	"timeout":        true,
	"ufw":            true,
	"watch":          true,
	"wipefs":         true,
	"wish":           true,
	"zsh":            true,
}

var writeCommands = map[string]bool{
	"chmod":    true,
	"chown":    true,
	"cp":       true,
	"install":  true,
	"ln":       true,
	"mkdir":    true,
	"mv":       true,
	"tee":      true,
	"touch":    true,
	"truncate": true,
}

// Classify returns an opskit-core safety risk that can be passed directly to
// safety.Authorize. Unparseable or dynamically constructed commands are R3.
// Unknown commands intentionally have an R2 floor; exhaustively listing every
// executable or living-off-the-land binary is not a goal of this classifier.
//
//nolint:gocyclo // Operator handling stays centralized so escalation cannot be skipped by a branch.
func Classify(command string) safety.Risk {
	items, ok := scan(command)
	if !ok || len(items) == 0 {
		return safety.R3
	}

	base := safety.R0
	hasOperator := false
	hasCommand := false
	segment := make([]string, 0, len(items))
	for i := 0; i < len(items); i++ {
		current := items[i]
		if current.kind == wordItem {
			segment = append(segment, current.text)
			continue
		}
		if current.text == "&" {
			return safety.R3
		}
		if current.text == ">" || current.text == ">>" || current.text == "<" {
			if i+1 >= len(items) || items[i+1].kind != wordItem {
				return safety.R3
			}
			if current.text != "<" && isSensitiveWriteTarget(items[i+1].text) {
				return safety.R3
			}
			i++
			hasOperator = true
			continue
		}
		if len(segment) > 0 {
			base = maxRisk(base, classifySegment(segment))
			segment = segment[:0]
			hasCommand = true
		}
		hasOperator = true
	}
	if len(segment) > 0 {
		base = maxRisk(base, classifySegment(segment))
		hasCommand = true
	}
	if !hasCommand {
		return safety.R3
	}
	if base == safety.R3 {
		return base
	}
	if hasOperator {
		return raise(base)
	}
	return base
}

//nolint:gocyclo // The explicit command rule table is easier to audit than dispersed callbacks.
func classifySegment(words []string) safety.Risk {
	if len(words) == 0 {
		return safety.R3
	}
	command := commandName(words[0])
	if dangerousCommands[command] || strings.HasPrefix(command, "mkfs.") {
		return safety.R3
	}
	for _, word := range words {
		if commandName(word) == "sudo" {
			return safety.R3
		}
	}

	switch command {
	case "rm":
		if destructiveRM(words[1:]) {
			return safety.R3
		}
		return safety.R2
	case "curl":
		if curlUploads(words[1:]) {
			return safety.R3
		}
		return safety.R2
	case "wget":
		if hasOptionPrefix(words[1:], "--post-", "--body-") {
			return safety.R3
		}
		if target, ok := wgetOutputTarget(words[1:]); ok && isSensitiveWriteTarget(target) {
			return safety.R3
		}
		return safety.R2
	case "find":
		if hasAnyWord(words[1:], "-exec", "-execdir", "-delete", "-ok", "-okdir") {
			return safety.R3
		}
		if target, ok := findWriteTarget(words[1:]); ok {
			if target == "" || isSensitiveWriteTarget(target) {
				return safety.R3
			}
			return safety.R2
		}
		return safety.R0
	case "ss":
		if ssKillsSockets(words[1:]) {
			return safety.R3
		}
		return safety.R0
	case "awk", "gawk", "mawk", "perl", "python", "python3", "ruby", "node", "eval", "xargs", "env":
		return safety.R3
	case "systemctl":
		return classifySystemctl(words)
	case "docker":
		return classifyDocker(words)
	case "ip":
		if len(words) >= 2 && hasAnyWord(words[1:2], "address", "addr", "link", "route", "rule", "neighbor", "netns") {
			return safety.R0
		}
		return safety.R2
	}

	if writeCommands[command] {
		for _, arg := range words[1:] {
			if isSensitiveWriteTarget(arg) {
				return safety.R3
			}
		}
		if command == "mkdir" || command == "touch" {
			return safety.R1
		}
		return safety.R2
	}
	if readOnlyCommands[command] {
		return safety.R0
	}
	return safety.R2
}

func classifyDocker(words []string) safety.Risk {
	if len(words) < 2 || strings.HasPrefix(words[1], "-") {
		return safety.R3
	}
	if hasAnyWord(words[1:2], "compose", "stack") {
		return safety.R3
	}
	actionIndex := 1
	if hasAnyWord(words[1:2], "container", "image", "volume", "network", "system", "builder") {
		actionIndex = 2
	}
	if len(words) <= actionIndex || strings.HasPrefix(words[actionIndex], "-") {
		return safety.R3
	}
	action := strings.ToLower(words[actionIndex])
	if hasAnyWord(
		[]string{action},
		"run", "create", "exec", "build", "commit", "cp",
		"import", "save", "load", "export", "prune",
	) {
		return safety.R3
	}
	if hasAnyWord(
		[]string{action},
		"ps", "ls", "images", "inspect", "logs", "version", "info",
		"stats", "top", "port", "diff", "history", "events",
	) {
		return safety.R0
	}
	return safety.R2
}

func classifySystemctl(words []string) safety.Risk {
	if len(words) < 2 {
		return safety.R3
	}
	subcommand := strings.ToLower(words[1])
	if strings.HasPrefix(subcommand, "-") {
		return safety.R3
	}
	if hasAnyWord(
		[]string{subcommand},
		"reboot", "poweroff", "halt", "kexec",
		"suspend", "hibernate", "hybrid-sleep",
		"emergency", "rescue", "isolate", "switch-root", "mask",
	) {
		return safety.R3
	}
	if hasAnyWord([]string{subcommand}, "status", "show", "is-active", "is-enabled", "list-units", "list-unit-files") {
		return safety.R0
	}
	return safety.R2
}

func ssKillsSockets(args []string) bool {
	for _, arg := range args {
		if arg == "--kill" || strings.HasPrefix(arg, "--kill=") {
			return true
		}
		if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") && strings.ContainsRune(strings.TrimPrefix(arg, "-"), 'K') {
			return true
		}
	}
	return false
}

//nolint:gocyclo // Shell quoting and operator states are deliberately handled in one fail-closed scanner.
func scan(command string) ([]item, bool) {
	var items []item
	var token strings.Builder
	quote := rune(0)
	escaped := false
	atBoundary := true

	flush := func() {
		if token.Len() == 0 {
			return
		}
		items = append(items, item{kind: wordItem, text: token.String()})
		token.Reset()
	}

	for pos := 0; pos < len(command); {
		r, size := utf8.DecodeRuneInString(command[pos:])
		if r == utf8.RuneError && size == 1 || r == 0 {
			return nil, false
		}
		pos += size

		if escaped {
			token.WriteRune(r)
			escaped = false
			atBoundary = false
			continue
		}
		if quote != 0 {
			if r == quote {
				quote = 0
				continue
			}
			if quote == '"' && r == '\\' {
				escaped = true
				continue
			}
			if quote == '"' && (r == '$' || r == '`') {
				return nil, false
			}
			token.WriteRune(r)
			atBoundary = false
			continue
		}

		switch {
		case r == '\\':
			escaped = true
			atBoundary = false
		case r == '\'' || r == '"':
			quote = r
			atBoundary = false
		case r == '$' || r == '`' || r == '(' || r == ')':
			return nil, false
		case r == '#' && atBoundary:
			flush()
			sawNewline := false
			for pos < len(command) {
				next, nextSize := utf8.DecodeRuneInString(command[pos:])
				pos += nextSize
				if next == '\n' {
					sawNewline = true
					break
				}
			}
			if sawNewline {
				items = append(items, item{kind: operatorItem, text: ";"})
			}
			atBoundary = true
		case r == '\n':
			flush()
			items = append(items, item{kind: operatorItem, text: ";"})
			atBoundary = true
		case unicode.IsSpace(r):
			flush()
			atBoundary = true
		case strings.ContainsRune("|&;><", r):
			flush()
			op := string(r)
			if pos < len(command) && isRepeatedOperator(r, command[pos]) {
				op += string(r)
				pos++
			}
			items = append(items, item{kind: operatorItem, text: op})
			atBoundary = true
		default:
			token.WriteRune(r)
			atBoundary = false
		}
	}
	if quote != 0 || escaped {
		return nil, false
	}
	flush()
	return items, true
}

func isRepeatedOperator(operator rune, next byte) bool {
	switch operator {
	case '|':
		return next == '|'
	case '&':
		return next == '&'
	case '>':
		return next == '>'
	default:
		return false
	}
}

func destructiveRM(args []string) bool {
	recursive := false
	force := false
	for _, arg := range args {
		if arg == "--" {
			break
		}
		switch arg {
		case "--recursive":
			recursive = true
		case "--force":
			force = true
		default:
			if strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--") {
				flags := strings.TrimPrefix(arg, "-")
				recursive = recursive || strings.Contains(flags, "r") || strings.Contains(flags, "R")
				force = force || strings.Contains(flags, "f")
			}
		}
	}
	return recursive && force
}

func commandName(value string) string {
	value = strings.ReplaceAll(value, "\\", "/")
	return strings.ToLower(path.Base(value))
}

func isSystemPath(value string) bool {
	value = strings.ReplaceAll(value, "\\", "/")
	cleaned := path.Clean(value)
	for strings.HasPrefix(cleaned, "../") {
		cleaned = strings.TrimPrefix(cleaned, "../")
	}
	for _, prefix := range []string{"/boot", "/dev", "/etc", "/proc", "/root", "/sbin", "/sys", "/usr", "boot", "dev", "etc", "proc", "root", "sbin", "sys", "usr"} {
		if cleaned == prefix || strings.HasPrefix(cleaned, prefix+"/") {
			return true
		}
	}
	return strings.HasPrefix(cleaned, "/dev/tcp/") || strings.HasPrefix(cleaned, "/dev/udp/")
}

func isSensitiveWriteTarget(value string) bool {
	if isSystemPath(value) {
		return true
	}
	normalized := strings.ToLower(strings.ReplaceAll(value, "\\", "/"))
	cleaned := path.Clean(normalized)
	if strings.HasPrefix(cleaned, "~/") {
		cleaned = "/home/~/" + strings.TrimPrefix(cleaned, "~/")
	}
	if strings.Contains(cleaned, "/.ssh/") || strings.HasSuffix(cleaned, "/.ssh") {
		return true
	}
	base := path.Base(cleaned)
	switch base {
	case "authorized_keys", ".bashrc", ".profile", ".bash_profile", ".zshrc", "crontab":
		return true
	}
	return cleaned == "/var/spool/cron" || strings.HasPrefix(cleaned, "/var/spool/cron/")
}

func curlUploads(args []string) bool {
	for _, arg := range args {
		if strings.HasPrefix(arg, "--") {
			lower := strings.ToLower(arg)
			for _, option := range []string{
				"--upload-file", "--form", "--data", "--data-ascii", "--data-binary",
				"--data-raw", "--data-urlencode", "--json",
			} {
				if lower == option || strings.HasPrefix(lower, option+"=") {
					return true
				}
			}
			continue
		}
		if strings.HasPrefix(arg, "-") && len(arg) > 1 {
			flags := strings.TrimPrefix(arg, "-")
			if strings.ContainsRune(flags, 'T') || strings.ContainsRune(flags, 'F') || strings.ContainsRune(flags, 'd') {
				return true
			}
		}
	}
	return false
}

func wgetOutputTarget(args []string) (string, bool) {
	for i, arg := range args {
		switch {
		case arg == "-O" || arg == "--output-document":
			if i+1 >= len(args) {
				return "", true
			}
			return args[i+1], true
		case strings.HasPrefix(arg, "--output-document="):
			return strings.TrimPrefix(arg, "--output-document="), true
		case strings.HasPrefix(arg, "-") && !strings.HasPrefix(arg, "--"):
			optionPos := strings.IndexRune(strings.TrimPrefix(arg, "-"), 'O')
			if optionPos < 0 {
				continue
			}
			target := strings.TrimPrefix(arg, "-")[optionPos+1:]
			if target != "" {
				return target, true
			}
			if i+1 >= len(args) {
				return "", true
			}
			return args[i+1], true
		}
	}
	return "", false
}

func findWriteTarget(args []string) (string, bool) {
	for i, arg := range args {
		switch strings.ToLower(arg) {
		case "-fprintf", "-fprint", "-fprint0", "-fls":
			if i+1 >= len(args) {
				return "", true
			}
			return args[i+1], true
		}
	}
	return "", false
}

func hasOptionPrefix(args []string, prefixes ...string) bool {
	for _, arg := range args {
		lower := strings.ToLower(arg)
		for _, prefix := range prefixes {
			if strings.HasPrefix(lower, prefix) {
				return true
			}
		}
	}
	return false
}

func hasAnyWord(words []string, candidates ...string) bool {
	for _, word := range words {
		lower := strings.ToLower(word)
		for _, candidate := range candidates {
			if lower == candidate {
				return true
			}
		}
	}
	return false
}

func maxRisk(left, right safety.Risk) safety.Risk {
	if right > left {
		return right
	}
	return left
}

func raise(risk safety.Risk) safety.Risk {
	if risk >= safety.R3 {
		return safety.R3
	}
	return risk + 1
}
