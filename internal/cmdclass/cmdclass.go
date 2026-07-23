// Package cmdclass classifies shell commands by governance risk.
package cmdclass

import (
	"net/url"
	"path"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/JiangHe12/opskit-core/v2/safety"
)

type itemKind uint8

const (
	wordItem itemKind = iota
	operatorItem
)

type item struct {
	kind              itemKind
	text              string
	quoted            bool
	unquotedExpansion bool
}

var readOnlyCommands = map[string]bool{
	"cat":      true,
	"df":       true,
	"du":       true,
	"echo":     true,
	"free":     true,
	"grep":     true,
	"head":     true,
	"id":       true,
	"ls":       true,
	"netstat":  true,
	"pgrep":    true,
	"printf":   true,
	"ps":       true,
	"pwd":      true,
	"readlink": true,
	"stat":     true,
	"tail":     true,
	"uname":    true,
	"uptime":   true,
	"wc":       true,
	"whoami":   true,
}

var dangerousCommands = map[string]bool{
	".":              true,
	"bash":           true,
	"builtin":        true,
	"busybox":        true,
	"chrt":           true,
	"command":        true,
	"dash":           true,
	"dd":             true,
	"doas":           true,
	"docker-compose": true,
	"exec":           true,
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
	"source":         true,
	"stdbuf":         true,
	"su":             true,
	"sudo":           true,
	"taskset":        true,
	"tclsh":          true,
	"time":           true,
	"timeout":        true,
	"trap":           true,
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
	segment := make([]item, 0, len(items))
	for i := 0; i < len(items); i++ {
		current := items[i]
		if current.kind == wordItem {
			segment = append(segment, current)
			continue
		}
		if current.text == "&" {
			return safety.R3
		}
		if current.text == ">" || current.text == ">>" || current.text == "<" {
			if i+1 >= len(items) || items[i+1].kind != wordItem {
				return safety.R3
			}
			if items[i+1].unquotedExpansion ||
				current.text != "<" && isSensitiveWriteTarget(items[i+1].text) {
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

func classifySegment(parts []item) safety.Risk {
	if len(parts) == 0 || hasUnquotedExpansion(parts) {
		return safety.R3
	}
	words := make([]string, len(parts))
	for i := range parts {
		words[i] = parts[i].text
	}
	return classifyWords(words)
}

//nolint:gocyclo // The explicit command rule table is easier to audit than dispersed callbacks.
func classifyWords(words []string) safety.Risk {
	command := commandName(words[0])
	if command == "!" || isShellAssignment(words[0]) || dangerousCommands[command] || strings.HasPrefix(command, "mkfs.") {
		return safety.R3
	}
	for _, word := range words {
		if commandName(word) == "sudo" {
			return safety.R3
		}
	}

	switch command {
	case "rm":
		return classifyRM(words[1:])
	case "date":
		return classifyDate(words[1:])
	case "hostname":
		return classifyHostname(words[1:])
	case "journalctl":
		return classifyJournalctl(words[1:])
	case "curl":
		return classifyCurl(words[1:])
	case "wget":
		return classifyWget(words[1:])
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
		return classifyIP(words[1:])
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
		"import", "save", "load", "export", "prune", "rm", "remove", "rmi",
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
	if hasAnyWord([]string{action}, "start", "stop", "restart") {
		return safety.R2
	}
	return safety.R3
}

func classifyDate(args []string) safety.Risk {
	if len(args) == 0 {
		return safety.R0
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case strings.HasPrefix(arg, "-s"), arg == "--set", strings.HasPrefix(arg, "--set="):
			return safety.R3
		case strings.HasPrefix(arg, "+"):
			continue
		case hasExactWord(arg, "-u", "-R", "-I", "--utc", "--universal", "--rfc-email", "--debug", "--resolution", "--help", "--version", "--iso-8601"):
			continue
		case arg == "-d", arg == "-f", arg == "-r", arg == "--date", arg == "--file", arg == "--reference":
			if i+1 >= len(args) {
				return safety.R3
			}
			i++
		case strings.HasPrefix(arg, "-d"), strings.HasPrefix(arg, "-f"), strings.HasPrefix(arg, "-r"),
			strings.HasPrefix(arg, "--date="), strings.HasPrefix(arg, "--file="), strings.HasPrefix(arg, "--reference="),
			strings.HasPrefix(arg, "--iso-8601="), strings.HasPrefix(arg, "--rfc-3339="):
			continue
		default:
			return safety.R3
		}
	}
	return safety.R0
}

func classifyHostname(args []string) safety.Risk {
	for _, arg := range args {
		if !hasExactWord(
			arg,
			"-a", "--alias", "-d", "--domain", "-f", "--fqdn", "--long",
			"-i", "--ip-address", "-I", "--all-ip-addresses", "-s", "--short",
			"-y", "--yp", "--nis", "-V", "--version", "-h", "--help",
		) {
			return safety.R3
		}
	}
	return safety.R0
}

//nolint:gocyclo // Explicit option parsing prevents maintenance flags from hiding inside read syntax.
func classifyJournalctl(args []string) safety.Risk {
	for i := 0; i < len(args); i++ {
		arg := args[i]
		lower := strings.ToLower(arg)
		if hasAnyWord(
			[]string{lower},
			"--rotate", "--flush", "--sync", "--relinquish-var",
			"--smart-relinquish-var", "--setup-keys", "--update-catalog",
			"--cursor-file",
		) || strings.HasPrefix(lower, "--vacuum-") {
			return safety.R3
		}
		if strings.HasPrefix(lower, "--cursor-file=") {
			return safety.R3
		}
		if arg == "" || arg[0] != '-' {
			continue
		}
		if !strings.HasPrefix(arg, "--") {
			if arg == "-b" && i+1 < len(args) && isJournalBootOffset(args[i+1]) {
				i++
				continue
			}
			next, ok := classifyJournalShortOption(args, i)
			if !ok {
				return safety.R3
			}
			i = next
			continue
		}
		if hasExactWord(
			arg,
			"--all", "--boot", "--case-sensitive", "--catalog", "--disk-usage",
			"--dmesg", "--fields", "--follow", "--full", "--header", "--help",
			"--list-boots", "--list-fields", "--local", "--merge", "--no-hostname",
			"--no-pager", "--no-tail", "--pager-end", "--quiet", "--reverse",
			"--show-cursor", "--system", "--user", "--utc", "--verify", "--version",
		) {
			if arg == "--boot" && i+1 < len(args) && isJournalBootOffset(args[i+1]) {
				i++
			}
			continue
		}
		if hasExactWord(
			arg,
			"--after-cursor", "--cursor", "--directory",
			"--facility", "--field", "--file", "--grep", "--identifier", "--image",
			"--interval", "--lines", "--machine", "--namespace",
			"--output", "--output-fields", "--priority", "--root",
			"--since", "--unit", "--until", "--user-unit",
			"--verify-key",
		) {
			if i+1 >= len(args) || strings.HasPrefix(args[i+1], "--") {
				return safety.R3
			}
			i++
			continue
		}
		if hasOptionPrefix(
			[]string{arg},
			"--after-cursor=", "--boot=", "--cursor=", "--directory=",
			"--facility=", "--field=", "--file=", "--grep=", "--identifier=", "--image=",
			"--interval=", "--lines=", "--machine=", "--namespace=", "--output=",
			"--output-fields=", "--priority=", "--root=", "--since=", "--unit=",
			"--until=", "--user-unit=", "--verify-key=",
		) {
			continue
		}
		return safety.R3
	}
	return safety.R0
}

func classifyJournalShortOption(args []string, index int) (int, bool) {
	option := strings.TrimPrefix(args[index], "-")
	if option == "" {
		return index, false
	}
	runes := []rune(option)
	for pos, flag := range runes {
		if flag == 'b' && pos+1 < len(runes) && isJournalBootOffset(string(runes[pos+1:])) {
			return index, true
		}
		if strings.ContainsRune("abefhklmNqrxV", flag) {
			continue
		}
		if !strings.ContainsRune("cDFgMnopStuU", flag) {
			return index, false
		}
		if pos+1 < len(runes) {
			return index, true
		}
		if index+1 >= len(args) || strings.HasPrefix(args[index+1], "--") {
			return index, false
		}
		return index + 1, true
	}
	return index, true
}

func isJournalBootOffset(value string) bool {
	value = strings.TrimPrefix(strings.TrimPrefix(value, "-"), "+")
	if value == "" {
		return false
	}
	for _, char := range value {
		if char < '0' || char > '9' {
			return false
		}
	}
	return true
}

//nolint:gocyclo // The explicit object/action allowlist keeps unknown ip combinations fail-closed.
func classifyIP(args []string) safety.Risk {
	index := 0
	for index < len(args) && strings.HasPrefix(args[index], "-") {
		option := args[index]
		if hasExactWord(
			option,
			"-0", "-4", "-6", "-B", "-M", "-a", "-all", "-br", "-brief", "-c", "-color",
			"-d", "-details", "-h", "-human", "-iec", "-j", "-json", "-o",
			"-oneline", "-p", "-pretty", "-r", "-resolve", "-s", "-statistics",
			"-t", "-timestamp", "-ts",
		) {
			index++
			continue
		}
		if hasExactWord(option, "-f", "-family", "-netns", "-rcvbuf") {
			if index+1 >= len(args) {
				return safety.R3
			}
			index += 2
			continue
		}
		return safety.R3
	}
	if index >= len(args) {
		return safety.R3
	}

	object := strings.ToLower(args[index])
	index++
	action := ""
	if index < len(args) {
		action = strings.ToLower(args[index])
	}

	switch object {
	case "a", "addr", "address":
		if action == "" || isIPShowAction(action) {
			return safety.R0
		}
	case "l", "link":
		if action == "" || isIPShowAction(action) {
			return safety.R0
		}
		if action == "property" && index+1 < len(args) && isIPShowAction(strings.ToLower(args[index+1])) {
			return safety.R0
		}
	case "r", "route":
		if action == "" || isIPShowAction(action) || hasAnyWord([]string{action}, "g", "get") {
			return safety.R0
		}
	case "ru", "rule":
		if action == "" || isIPShowAction(action) {
			return safety.R0
		}
	case "neighbor", "neigh":
		if action == "" || isIPShowAction(action) {
			return safety.R0
		}
	case "netns":
		if hasAnyWord([]string{action}, "l", "list", "list-id", "identify", "pids") {
			return safety.R0
		}
	}
	return safety.R3
}

func isIPShowAction(action string) bool {
	return hasAnyWord([]string{action}, "l", "list", "ls", "lst", "sh", "sho", "show")
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
	tokenStarted := false
	tokenQuoted := false
	tokenUnquotedExpansion := false

	flush := func() {
		if !tokenStarted {
			return
		}
		items = append(items, item{
			kind:              wordItem,
			text:              token.String(),
			quoted:            tokenQuoted,
			unquotedExpansion: tokenUnquotedExpansion,
		})
		token.Reset()
		tokenStarted = false
		tokenQuoted = false
		tokenUnquotedExpansion = false
	}

	for pos := 0; pos < len(command); {
		r, size := utf8.DecodeRuneInString(command[pos:])
		if r == utf8.RuneError && size == 1 || r == 0 {
			return nil, false
		}
		pos += size

		if escaped {
			if r == '\n' {
				escaped = false
				continue
			}
			if quote == '"' && !strings.ContainsRune("$`\"\\", r) {
				token.WriteRune('\\')
			}
			token.WriteRune(r)
			tokenStarted = true
			tokenQuoted = true
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
			tokenStarted = true
			atBoundary = false
			continue
		}

		switch {
		case r == '\\':
			escaped = true
		case r == '\'' || r == '"':
			quote = r
			tokenStarted = true
			tokenQuoted = true
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
			if isExpansionRune(r) || r == '~' && !tokenStarted {
				tokenUnquotedExpansion = true
			}
			tokenStarted = true
			atBoundary = false
		}
	}
	if quote != 0 || escaped {
		return nil, false
	}
	flush()
	return items, true
}

func isExpansionRune(value rune) bool {
	return strings.ContainsRune("{}*?[", value)
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

//nolint:gocyclo // The option and target checks stay together so unknown forms fail closed.
func classifyRM(args []string) safety.Risk {
	parseOptions := true
	for _, arg := range args {
		if parseOptions && arg == "--" {
			parseOptions = false
			continue
		}
		if parseOptions && strings.HasPrefix(arg, "--") {
			switch {
			case arg == "--recursive":
				return safety.R3
			case hasExactWord(
				arg,
				"--dir", "--force", "--help", "--interactive", "--no-preserve-root",
				"--one-file-system", "--preserve-root", "--verbose", "--version",
			),
				strings.HasPrefix(arg, "--interactive="),
				arg == "--preserve-root=all":
				continue
			default:
				return safety.R3
			}
		}
		if parseOptions && strings.HasPrefix(arg, "-") && arg != "-" {
			for _, flag := range strings.TrimPrefix(arg, "-") {
				if flag == 'r' || flag == 'R' {
					return safety.R3
				}
				if !strings.ContainsRune("dfiIv", flag) {
					return safety.R3
				}
			}
			continue
		}
		if isSensitiveWriteTarget(arg) {
			return safety.R3
		}
	}
	return safety.R2
}

func isShellAssignment(value string) bool {
	equals := strings.IndexByte(value, '=')
	if equals <= 0 {
		return false
	}
	name := strings.TrimSuffix(value[:equals], "+")
	if name == "" {
		return false
	}
	for i, r := range name {
		if i == 0 {
			if r != '_' && !unicode.IsLetter(r) {
				return false
			}
			continue
		}
		if r != '_' && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

func hasUnquotedExpansion(parts []item) bool {
	for _, part := range parts {
		if part.unquotedExpansion {
			return true
		}
	}
	return false
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
	if cleaned == "/" {
		return true
	}
	first := strings.SplitN(strings.TrimPrefix(cleaned, "/"), "/", 2)[0]
	if strings.HasPrefix(first, "lib") {
		return true
	}
	return hasExactWord(first, "bin", "boot", "dev", "etc", "proc", "root", "run", "sbin", "sys", "usr", "var")
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
	if cleaned == ".ssh" || strings.HasPrefix(cleaned, ".ssh/") ||
		strings.Contains(cleaned, "/.ssh/") || strings.HasSuffix(cleaned, "/.ssh") {
		return true
	}
	base := path.Base(cleaned)
	switch base {
	case "authorized_keys", ".bashrc", ".profile", ".bash_profile", ".zshrc", ".ssh",
		"cron", "cron.d", "crontab":
		return true
	}
	return cleaned == "/var/spool/cron" || strings.HasPrefix(cleaned, "/var/spool/cron/")
}

//nolint:gocyclo // Structured fail-closed option parsing is intentionally explicit.
func classifyCurl(args []string) safety.Risk {
	configDisabled := curlConfigDisabled(args)
	parseOptions := true
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !parseOptions {
			if !isSafeTransferURL(arg, "http", "https", "ftp", "ftps") {
				return safety.R3
			}
			continue
		}
		if arg == "--" {
			parseOptions = false
			continue
		}
		if strings.HasPrefix(arg, "--") {
			risk, next := classifyCurlLongOption(args, i)
			if risk == safety.R3 {
				return safety.R3
			}
			i = next
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			risk, next := classifyCurlShortOption(args, i)
			if risk == safety.R3 {
				return safety.R3
			}
			i = next
			continue
		}
		if !isSafeTransferURL(arg, "http", "https", "ftp", "ftps") {
			return safety.R3
		}
	}
	if !configDisabled {
		return safety.R3
	}
	return safety.R2
}

//nolint:gocyclo // Every accepted curl long option is intentionally visible in this fail-closed inventory.
func classifyCurlLongOption(args []string, index int) (safety.Risk, int) {
	name, inlineValue, hasInlineValue := splitLongOption(args[index])
	if name == "--next" {
		if hasInlineValue {
			return safety.R3, index
		}
		return safety.R2, index
	}

	if strings.HasPrefix(name, "--expand-") || hasExactWord(
		name,
		"--config", "--upload-file", "--form", "--form-string",
		"--data", "--data-ascii", "--data-binary", "--data-raw", "--data-urlencode", "--json",
		"--quote", "--prequote", "--postquote",
		"--remote-name", "--remote-name-all", "--remote-header-name",
		"--create-dirs", "--remove-on-error", "--metalink",
		"--variable", "--netrc", "--netrc-file", "--netrc-optional",
		"--cert", "--cert-type", "--key", "--key-type", "--pass",
		"--delegation", "--engine", "--egd-file", "--random-file",
		"--location-trusted", "--ftp-create-dirs", "--ftp-port",
		"--ftp-alternative-to-user", "--mail-auth", "--mail-from", "--mail-rcpt",
		"--ssl-auto-client-cert", "--telnet-option",
		"--proto", "--proto-default", "--proto-redir",
	) {
		return safety.R3, index
	}

	switch name {
	case "--request":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || !isReadOnlyHTTPMethod(value) {
			return safety.R3, index
		}
		return safety.R2, next
	case "--output", "--output-dir", "--cookie-jar", "--dump-header",
		"--trace", "--trace-ascii", "--stderr", "--etag-save", "--alt-svc",
		"--hsts", "--libcurl":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || isUnsafeOutputTarget(value) {
			return safety.R3, index
		}
		return safety.R2, next
	case "--write-out":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || classifyCurlWriteOut(value) == safety.R3 {
			return safety.R3, index
		}
		return safety.R2, next
	case "--header", "--proxy-header":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || classifyHTTPHeader(value) == safety.R3 {
			return safety.R3, index
		}
		return safety.R2, next
	case "--cookie":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || curlCookieReadsFile(value) {
			return safety.R3, index
		}
		return safety.R2, next
	case "--url-query":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || curlQueryReadsFile(value) {
			return safety.R3, index
		}
		return safety.R2, next
	case "--url":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || !isSafeTransferURL(value, "http", "https", "ftp", "ftps") {
			return safety.R3, index
		}
		return safety.R2, next
	}

	if hasExactWord(
		name,
		"--anyauth", "--append", "--basic", "--ca-native", "--compressed",
		"--compressed-ssh", "--crlf", "--digest", "--disable",
		"--disable-eprt", "--disable-epsv", "--disallow-username-in-url",
		"--doh-cert-status", "--doh-insecure", "--fail", "--fail-early",
		"--fail-with-body", "--false-start", "--ftp-ccc", "--ftp-pasv",
		"--ftp-pret", "--ftp-skip-pasv-ip", "--ftp-ssl-ccc",
		"--ftp-ssl-control", "--get", "--globoff", "--head",
		"--haproxy-protocol",
		"--help", "--http0.9", "--http1.0", "--http1.1", "--http2",
		"--http2-prior-knowledge", "--http3", "--http3-only",
		"--ignore-content-length", "--include", "--insecure", "--ipv4",
		"--ipv6", "--junk-session-cookies", "--list-only", "--location",
		"--manual", "--negotiate", "--no-alpn", "--no-buffer",
		"--no-clobber", "--no-keepalive", "--no-npn", "--no-progress-meter",
		"--no-sessionid", "--ntlm", "--ntlm-wb", "--parallel",
		"--parallel-immediate", "--path-as-is", "--post301", "--post302",
		"--post303", "--progress-bar", "--proxy-anyauth", "--proxy-basic",
		"--proxy-ca-native", "--proxy-digest", "--proxy-insecure",
		"--proxy-negotiate", "--proxy-ntlm", "--proxy-ssl-allow-beast",
		"--proxy-tlsv1",
		"--raw", "--remote-time", "--retry-all-errors", "--retry-connrefused",
		"--sasl-ir", "--show-error", "--silent", "--socks5-basic",
		"--socks5-gssapi", "--ssl", "--ssl-allow-beast", "--ssl-reqd",
		"--ssl-revoke-best-effort",
		"--styled-output", "--suppress-connect-headers", "--tcp-fastopen",
		"--tcp-nodelay", "--tls-earlydata", "--tlsv1", "--tlsv1.0",
		"--tlsv1.1", "--tlsv1.2", "--tlsv1.3", "--trace-ids",
		"--trace-time", "--tr-encoding", "--use-ascii", "--verbose",
		"--version", "--xattr",
	) {
		if hasInlineValue {
			return safety.R3, index
		}
		return safety.R2, index
	}

	if hasExactWord(
		name,
		"--abstract-unix-socket", "--aws-sigv4", "--connect-timeout",
		"--connect-to", "--continue-at", "--curves",
		"--dns-interface", "--dns-ipv4-addr", "--dns-ipv6-addr",
		"--dns-servers", "--doh-url", "--expect100-timeout", "--ftp-account",
		"--ftp-method", "--happy-eyeballs-timeout-ms",
		"--haproxy-clientip", "--hostpubmd5",
		"--hostpubsha256", "--interface", "--ip-tos", "--keepalive-cnt",
		"--keepalive-time", "--limit-rate", "--local-port", "--login-options",
		"--max-filesize", "--max-redirs", "--max-time", "--noproxy",
		"--oauth2-bearer", "--parallel-max", "--pinnedpubkey", "--preproxy",
		"--proxy", "--proxy-cacert", "--proxy-capath", "--proxy-ciphers",
		"--proxy-crlfile", "--proxy-service-name",
		"--proxy-tls13-ciphers", "--proxy-tlsauthtype", "--proxy-tlspassword",
		"--proxy-tlsuser", "--proxy-user", "--proxy1.0", "--rate", "--range",
		"--referer", "--request-target", "--resolve", "--retry",
		"--retry-delay", "--retry-max-time", "--sasl-authzid", "--service-name",
		"--socks4", "--socks4a", "--socks5", "--socks5-hostname",
		"--speed-limit", "--speed-time", "--tls-max", "--tls13-ciphers",
		"--tlsauthtype", "--tlspassword", "--tlsuser", "--tftp-blksize",
		"--time-cond", "--unix-socket", "--user", "--user-agent",
	) {
		_, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok {
			return safety.R3, index
		}
		return safety.R2, next
	}
	return safety.R3, index
}

//nolint:gocyclo // Short-option value consumption must remain explicit and fail closed.
func classifyCurlShortOption(args []string, index int) (safety.Risk, int) {
	option := strings.TrimPrefix(args[index], "-")
	if option == "" {
		return safety.R3, index
	}
	for pos := 0; pos < len(option); pos++ {
		switch option[pos] {
		case 'd', 'E', 'F', 'J', 'K', 'n', 'O', 'P', 'Q', 't', 'T':
			return safety.R3, index
		case 'X':
			method, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok || !isReadOnlyHTTPMethod(method) {
				return safety.R3, index
			}
			return safety.R2, next
		case 'o':
			target, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok || target == "" || isSensitiveWriteTarget(target) {
				return safety.R3, index
			}
			return safety.R2, next
		case 'c', 'D':
			target, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok || isUnsafeOutputTarget(target) {
				return safety.R3, index
			}
			return safety.R2, next
		case 'w':
			value, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok || classifyCurlWriteOut(value) == safety.R3 {
				return safety.R3, index
			}
			return safety.R2, next
		case 'H':
			value, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok || classifyHTTPHeader(value) == safety.R3 {
				return safety.R3, index
			}
			return safety.R2, next
		case 'b':
			value, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok || curlCookieReadsFile(value) {
				return safety.R3, index
			}
			return safety.R2, next
		case 'A', 'C', 'e', 'm', 'r', 'u', 'U', 'x', 'y', 'Y', 'z':
			_, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok {
				return safety.R3, index
			}
			return safety.R2, next
		default:
			if !strings.ContainsRune("012346aBfgGhIijkLlMNRpqRsSvVZ#", rune(option[pos])) {
				return safety.R3, index
			}
		}
	}
	return safety.R2, index
}

//nolint:gocyclo // Structured fail-closed option parsing is intentionally explicit.
func classifyWget(args []string) safety.Risk {
	configDisabled := wgetConfigDisabled(args)
	parseOptions := true
	explicitOutput := false
	noOutput := false
	urls := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if !parseOptions {
			if !isSafeTransferURL(arg, "http", "https", "ftp") {
				return safety.R3
			}
			urls = append(urls, arg)
			continue
		}
		if arg == "--" {
			parseOptions = false
			continue
		}
		if strings.HasPrefix(arg, "--") {
			risk, next, output, spider := classifyWgetLongOption(args, i)
			if risk == safety.R3 {
				return safety.R3
			}
			explicitOutput = explicitOutput || output
			noOutput = noOutput || spider
			i = next
			continue
		}
		if strings.HasPrefix(arg, "-") && arg != "-" {
			risk, next, output := classifyWgetShortOption(args, i)
			if risk == safety.R3 {
				return safety.R3
			}
			explicitOutput = explicitOutput || output
			i = next
			continue
		}
		if !isSafeTransferURL(arg, "http", "https", "ftp") {
			return safety.R3
		}
		urls = append(urls, arg)
	}
	if !explicitOutput && !noOutput {
		for _, rawURL := range urls {
			if hasSensitiveDownloadName(rawURL) {
				return safety.R3
			}
		}
	}
	if !configDisabled {
		return safety.R3
	}
	return safety.R2
}

//nolint:gocyclo // Every accepted wget long option is intentionally visible in this fail-closed inventory.
func classifyWgetLongOption(args []string, index int) (safety.Risk, int, bool, bool) {
	name, inlineValue, hasInlineValue := splitLongOption(args[index])
	if hasExactWord(
		name,
		"--config", "--execute", "--use-askpass", "--delete-after", "--unlink",
		"--post-data", "--post-file", "--body-data", "--body-file",
		"--input-file", "--mirror", "--recursive", "--page-requisites",
		"--content-disposition", "--trust-server-names", "--default-page",
		"--certificate", "--private-key", "--load-cookies", "--netrc-file",
		"--backup-converted", "--follow-ftp", "--preserve-permissions",
		"--retr-symlinks", "--span-hosts",
	) || strings.HasPrefix(name, "--warc-") &&
		name != "--warc-file" && name != "--warc-tempdir" {
		return safety.R3, index, false, false
	}

	switch name {
	case "--method":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || !isReadOnlyHTTPMethod(value) {
			return safety.R3, index, false, false
		}
		return safety.R2, next, false, false
	case "--header":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || classifyHTTPHeader(value) == safety.R3 {
			return safety.R3, index, false, false
		}
		return safety.R2, next, false, false
	case "--output-document":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || isUnsafeOutputTarget(value) {
			return safety.R3, index, false, false
		}
		return safety.R2, next, true, false
	case "--directory-prefix", "--output-file", "--append-output",
		"--save-cookies", "--hsts-file", "--warc-file", "--warc-tempdir":
		value, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok || isUnsafeOutputTarget(value) {
			return safety.R3, index, false, false
		}
		return safety.R2, next, false, false
	case "--spider":
		if hasInlineValue {
			return safety.R3, index, false, false
		}
		return safety.R2, index, false, true
	}

	if hasExactWord(
		name,
		"--adjust-extension", "--auth-no-challenge", "--background", "--cache",
		"--content-on-error",
		"--continue", "--convert-file-only", "--convert-links", "--debug",
		"--dns-cache", "--force-directories", "--force-html",
		"--ftp-stmlf", "--help", "--hsts", "--https-only", "--if-modified-since",
		"--ignore-case", "--ignore-length", "--iri", "--keep-badhash",
		"--keep-session-cookies", "--no-cache", "--no-check-certificate",
		"--no-clobber", "--no-config", "--no-cookies", "--no-directories",
		"--no-glob",
		"--no-dns-cache", "--no-host-directories", "--no-http-keep-alive",
		"--no-hsts",
		"--no-if-modified-since", "--no-iri", "--no-passive-ftp",
		"--no-parent", "--no-proxy", "--no-remove-listing",
		"--no-use-server-timestamps", "--no-verbose", "--no-xattr",
		"--passive-ftp", "--protocol-directories", "--quiet", "--random-wait",
		"--relative",
		"--retry-connrefused", "--save-headers", "--server-response",
		"--show-progress", "--timestamping",
		"--use-server-timestamps", "--verbose", "--version", "--xattr",
	) {
		if hasInlineValue {
			return safety.R3, index, false, false
		}
		return safety.R2, index, false, false
	}

	if hasExactWord(
		name,
		"--accept", "--accept-regex", "--base", "--bind-address",
		"--bind-dns-address", "--ca-directory", "--ciphers",
		"--compression", "--connect-timeout", "--cut-dirs",
		"--dns-timeout", "--domains", "--exclude-directories",
		"--exclude-domains", "--ftp-password", "--ftp-user", "--http-password",
		"--http-user", "--https-proxy", "--include-directories",
		"--level", "--limit-rate", "--local-encoding", "--max-redirect",
		"--password", "--prefer-family", "--progress", "--proxy-password",
		"--proxy-user", "--quota", "--read-timeout", "--referer", "--reject",
		"--reject-regex", "--remote-encoding", "--report-speed",
		"--restrict-file-names", "--retry-on-http-error", "--secure-protocol",
		"--start-pos", "--timeout", "--tries", "--user", "--user-agent", "--wait",
		"--waitretry",
	) {
		_, next, ok := longOptionValue(args, index, inlineValue, hasInlineValue)
		if !ok {
			return safety.R3, index, false, false
		}
		return safety.R2, next, false, false
	}
	return safety.R3, index, false, false
}

//nolint:gocyclo // Short-option value consumption must remain explicit and fail closed.
func classifyWgetShortOption(args []string, index int) (safety.Risk, int, bool) {
	option := strings.TrimPrefix(args[index], "-")
	if option == "" {
		return safety.R3, index, false
	}
	if hasExactWord(option, "nc", "nd", "nH", "np", "nv") {
		return safety.R2, index, false
	}
	for pos := 0; pos < len(option); pos++ {
		switch option[pos] {
		case 'e', 'H', 'i', 'K', 'm', 'p', 'r':
			return safety.R3, index, false
		case 'O', 'P', 'o', 'a':
			target, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok || isUnsafeOutputTarget(target) {
				return safety.R3, index, false
			}
			return safety.R2, next, option[pos] == 'O'
		case 'A', 'B', 'D', 'I', 'l', 'Q', 'R', 't', 'T', 'U', 'w', 'X':
			_, next, ok := joinedOrNextOptionValue(option[pos+1:], args, index)
			if !ok {
				return safety.R3, index, false
			}
			return safety.R2, next, false
		default:
			if !strings.ContainsRune("46bcdEFhLNSqvVxk", rune(option[pos])) {
				return safety.R3, index, false
			}
		}
	}
	return safety.R2, index, false
}

func splitLongOption(arg string) (string, string, bool) {
	if equals := strings.IndexByte(arg, '='); equals >= 0 {
		return arg[:equals], arg[equals+1:], true
	}
	return arg, "", false
}

func longOptionValue(
	args []string,
	index int,
	inlineValue string,
	hasInlineValue bool,
) (string, int, bool) {
	if hasInlineValue {
		return inlineValue, index, inlineValue != ""
	}
	if index+1 >= len(args) || args[index+1] == "" {
		return "", index, false
	}
	return args[index+1], index + 1, true
}

func joinedOrNextOptionValue(joined string, args []string, index int) (string, int, bool) {
	if joined != "" {
		return joined, index, true
	}
	if index+1 >= len(args) {
		return "", index, false
	}
	return args[index+1], index + 1, args[index+1] != ""
}

func curlConfigDisabled(args []string) bool {
	if len(args) == 0 {
		return false
	}
	first := args[0]
	if first == "--disable" {
		return true
	}
	return len(first) > 1 && first[0] == '-' && first[1] == 'q'
}

func wgetConfigDisabled(args []string) bool {
	return len(args) > 0 && args[0] == "--no-config"
}

func isUnsafeOutputTarget(value string) bool {
	return value == "" || isSensitiveWriteTarget(value)
}

func classifyCurlWriteOut(value string) safety.Risk {
	if value == "" || strings.HasPrefix(value, "@") {
		return safety.R3
	}
	const outputDirective = "%output{"
	for remaining := value; ; {
		start := strings.Index(remaining, outputDirective)
		if start < 0 {
			return safety.R2
		}
		remaining = remaining[start+len(outputDirective):]
		end := strings.IndexByte(remaining, '}')
		if end < 0 {
			return safety.R3
		}
		target := strings.TrimPrefix(remaining[:end], ">>")
		if isUnsafeOutputTarget(target) {
			return safety.R3
		}
		remaining = remaining[end+1:]
	}
}

func classifyHTTPHeader(value string) safety.Risk {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "@") ||
		strings.ContainsAny(trimmed, "\r\n") {
		return safety.R3
	}
	name, method, found := strings.Cut(trimmed, ":")
	if !isHTTPMethodOverrideHeader(strings.TrimSpace(name)) {
		return safety.R2
	}
	if !found || !isReadOnlyHTTPMethod(strings.TrimSpace(method)) {
		return safety.R3
	}
	return safety.R2
}

func isHTTPMethodOverrideHeader(name string) bool {
	return strings.EqualFold(name, "X-HTTP-Method-Override") ||
		strings.EqualFold(name, "X-HTTP-Method") ||
		strings.EqualFold(name, "X-Method-Override")
}

func curlCookieReadsFile(value string) bool {
	trimmed := strings.TrimSpace(value)
	return trimmed == "" || strings.HasPrefix(trimmed, "@") || !strings.Contains(trimmed, "=")
}

func curlQueryReadsFile(value string) bool {
	trimmed := strings.TrimSpace(value)
	if trimmed == "" || strings.HasPrefix(trimmed, "@") {
		return true
	}
	at := strings.IndexByte(trimmed, '@')
	equals := strings.IndexByte(trimmed, '=')
	return at >= 0 && (equals < 0 || at < equals)
}

func isSafeTransferURL(value string, allowedSchemes ...string) bool {
	if value == "" {
		return false
	}
	parsed, err := url.Parse(value)
	if err != nil {
		return isHostPortShorthand(value)
	}
	if strings.ContainsAny(value, "{}[]") || strings.ContainsAny(parsed.Path, "*?") {
		return false
	}
	if parsed.Scheme == "" {
		return true
	}
	for _, allowed := range allowedSchemes {
		if strings.EqualFold(parsed.Scheme, allowed) {
			return true
		}
	}
	return isHostPortShorthand(value)
}

func isHostPortShorthand(value string) bool {
	colon := strings.IndexByte(value, ':')
	if colon <= 0 || strings.Contains(value[:colon], "/") {
		return false
	}
	host := value[:colon]
	if !strings.EqualFold(host, "localhost") && !strings.Contains(host, ".") {
		return false
	}
	remainder := value[colon+1:]
	if slash := strings.IndexByte(remainder, '/'); slash >= 0 {
		remainder = remainder[:slash]
	}
	if remainder == "" {
		return false
	}
	for _, char := range remainder {
		if char < '0' || char > '9' {
			return false
		}
	}
	parsed, err := url.Parse("http://" + value)
	return err == nil && parsed.Host != ""
}

func hasSensitiveDownloadName(rawURL string) bool {
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return true
	}
	name := path.Base(strings.ReplaceAll(parsed.Path, "\\", "/"))
	if name == "." || name == "/" || name == "" {
		return false
	}
	return isSensitiveWriteTarget(name)
}

func isReadOnlyHTTPMethod(value string) bool {
	switch strings.ToUpper(value) {
	case "GET", "HEAD", "OPTIONS", "TRACE":
		return true
	default:
		return false
	}
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

func hasExactWord(word string, candidates ...string) bool {
	for _, candidate := range candidates {
		if word == candidate {
			return true
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
