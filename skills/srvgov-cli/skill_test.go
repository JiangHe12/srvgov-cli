// Package skilltest validates the srvgov-cli AI Skill against the Cobra surface.
package skilltest

import (
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	cmdpkg "github.com/JiangHe12/srvgov-cli/cmd"
)

func loadSkillBody(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(file), "SKILL.md"))
	if err != nil {
		t.Fatalf("read SKILL.md: %v", err)
	}
	return strings.ReplaceAll(string(data), "\r\n", "\n")
}

func TestSkillFrontmatterAndGovernance(t *testing.T) {
	body := loadSkillBody(t)
	for _, want := range []string{
		"---\nname: srvgov-cli",
		"description: Governed remote server command execution",
		"Always use `-o json`",
		"R0",
		"R1",
		"R2",
		"R3",
		"`--reason`",
		"`--yes`",
		"`--ticket`",
		"`--allow-destructive`",
		"Never auto-supply `--ticket`",
		"`exec --dry-run`",
		"never model guesses",
		"`capabilities`",
		"`audit verify`",
		"`audit prune`",
		"`ctx role`",
		"`ctx export`",
		"`ctx import`",
		"`ctx migrate-credentials`",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("SKILL.md missing %q", want)
		}
	}
}

func TestSkillCommandsAndFlagsExist(t *testing.T) {
	body := loadSkillBody(t)
	root := cmdpkg.NewRootCmd()
	commands := collectCommandPaths(root)
	for _, command := range []string{
		"version",
		"capabilities",
		"doctor",
		"install",
		"exec",
		"audit query",
		"audit verify",
		"audit prune",
		"ctx set",
		"ctx use",
		"ctx list",
		"ctx current",
		"ctx delete",
		"ctx role",
		"ctx export",
		"ctx import",
		"ctx migrate-credentials",
	} {
		if !commands[command] {
			t.Errorf("command %q is missing from Cobra tree", command)
		}
	}

	flags := collectFlags(root)
	for _, flag := range markdownFlags(body) {
		if !flags[flag] {
			t.Errorf("SKILL.md references undefined flag %q", flag)
		}
	}
}

func collectCommandPaths(root *cobra.Command) map[string]bool {
	out := map[string]bool{}
	var walk func(*cobra.Command, []string)
	walk = func(command *cobra.Command, parts []string) {
		if len(parts) > 0 {
			out[strings.Join(parts, " ")] = true
		}
		for _, child := range command.Commands() {
			walk(child, append(parts, child.Name()))
		}
	}
	walk(root, nil)
	return out
}

func collectFlags(root *cobra.Command) map[string]bool {
	out := map[string]bool{}
	var walk func(*cobra.Command)
	walk = func(command *cobra.Command) {
		command.Flags().VisitAll(func(flag *pflag.Flag) {
			out["--"+flag.Name] = true
			if flag.Shorthand != "" {
				out["-"+flag.Shorthand] = true
			}
		})
		command.PersistentFlags().VisitAll(func(flag *pflag.Flag) {
			out["--"+flag.Name] = true
			if flag.Shorthand != "" {
				out["-"+flag.Shorthand] = true
			}
		})
		for _, child := range command.Commands() {
			walk(child)
		}
	}
	walk(root)
	return out
}

func markdownFlags(body string) []string {
	re := regexp.MustCompile(`--[a-z][a-z0-9-]*[a-z0-9]|-o`)
	matches := re.FindAllString(body, -1)
	seen := map[string]bool{}
	out := make([]string, 0, len(matches))
	for _, match := range matches {
		if !seen[match] {
			seen[match] = true
			out = append(out, match)
		}
	}
	return out
}
