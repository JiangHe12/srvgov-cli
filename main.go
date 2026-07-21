package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/JiangHe12/opskit-core/v2/apperrors"

	"github.com/JiangHe12/srvgov-cli/cmd"
)

var (
	version = "dev"
	commit  = "unknown"
	built   = "unknown"
)

func main() {
	cmd.SetVersionInfo(version, commit, built)
	cmd.SetSkillFS(skillEmbedFS)
	err := cmd.NewRootCmd().Execute()
	if err != nil {
		writeExecutionError(os.Stderr, os.Args[1:], err)
	}
	os.Exit(apperrors.ExitCode(err))
}

func writeExecutionError(w io.Writer, args []string, err error) {
	if strings.EqualFold(outputFlagFromArgs(args), "json") {
		_ = apperrors.WriteJSON(w, err)
		return
	}
	_, _ = fmt.Fprintln(w, err)
}

func outputFlagFromArgs(args []string) string {
	for i, arg := range args {
		if (arg == "-o" || arg == "--output") && i+1 < len(args) {
			return args[i+1]
		}
		if strings.HasPrefix(arg, "--output=") {
			return strings.TrimPrefix(arg, "--output=")
		}
		if strings.HasPrefix(arg, "-o=") {
			return strings.TrimPrefix(arg, "-o=")
		}
	}
	return ""
}
