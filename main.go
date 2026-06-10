package main

import (
	"fmt"
	"os"

	"github.com/JiangHe12/opskit-core/apperrors"

	"github.com/JiangHe12/srvgov-cli/cmd"
)

func main() {
	cmd.SetSkillFS(skillEmbedFS)
	err := cmd.NewRootCmd().Execute()
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
	}
	os.Exit(apperrors.ExitCode(err))
}
