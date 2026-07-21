package cmd

import (
	"errors"
	"io"
	"testing"

	"github.com/JiangHe12/opskit-core/v2/apperrors"
)

type brokenOutputWriter struct{}

func (brokenOutputWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestCommandOutputWriteErrorsPropagate(t *testing.T) {
	for _, testCase := range []struct {
		name string
		args []string
	}{
		{name: "info", args: []string{"version"}},
		{name: "table", args: []string{"capabilities"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			f := &cliFlags{
				Output:          "table",
				trustedOperator: "test@localhost",
			}
			root := newRootCmdWith(f)
			root.SetOut(brokenOutputWriter{})
			root.SetErr(io.Discard)
			root.SetArgs(testCase.args)
			err := root.Execute()
			if !errors.Is(err, io.ErrClosedPipe) ||
				apperrors.AsAppError(err).Code != apperrors.CodeLocalIOError {
				t.Fatalf("Execute() error = %v, want LOCAL_IO_ERROR wrapping closed pipe", err)
			}
		})
	}
}
