package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/JiangHe12/opskit-core/apperrors"
)

func TestErrorJSON(t *testing.T) {
	cases := []struct {
		name string
		args []string
	}{
		{name: "short output flag", args: []string{"-o", "json", "ctx", "use"}},
		{name: "long output flag", args: []string{"--output", "json", "ctx", "use"}},
		{name: "long output assignment", args: []string{"ctx", "use", "--output=json"}},
		{name: "short output assignment", args: []string{"ctx", "use", "-o=json"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var out bytes.Buffer
			writeExecutionError(&out, tc.args, apperrors.New(apperrors.CodeUsageError, "ctx use requires 1 argument(s)", nil))

			var envelope struct {
				APIVersion string              `json:"apiVersion"`
				Kind       string              `json:"kind"`
				Success    bool                `json:"success"`
				Error      *apperrors.AppError `json:"error"`
			}
			if err := json.Unmarshal(out.Bytes(), &envelope); err != nil {
				t.Fatalf("error output is not JSON: %v; output=%q", err, out.String())
			}
			if envelope.APIVersion != "srvgov.io/v1" || envelope.Kind != "Error" || envelope.Success {
				t.Fatalf("envelope = %+v", envelope)
			}
			if envelope.Error == nil || envelope.Error.Code != apperrors.CodeUsageError || envelope.Error.Message != "ctx use requires 1 argument(s)" {
				t.Fatalf("error = %+v", envelope.Error)
			}
		})
	}
}

func TestErrorTextWhenOutputIsNotJSON(t *testing.T) {
	var out bytes.Buffer
	writeExecutionError(&out, []string{"ctx", "use"}, errors.New("plain error"))

	if got := out.String(); got != "plain error\n" {
		t.Fatalf("error output = %q", got)
	}
}

func TestOutputFlagFromArgs(t *testing.T) {
	cases := []struct {
		name string
		args []string
		want string
	}{
		{name: "short", args: []string{"-o", "json"}, want: "json"},
		{name: "long", args: []string{"--output", "plain"}, want: "plain"},
		{name: "long assignment", args: []string{"--output=json"}, want: "json"},
		{name: "short assignment", args: []string{"-o=json"}, want: "json"},
		{name: "missing value", args: []string{"-o"}, want: ""},
		{name: "absent", args: []string{"ctx", "list"}, want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := outputFlagFromArgs(tc.args); got != tc.want {
				t.Fatalf("outputFlagFromArgs(%q) = %q, want %q", strings.Join(tc.args, " "), got, tc.want)
			}
		})
	}
}
