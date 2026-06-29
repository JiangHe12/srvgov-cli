package cmd

import (
	"encoding/json"
	"testing"
)

type jsonListData[T any] struct {
	Items     []T  `json:"items"`
	Total     int  `json:"total"`
	Page      int  `json:"page"`
	PageSize  int  `json:"pageSize"`
	Truncated bool `json:"truncated"`
}

func decodeJSONData[T any](t *testing.T, output, wantKind string) T {
	t.Helper()
	var env struct {
		APIVersion string `json:"apiVersion"`
		Kind       string `json:"kind"`
		Success    bool   `json:"success"`
		Data       T      `json:"data"`
	}
	if err := json.Unmarshal([]byte(output), &env); err != nil {
		t.Fatalf("Unmarshal(envelope) error = %v; output = %q", err, output)
	}
	assertJSONEnvelope(t, env.APIVersion, env.Kind, env.Success, wantKind)
	return env.Data
}

func decodeJSONList[T any](t *testing.T, output, wantKind string) jsonListData[T] {
	t.Helper()
	return decodeJSONData[jsonListData[T]](t, output, wantKind)
}

func decodeJSONRawData(t *testing.T, output, wantKind string) json.RawMessage {
	t.Helper()
	return decodeJSONData[json.RawMessage](t, output, wantKind)
}

func assertJSONEnvelope(t *testing.T, apiVersion, kind string, success bool, wantKind string) {
	t.Helper()
	if apiVersion != "srvgov-cli.io/v1" || kind != wantKind || !success {
		t.Fatalf("envelope = apiVersion=%q kind=%q success=%t, want apiVersion=srvgov-cli.io/v1 kind=%s success=true", apiVersion, kind, success, wantKind)
	}
}
