package main

import (
	"os"
	"path/filepath"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestWorkflowYAMLSyntax(t *testing.T) {
	paths, err := filepath.Glob(filepath.Join(".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("Glob() error = %v", err)
	}
	if len(paths) != 3 {
		t.Fatalf("workflow count = %d, want 3", len(paths))
	}
	for _, path := range paths {
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile(%s) error = %v", path, err)
		}
		var document yaml.Node
		if err := yaml.Unmarshal(data, &document); err != nil {
			t.Fatalf("workflow %s is invalid YAML: %v", path, err)
		}
		if len(document.Content) != 1 || document.Content[0].Kind != yaml.MappingNode {
			t.Fatalf("workflow %s root is not a mapping", path)
		}
	}
}
