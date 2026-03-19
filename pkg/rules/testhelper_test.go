/*
Copyright 2025 Hare Krishna Rai

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package rules_test

import (
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// makeWorkflow parses inline YAML into a WorkflowFile ready for rule checks.
func makeWorkflow(t *testing.T, yamlContent string) parser.WorkflowFile {
	t.Helper()
	wf := parser.WorkflowFile{
		Path:    "test.yml",
		Name:    "test.yml",
		Content: []byte(yamlContent),
	}
	if err := parser.ParseWorkflowYAML(&wf); err != nil {
		t.Fatalf("makeWorkflow: failed to parse YAML: %v", err)
	}
	return wf
}

// findRule returns the Rule with the given ID from StandardRules or fatally fails.
func findRule(t *testing.T, id string) rules.Rule {
	t.Helper()
	for _, r := range rules.StandardRules() {
		if r.ID == id {
			return r
		}
	}
	t.Fatalf("findRule: rule %q not found in StandardRules", id)
	return rules.Rule{}
}
