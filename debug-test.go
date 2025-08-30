package main

import (
	"fmt"
	"log"
	"os"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"gopkg.in/yaml.v3"
)

func testDebug() {
	// Parse the simple test file
	content, err := os.ReadFile("test/simple-test.yml")
	if err != nil {
		log.Fatal(err)
	}

	var workflow parser.Workflow
	if err := yaml.Unmarshal(content, &workflow); err != nil {
		log.Fatal(err)
	}

	workflowFile := parser.WorkflowFile{
		Path:     "test/simple-test.yml",
		Name:     "simple-test.yml",
		Content:  content,
		Workflow: workflow,
	}

	// Print workflow structure for debugging
	fmt.Printf("Jobs: %d\n", len(workflow.Jobs))
	for jobName, job := range workflow.Jobs {
		fmt.Printf("Job %s has %d steps\n", jobName, len(job.Steps))
		for i, step := range job.Steps {
			fmt.Printf("  Step %d: Name='%s', Run='%s'\n", i, step.Name, step.Run)
		}
	}

	// Test all rules
	allRules := rules.StandardRules()
	for _, rule := range allRules {
		if rule.ID == "DANGEROUS_WRITE_OPERATION" {
			findings := rule.Check(workflowFile)
			fmt.Printf("Rule %s found %d findings\n", rule.ID, len(findings))
		}
	}
}
