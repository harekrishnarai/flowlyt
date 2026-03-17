package rules_test

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

func fixtureDir() string {
	_, filename, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(filename), "..", "..", "testdata", "workflows")
}

func loadFixture(t *testing.T, name string) parser.WorkflowFile {
	t.Helper()
	path := filepath.Join(fixtureDir(), name)
	wfs, err := parser.LoadSingleWorkflow(path)
	if err != nil {
		t.Fatalf("failed to load fixture %s: %v", name, err)
	}
	if len(wfs) == 0 {
		t.Fatalf("no workflows loaded from %s", name)
	}
	return wfs[0]
}

func TestFixture_SafeEnvVarIndirection_NoInjectionFinding(t *testing.T) {
	wf := loadFixture(t, "safe_env_var_indirection.yml")
	engine := rules.NewRuleEngine(nil)
	findings := engine.ExecuteRules(wf, rules.StandardRules())
	for _, f := range findings {
		if f.RuleID == "INJECTION_VULNERABILITY" {
			t.Errorf("false positive INJECTION_VULNERABILITY on safe env-var indirection fixture: %s", f.Evidence)
		}
	}
}

func TestFixture_SafePRTLabeler_NoCriticalFindings(t *testing.T) {
	wf := loadFixture(t, "safe_prt_labeler.yml")
	engine := rules.NewRuleEngine(nil)
	findings := engine.ExecuteRules(wf, rules.StandardRules())
	for _, f := range findings {
		if f.Severity == rules.Critical {
			t.Errorf("false positive CRITICAL finding on safe PRT labeler fixture: %s / %s", f.RuleID, f.Evidence)
		}
	}
}

func TestFixture_VulnWorkflowRunArtifact_HasFindings(t *testing.T) {
	wf := loadFixture(t, "vuln_workflow_run_artifact.yml")
	findings := rules.CheckWorkflowRunTrust(wf)
	if len(findings) == 0 {
		t.Error("expected findings for vuln_workflow_run_artifact fixture, got none")
	}
}

func TestFixture_VulnMemdump_HasCriticalFinding(t *testing.T) {
	wf := loadFixture(t, "vuln_memdump.yml")
	findings := rules.CheckInjectionVulnerabilities(wf)
	found := false
	for _, f := range findings {
		if f.RuleID == "MEMDUMP_EXFILTRATION_SIGNATURE" {
			found = true
		}
	}
	if !found {
		t.Errorf("expected MEMDUMP_EXFILTRATION_SIGNATURE for vuln_memdump fixture, got findings: %v", findings)
	}
}
