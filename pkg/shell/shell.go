package shell

import (
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
	"mvdan.cc/sh/v3/syntax"
)

// Analyzer represents a shell script analyzer
type Analyzer struct {
	// Custom rules to apply in addition to defaults
	CustomRules []rules.Rule
}

// NewAnalyzer creates a new shell script analyzer
func NewAnalyzer() *Analyzer {
	return &Analyzer{
		CustomRules: []rules.Rule{},
	}
}

// AddCustomRule adds a custom rule to the analyzer
func (a *Analyzer) AddCustomRule(rule rules.Rule) {
	a.CustomRules = append(a.CustomRules, rule)
}

// Analyze analyzes shell commands in workflow steps
func (a *Analyzer) Analyze(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// Add default shell analysis rules
	shellAnalysisRules := []rules.Rule{
		{
			ID:          "SHELL_EVAL_USAGE",
			Name:        "Dangerous eval Usage",
			Description: "Detects usage of eval in shell commands, which can be dangerous",
			Severity:    rules.High,
			Category:    rules.ShellObfuscation,
			Check:       a.checkEvalUsage,
		},
		{
			ID:          "SHELL_OBFUSCATION",
			Name:        "Shell Command Obfuscation",
			Description: "Detects attempts to obfuscate shell commands",
			Severity:    rules.Critical,
			Category:    rules.ShellObfuscation,
			Check:       a.checkObfuscation,
		},
		{
			ID:          "DANGEROUS_COMMAND",
			Name:        "Dangerous Shell Command",
			Description: "Detects potentially dangerous shell commands",
			Severity:    rules.High,
			Category:    rules.MaliciousPattern,
			Check:       a.checkDangerousCommands,
		},
	}

	// Apply all shell analysis rules
	for _, rule := range shellAnalysisRules {
		findings = append(findings, rule.Check(workflow)...)
	}

	// Apply any custom rules
	for _, rule := range a.CustomRules {
		findings = append(findings, rule.Check(workflow)...)
	}

	return findings
}

// checkEvalUsage checks for eval usage in shell commands
func (a *Analyzer) checkEvalUsage(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	evalRegex := regexp.MustCompile(`(?:^|\s+)eval\s+`)

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if evalRegex.MatchString(step.Run) {
				findings = append(findings, rules.Finding{
					RuleID:      "SHELL_EVAL_USAGE",
					RuleName:    "Dangerous eval Usage",
					Description: "Use of eval in shell scripts can be dangerous as it executes dynamic code",
					Severity:    rules.High,
					Category:    rules.ShellObfuscation,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    step.Run,
					Remediation: "Avoid using eval. Consider safer alternatives for your specific use case.",
				})
			}
		}
	}

	return findings
}

// checkObfuscation checks for common shell obfuscation techniques
func (a *Analyzer) checkObfuscation(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// Define patterns for shell obfuscation
	obfuscationPatterns := []*regexp.Regexp{
		// Environment variable or command substitution obfuscation with base64
		regexp.MustCompile(`echo\s+.*\s*\|\s*base64\s+(-d|--decode)`),
		regexp.MustCompile(`\$\(echo\s+.*\s*\|\s*base64\s+(-d|--decode)\)`),
		// Base64 encoded string being decoded and executed
		regexp.MustCompile(`.*\|\s*base64\s+(-d|--decode)\s*\|\s*(bash|sh)`),
		// String concatenation to hide commands
		regexp.MustCompile(`[a-zA-Z]+="[^"]+"\s*;\s*[a-zA-Z]+="[^"]+"\s*;\s*\$[a-zA-Z]+\$[a-zA-Z]+`),
		// Character by character command construction - avoid backreferences
		regexp.MustCompile(`[a-z]{1,2}=['"][^'"]+['"];[a-z]{1,2}=['"][^'"]+['"];.*\$[a-z]{1,2}\$[a-z]{1,2}`),
		// Hex or octal escape sequences
		regexp.MustCompile(`\\x[0-9a-fA-F]{2}|\\[0-7]{3}`),
		// Commands hidden in variables with indirect reference - avoid backreferences
		regexp.MustCompile(`[a-zA-Z_][a-zA-Z0-9_]*=['"][^'"]+['"]?\s*;\s*eval\s+\$[a-zA-Z_][a-zA-Z0-9_]*`),
		// IFS manipulation - avoid backreferences
		regexp.MustCompile(`IFS=['"]?[^'";\s]+['"]?\s*;\s*[a-zA-Z_][a-zA-Z0-9_]*=['"][^'"]+['"]`),
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			for _, pattern := range obfuscationPatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, rules.Finding{
						RuleID:      "SHELL_OBFUSCATION",
						RuleName:    "Shell Command Obfuscation",
						Description: "Shell command appears to use obfuscation techniques to hide its true purpose",
						Severity:    rules.Critical,
						Category:    rules.ShellObfuscation,
						FilePath:    workflow.Path,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:    step.Run,
						Remediation: "Rewrite the command to be clear and transparent. Avoid techniques that obscure the command's intent.",
					})
					break // Only report once per step for this rule
				}
			}
		}
	}

	return findings
}

// checkDangerousCommands checks for potentially dangerous shell commands
func (a *Analyzer) checkDangerousCommands(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// List of potentially dangerous commands
	dangerousCommands := []string{
		"rm -rf /", "chmod 777", "dd if=/dev/zero", "dd if=/dev/random",
		"echo.*>.*/etc/", "mv.*>.*/etc/", ">.*\\.ssh/authorized_keys",
		"wget.*-O.*\\|\\s*bash", "curl.*\\|\\s*bash",
	}

	// Create a regex that matches any of the dangerous commands
	dangerousRegex := regexp.MustCompile(strings.Join(dangerousCommands, "|"))

	for jobName, job := range workflow.Workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			if dangerousRegex.MatchString(step.Run) {
				findings = append(findings, rules.Finding{
					RuleID:      "DANGEROUS_COMMAND",
					RuleName:    "Dangerous Shell Command",
					Description: "Command contains potentially dangerous or destructive operations",
					Severity:    rules.High,
					Category:    rules.MaliciousPattern,
					FilePath:    workflow.Path,
					JobName:     jobName,
					StepName:    step.Name,
					Evidence:    step.Run,
					Remediation: "Review and replace with a safer alternative. If necessary, scope the command more precisely.",
				})
			}
		}
	}

	return findings
}

// Parse parses a shell script and returns a syntax tree
func Parse(script string) (*syntax.File, error) {
	parser := syntax.NewParser()
	file, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		return nil, err
	}
	return file, nil
}
