package gitlab

import (
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// GitLabRules returns GitLab CI/CD specific security rules
func GitLabRules() []rules.Rule {
	return []rules.Rule{
		{
			ID:          "GITLAB_INSECURE_IMAGE",
			Name:        "Insecure Docker Image",
			Description: "Using latest tag or unverified Docker images",
			Severity:    rules.High,
			Category:    rules.SupplyChain,
			Platform:    rules.PlatformGitLab, // GitLab CI specific
			Check:       checkInsecureDockerImage,
		},
		{
			ID:          "GITLAB_SCRIPT_INJECTION",
			Name:        "Script Injection Vulnerability",
			Description: "User input directly used in script commands without sanitization",
			Severity:    rules.Critical,
			Category:    rules.InjectionAttack,
			Platform:    rules.PlatformGitLab, // GitLab CI specific
			Check:       checkScriptInjection,
		},
		{
			ID:          "GITLAB_EXPOSED_VARIABLES",
			Name:        "Exposed Sensitive Variables",
			Description: "Potentially sensitive variables exposed in pipeline configuration",
			Severity:    rules.High,
			Category:    rules.SecretsExposure,
			Platform:    rules.PlatformGitLab, // GitLab CI specific
			Check:       checkExposedVariables,
		},
		{
			ID:          "GITLAB_UNRESTRICTED_RULES",
			Name:        "Unrestricted Pipeline Rules",
			Description: "Pipeline runs without proper branch or tag restrictions",
			Severity:    rules.Medium,
			Category:    rules.AccessControl,
			Platform:    rules.PlatformGitLab, // GitLab CI specific
			Check:       checkUnrestrictedRules,
		},
		{
			ID:          "GITLAB_PRIVILEGED_SERVICES",
			Name:        "Privileged Docker Services",
			Description: "Using privileged Docker services which can be dangerous",
			Severity:    rules.High,
			Category:    rules.PrivilegeEscalation,
			Platform:    rules.PlatformGitLab, // GitLab CI specific
			Check:       checkPrivilegedServices,
		},
		{
			ID:          "GITLAB_INSECURE_ARTIFACTS",
			Name:        "Insecure Artifact Configuration",
			Description: "Artifacts configured without proper expiration or access controls",
			Severity:    rules.Medium,
			Category:    rules.DataExposure,
			Platform:    rules.PlatformGitLab, // GitLab CI specific
			Check:       checkInsecureArtifacts,
		},
	}
}

func checkInsecureDockerImage(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// Check for insecure image patterns
	insecurePatterns := []*regexp.Regexp{
		regexp.MustCompile(`:\s*latest\s*$`), // :latest tag
		regexp.MustCompile(`^[^/]+$`),        // no registry specified
		regexp.MustCompile(`^[^/]+:[^/]+$`),  // docker hub without explicit registry
	}

	contentStr := string(workflow.Content)
	lines := strings.Split(contentStr, "\n")

	for lineNum, line := range lines {
		if strings.Contains(line, "image:") {
			for _, pattern := range insecurePatterns {
				if pattern.MatchString(line) {
					findings = append(findings, rules.Finding{
						RuleID:      "GITLAB_INSECURE_IMAGE",
						RuleName:    "Insecure Docker Image",
						Description: "Using latest tag or unverified Docker images can lead to supply chain attacks",
						Severity:    rules.High,
						Category:    rules.SupplyChain,
						FilePath:    workflow.Path,
						Evidence:    strings.TrimSpace(line),
						Remediation: "Use specific image tags and trusted registries",
						LineNumber:  lineNum + 1,
					})
					break
				}
			}
		}
	}

	return findings
}

func checkScriptInjection(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// Check for potential script injection patterns
	injectionPatterns := []*regexp.Regexp{
		regexp.MustCompile(`\$\{?CI_COMMIT_MESSAGE\}?`),      // Commit message injection
		regexp.MustCompile(`\$\{?CI_COMMIT_TITLE\}?`),        // Commit title injection
		regexp.MustCompile(`\$\{?CI_COMMIT_AUTHOR\}?`),       // Author injection
		regexp.MustCompile(`\$\{?CI_MERGE_REQUEST_TITLE\}?`), // MR title injection
		regexp.MustCompile(`\$\{?CI_MERGE_REQUEST_DESC\}?`),  // MR description injection
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for stepIndex, step := range job.Steps {
			if step.Run != "" {
				for _, pattern := range injectionPatterns {
					if pattern.MatchString(step.Run) {
						findings = append(findings, rules.Finding{
							RuleID:      "GITLAB_SCRIPT_INJECTION",
							RuleName:    "Script Injection Vulnerability",
							Description: "User-controlled input used directly in script commands without sanitization",
							Severity:    rules.Critical,
							Category:    rules.InjectionAttack,
							FilePath:    workflow.Path,
							JobName:     jobName,
							StepName:    step.Name,
							Evidence:    step.Run,
							Remediation: "Sanitize user input or use GitLab's built-in variable validation",
							LineNumber:  stepIndex + 1,
						})
					}
				}
			}
		}
	}

	return findings
}

func checkExposedVariables(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	// Sensitive variable patterns
	sensitivePatterns := []*regexp.Regexp{
		regexp.MustCompile(`(?i)(password|passwd|pwd)`),
		regexp.MustCompile(`(?i)(secret|token|key)`),
		regexp.MustCompile(`(?i)(api[_-]?key)`),
		regexp.MustCompile(`(?i)(private[_-]?key)`),
		regexp.MustCompile(`(?i)(access[_-]?token)`),
	}

	contentStr := string(workflow.Content)
	lines := strings.Split(contentStr, "\n")

	for lineNum, line := range lines {
		if strings.Contains(line, "variables:") || strings.Contains(line, ":") {
			for _, pattern := range sensitivePatterns {
				if pattern.MatchString(line) && !strings.Contains(line, "$") {
					findings = append(findings, rules.Finding{
						RuleID:      "GITLAB_EXPOSED_VARIABLES",
						RuleName:    "Exposed Sensitive Variables",
						Description: "Potentially sensitive variables exposed in pipeline configuration",
						Severity:    rules.High,
						Category:    rules.SecretsExposure,
						FilePath:    workflow.Path,
						Evidence:    strings.TrimSpace(line),
						Remediation: "Use GitLab CI/CD variables or secrets management",
						LineNumber:  lineNum + 1,
					})
				}
			}
		}
	}

	return findings
}

func checkUnrestrictedRules(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	contentStr := string(workflow.Content)

	// Check if there are no rules, only, or except restrictions
	hasRestrictions := strings.Contains(contentStr, "rules:") ||
		strings.Contains(contentStr, "only:") ||
		strings.Contains(contentStr, "except:")

	if !hasRestrictions {
		findings = append(findings, rules.Finding{
			RuleID:      "GITLAB_UNRESTRICTED_RULES",
			RuleName:    "Unrestricted Pipeline Rules",
			Description: "Pipeline runs without proper branch, tag, or merge request restrictions",
			Severity:    rules.Medium,
			Category:    rules.AccessControl,
			FilePath:    workflow.Path,
			Evidence:    "No rules, only, or except restrictions found",
			Remediation: "Add rules to restrict when jobs run (e.g., only on specific branches)",
			LineNumber:  1,
		})
	}

	return findings
}

func checkPrivilegedServices(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	contentStr := string(workflow.Content)
	lines := strings.Split(contentStr, "\n")

	privilegedPatterns := []*regexp.Regexp{
		regexp.MustCompile(`privileged:\s*true`),
		regexp.MustCompile(`--privileged`),
		regexp.MustCompile(`docker:.*dind`), // Docker in Docker
	}

	for lineNum, line := range lines {
		for _, pattern := range privilegedPatterns {
			if pattern.MatchString(line) {
				findings = append(findings, rules.Finding{
					RuleID:      "GITLAB_PRIVILEGED_SERVICES",
					RuleName:    "Privileged Docker Services",
					Description: "Using privileged Docker services increases attack surface",
					Severity:    rules.High,
					Category:    rules.PrivilegeEscalation,
					FilePath:    workflow.Path,
					Evidence:    strings.TrimSpace(line),
					Remediation: "Avoid privileged mode unless absolutely necessary",
					LineNumber:  lineNum + 1,
				})
			}
		}
	}

	return findings
}

func checkInsecureArtifacts(workflow parser.WorkflowFile) []rules.Finding {
	var findings []rules.Finding

	contentStr := string(workflow.Content)
	lines := strings.Split(contentStr, "\n")

	hasExpiration := false

	for lineNum, line := range lines {
		if strings.Contains(line, "artifacts:") {
			hasExpiration = false

			// Check next few lines for expiration
			for i := lineNum; i < len(lines) && i < lineNum+10; i++ {
				if strings.Contains(lines[i], "expire_in:") {
					hasExpiration = true
					break
				}
				// Stop if we hit another top-level key
				if i > lineNum && !strings.HasPrefix(lines[i], " ") && strings.Contains(lines[i], ":") {
					break
				}
			}

			if !hasExpiration {
				findings = append(findings, rules.Finding{
					RuleID:      "GITLAB_INSECURE_ARTIFACTS",
					RuleName:    "Insecure Artifact Configuration",
					Description: "Artifacts configured without proper expiration time",
					Severity:    rules.Medium,
					Category:    rules.DataExposure,
					FilePath:    workflow.Path,
					Evidence:    strings.TrimSpace(line),
					Remediation: "Set expire_in for artifacts to prevent indefinite storage",
					LineNumber:  lineNum + 1,
				})
			}
		}
	}

	return findings
}
