package astutil

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/analysis/ast"
	"github.com/harekrishnarai/flowlyt/pkg/constants"
	"github.com/harekrishnarai/flowlyt/pkg/parser"
	"github.com/harekrishnarai/flowlyt/pkg/rules"
)

// Insight captures parsed AST information for downstream enrichment.
type Insight struct {
	Workflow     *ast.WorkflowAST
	Reachability map[string]bool
	DataFlows    []*ast.DataFlow
	Triggers     []string
	JobRunners   map[string]string
}

// Stats tracks AST post-processing effects for reporting.
type Stats struct {
	SuppressedReachability int
	GeneratedDataFlows     int
}

// CollectInsights parses workflow files into AST insights shared across reachability
// filtering, metadata enrichment, and advanced data-flow findings.
func CollectInsights(workflowFiles []parser.WorkflowFile) map[string]*Insight {
	insights := make(map[string]*Insight)

	for _, workflowFile := range workflowFiles {
		analyzer := ast.NewASTAnalyzer()
		workflowAST, err := analyzer.ParseWorkflow(workflowFile.Content)
		if err != nil || workflowAST == nil {
			continue
		}

		workflowAST.Platform = detectPlatformFromPath(workflowFile.Path)

		result, err := analyzer.AnalyzeWorkflowComprehensive(workflowAST)
		if err != nil || result == nil {
			continue
		}

		jobRunners := make(map[string]string)
		for jobID, jobNode := range workflowAST.Jobs {
			if jobNode.RunsOn != "" {
				jobRunners[strings.ToLower(jobID)] = jobNode.RunsOn
				if jobNode.Name != "" {
					jobRunners[strings.ToLower(jobNode.Name)] = jobNode.RunsOn
				}
			}
		}

		triggers := make([]string, 0, len(workflowAST.Triggers))
		for _, trigger := range workflowAST.Triggers {
			if trigger.Event != "" {
				triggers = append(triggers, trigger.Event)
			}
		}

		key := normalizePath(workflowFile.Path)
		insights[key] = &Insight{
			Workflow:     workflowAST,
			Reachability: result.ReachabilityAnalysis,
			DataFlows:    result.DataFlows,
			Triggers:     triggers,
			JobRunners:   jobRunners,
		}
	}

	return insights
}

// FilterFindingsByReachability removes findings tied to unreachable jobs or steps.
func FilterFindingsByReachability(insights map[string]*Insight, findings []rules.Finding) ([]rules.Finding, int) {
	if len(insights) == 0 || len(findings) == 0 {
		return findings, 0
	}

	filtered := make([]rules.Finding, 0, len(findings))
	suppressed := 0

	for _, finding := range findings {
		key := normalizePath(finding.FilePath)
		insight, exists := insights[key]
		if !exists {
			filtered = append(filtered, finding)
			continue
		}

		reachability := insight.Reachability
		if reachability == nil || findingReachableInAST(finding, insight.Workflow, reachability) {
			filtered = append(filtered, finding)
			continue
		}

		suppressed++
	}

	return filtered, suppressed
}

// EnrichFindingsWithMetadata decorates findings with runner and trigger context where available.
func EnrichFindingsWithMetadata(findings []rules.Finding, insights map[string]*Insight) []rules.Finding {
	for i := range findings {
		key := normalizePath(findings[i].FilePath)
		insight, exists := insights[key]
		if !exists {
			continue
		}

		if findings[i].Trigger == "" && len(insight.Triggers) > 0 {
			findings[i].Trigger = insight.Triggers[0]
		}

		if findings[i].RunnerType == "" && findings[i].JobName != "" {
			if runner := lookupRunner(insight.JobRunners, findings[i].JobName); runner != "" {
				findings[i].RunnerType = runner
			}
		}
	}
	return findings
}

// GenerateDataFlowFindings converts AST taint analysis into actionable findings.
func GenerateDataFlowFindings(insights map[string]*Insight) []rules.Finding {
	var all []rules.Finding
	seen := make(map[string]struct{})

	for filePath, insight := range insights {
		if len(insight.DataFlows) == 0 {
			continue
		}

		for _, flow := range insight.DataFlows {
			if flow == nil || !flow.Tainted {
				continue
			}

			severity, ok := mapFlowSeverity(flow.Severity)
			if !ok {
				continue
			}

			jobID, stepName := extractJobStepFromFlow(flow.Path, insight.Workflow)
			jobDisplay := jobID
			if job, exists := insight.Workflow.Jobs[jobID]; exists && job.Name != "" {
				jobDisplay = job.Name
			}

			cacheKey := fmt.Sprintf("%s|%s|%s|%s|%s", filePath, flow.SourceID, flow.SinkID, jobID, stepName)
			if _, exists := seen[cacheKey]; exists {
				continue
			}
			seen[cacheKey] = struct{}{}

			finding := rules.Finding{
				RuleID:      "AST_SENSITIVE_DATA_FLOW",
				RuleName:    "Sensitive Data Flow",
				Description: fmt.Sprintf("Sensitive data from %s reaches %s (%s)", flow.SourceID, flow.SinkID, flow.Risk),
				Severity:    severity,
				Category:    rules.DataExposure,
				FilePath:    filePath,
				JobName:     jobDisplay,
				StepName:    stepName,
				Evidence:    fmt.Sprintf("Flow path: %s", strings.Join(flow.Path, " -> ")),
				Remediation: "Review this workflow to ensure secrets are not exposed to network, logs, or untrusted contexts.",
			}

			if runner := lookupRunner(insight.JobRunners, finding.JobName); runner != "" {
				finding.RunnerType = runner
			}

			if len(insight.Triggers) > 0 {
				finding.Trigger = insight.Triggers[0]
			}

			all = append(all, finding)
		}
	}

	return all
}

func findingReachableInAST(finding rules.Finding, workflow *ast.WorkflowAST, reachable map[string]bool) bool {
	if finding.JobName == "" {
		return true
	}

	jobID, job := resolveJob(workflow, finding.JobName)
	if job == nil {
		return true
	}

	jobNodeID := fmt.Sprintf("job_%s", jobID)
	if reachableValue, exists := reachable[jobNodeID]; exists && !reachableValue {
		return false
	}

	if finding.StepName == "" {
		return true
	}

	for idx, step := range job.Steps {
		if step.Name == finding.StepName || step.ID == finding.StepName {
			stepNodeID := fmt.Sprintf("step_%s_%d", jobID, idx)
			if reachableValue, exists := reachable[stepNodeID]; exists && !reachableValue {
				return false
			}
			return true
		}
	}

	return true
}

func resolveJob(workflow *ast.WorkflowAST, jobRef string) (string, *ast.JobNode) {
	if job, exists := workflow.Jobs[jobRef]; exists {
		return jobRef, job
	}

	for id, job := range workflow.Jobs {
		if job.Name != "" && strings.EqualFold(job.Name, jobRef) {
			return id, job
		}
	}

	return "", nil
}

func detectPlatformFromPath(path string) string {
	lower := strings.ToLower(path)
	switch {
	case strings.Contains(lower, ".github/workflows"):
		return constants.PlatformGitHub
	case strings.Contains(lower, ".gitlab-ci"):
		return constants.PlatformGitLab
	default:
		return constants.DefaultPlatform
	}
}

func mapFlowSeverity(flowSeverity string) (rules.Severity, bool) {
	switch strings.ToUpper(flowSeverity) {
	case "CRITICAL":
		return rules.Critical, true
	case "HIGH":
		return rules.High, true
	case "MEDIUM":
		return rules.Medium, true
	default:
		return "", false
	}
}

func extractJobStepFromFlow(path []string, workflow *ast.WorkflowAST) (string, string) {
	for _, node := range path {
		if strings.HasPrefix(node, "step_") {
			parts := strings.Split(node, "_")
			if len(parts) >= 3 {
				jobID := parts[1]
				stepIdx, err := strconv.Atoi(parts[2])
				if err != nil {
					return jobID, ""
				}

				if job, exists := workflow.Jobs[jobID]; exists {
					if stepIdx >= 0 && stepIdx < len(job.Steps) {
						step := job.Steps[stepIdx]
						if step.Name != "" {
							return jobID, step.Name
						}
						if step.ID != "" {
							return jobID, step.ID
						}
						return jobID, fmt.Sprintf("Step %d", stepIdx+1)
					}
				}
				return jobID, ""
			}
		}
	}

	for _, node := range path {
		if strings.HasPrefix(node, "job_") {
			jobID := strings.TrimPrefix(node, "job_")
			return jobID, ""
		}
	}

	return "", ""
}

func lookupRunner(jobRunners map[string]string, jobName string) string {
	if jobName == "" {
		return ""
	}
	if runner, exists := jobRunners[strings.ToLower(jobName)]; exists {
		return runner
	}
	return ""
}

func normalizePath(path string) string {
	return filepath.ToSlash(path)
}

