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

package rules

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/v2/pkg/linenum"
	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// CheckInsecureURLScheme is the public entry point for the INSECURE_URL_SCHEME rule.
func CheckInsecureURLScheme(workflow parser.WorkflowFile) []Finding {
	return checkInsecureURLScheme(workflow)
}

// insecureURLPattern matches plaintext HTTP URLs. The host portion is captured
// so that loopback and namespace hosts can be filtered out.
var insecureURLPattern = regexp.MustCompile(`(?i)\bhttp://([A-Za-z0-9._~%-]+(?::\d+)?)(/[^\s"'` + "`" + `,;)\]}]*)?`)

// loopbackHosts are addresses that never leave the runner, so plaintext HTTP
// carries no meaningful interception risk.
var loopbackHosts = map[string]bool{
	"localhost": true,
	"127.0.0.1": true,
	"0.0.0.0":   true,
	"::1":       true,
	"[::1]":     true,
}

// namespaceURLPrefixes are well-known URLs used as XML namespaces, schema
// identifiers, or license identifiers. They are opaque strings that are never
// dereferenced at runtime, so flagging them would be pure noise.
var namespaceURLPrefixes = []string{
	"http://www.w3.org/",
	"http://schemas.xmlsoap.org/",
	"http://schemas.microsoft.com/",
	"http://maven.apache.org/",
	"http://www.apache.org/licenses/",
	"http://json-schema.org/",
	"http://purl.org/",
	"http://xmlns.jcp.org/",
	"http://java.sun.com/",
	"http://docbook.org/",
	"http://www.opengis.net/",
	"http://relaxng.org/",
}

// isIgnorableInsecureURL reports whether a matched HTTP URL should be excluded
// from findings.
func isIgnorableInsecureURL(fullURL, host string) bool {
	lowerURL := strings.ToLower(fullURL)

	for _, prefix := range namespaceURLPrefixes {
		if strings.HasPrefix(lowerURL, prefix) {
			return true
		}
	}

	// Strip a port before comparing against loopback addresses.
	hostOnly := host
	if idx := strings.LastIndex(hostOnly, ":"); idx != -1 && !strings.Contains(hostOnly, "]") {
		hostOnly = hostOnly[:idx]
	}
	hostOnly = strings.ToLower(hostOnly)

	if loopbackHosts[hostOnly] {
		return true
	}

	// Link-local metadata endpoint and *.local mDNS names are runner-internal.
	if hostOnly == "169.254.169.254" || strings.HasSuffix(hostOnly, ".local") {
		return true
	}

	// A host that is entirely a GitHub Actions expression is resolved at
	// runtime and cannot be evaluated statically.
	if strings.Contains(host, "${{") {
		return true
	}

	return false
}

// insecureURLSite describes one location in the workflow that was scanned.
type insecureURLSite struct {
	jobName  string
	stepName string
	// field is a human-readable description of where the URL was found,
	// e.g. "run command" or "input `url`".
	field string
	value string
	// lineKey and lineValue drive line-number resolution.
	lineKey   string
	lineValue string
}

// checkInsecureURLScheme detects plaintext http:// URLs in workflow definitions.
//
// Fetching build inputs, installers, or scripts over unauthenticated HTTP allows
// a network-positioned attacker to tamper with the response and achieve code
// execution on the runner. This is especially severe in CI because the fetched
// content is typically executed or built without further verification.
func checkInsecureURLScheme(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	for _, site := range collectInsecureURLSites(workflow) {
		matches := insecureURLPattern.FindAllStringSubmatch(site.value, -1)
		if len(matches) == 0 {
			continue
		}

		for _, match := range matches {
			fullURL := match[0]
			host := match[1]

			if isIgnorableInsecureURL(fullURL, host) {
				continue
			}

			lineNumber := 0
			if result := lineMapper.FindLineNumber(linenum.FindPattern{
				Key:   site.lineKey,
				Value: site.lineValue,
			}); result != nil {
				lineNumber = result.LineNumber
			}

			// A single URL can legitimately appear in several matrix job
			// contexts that share one step definition; report it once.
			dedupKey := fmt.Sprintf("%s|%d", fullURL, lineNumber)
			if seen[dedupKey] {
				continue
			}
			seen[dedupKey] = true

			findings = append(findings, Finding{
				RuleID:      "INSECURE_URL_SCHEME",
				RuleName:    "Insecure URL Scheme",
				Description: "Workflow retrieves a resource over plaintext HTTP, allowing a network attacker to tamper with the response",
				Severity:    Medium,
				Category:    SupplyChain,
				FilePath:    workflow.Path,
				JobName:     site.jobName,
				StepName:    site.stepName,
				Evidence:    fmt.Sprintf("%s uses insecure URL: %s", site.field, fullURL),
				Remediation: fmt.Sprintf("Use the HTTPS equivalent (https://%s...) and verify the downloaded artifact's checksum or signature where possible", host),
				LineNumber:  lineNumber,
			})
		}
	}

	return findings
}

// collectInsecureURLSites gathers every string in the workflow that may contain
// a URL: run commands, action inputs, and environment variables at the
// workflow, job, and step levels.
func collectInsecureURLSites(workflow parser.WorkflowFile) []insecureURLSite {
	var sites []insecureURLSite

	for name, value := range workflow.Workflow.Env {
		sites = append(sites, insecureURLSite{
			field:     fmt.Sprintf("Workflow env `%s`", name),
			value:     value,
			lineKey:   name,
			lineValue: value,
		})
	}

	for jobName, job := range workflow.Workflow.Jobs {
		for name, value := range job.Env {
			sites = append(sites, insecureURLSite{
				jobName:   jobName,
				field:     fmt.Sprintf("Job env `%s`", name),
				value:     value,
				lineKey:   name,
				lineValue: value,
			})
		}

		for stepIdx, step := range job.Steps {
			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			if step.Run != "" {
				sites = append(sites, insecureURLSite{
					jobName:   jobName,
					stepName:  stepName,
					field:     "Run command",
					value:     step.Run,
					lineKey:   "run",
					lineValue: firstNonEmptyLine(step.Run),
				})
			}

			for name, raw := range step.With {
				value, ok := raw.(string)
				if !ok {
					continue
				}
				sites = append(sites, insecureURLSite{
					jobName:   jobName,
					stepName:  stepName,
					field:     fmt.Sprintf("Input `%s`", name),
					value:     value,
					lineKey:   name,
					lineValue: value,
				})
			}

			for name, value := range step.Env {
				sites = append(sites, insecureURLSite{
					jobName:   jobName,
					stepName:  stepName,
					field:     fmt.Sprintf("Step env `%s`", name),
					value:     value,
					lineKey:   name,
					lineValue: value,
				})
			}
		}
	}

	return sites
}

// firstNonEmptyLine returns the first non-blank line of a multi-line string,
// which gives the line mapper a usable anchor for multi-line `run:` blocks.
func firstNonEmptyLine(s string) string {
	for _, line := range strings.Split(s, "\n") {
		if trimmed := strings.TrimSpace(line); trimmed != "" {
			return trimmed
		}
	}
	return ""
}
