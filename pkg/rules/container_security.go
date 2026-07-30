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

// CheckContainerSecurity is the public entry point that runs both container
// image pinning and container registry credential checks.
func CheckContainerSecurity(workflow parser.WorkflowFile) []Finding {
	var findings []Finding
	findings = append(findings, checkUnpinnedContainerImage(workflow)...)
	findings = append(findings, checkHardcodedContainerCredentials(workflow)...)
	return findings
}

// containerSpec is a normalised view of a `container:` or `services.<name>:`
// block, both of which share the same schema.
type containerSpec struct {
	jobName string
	// origin describes the source of the spec for reporting, e.g.
	// "Job container" or "Service `postgres`".
	origin      string
	image       string
	credentials map[string]interface{}
}

// normalizeMap converts either YAML mapping representation into
// map[string]interface{}. YAML decoding into interface{} produces
// map[interface{}]interface{}, while decoding into a typed field produces
// map[string]interface{}.
func normalizeMap(value interface{}) (map[string]interface{}, bool) {
	switch v := value.(type) {
	case map[string]interface{}:
		return v, true
	case map[interface{}]interface{}:
		out := make(map[string]interface{}, len(v))
		for key, val := range v {
			if s, ok := key.(string); ok {
				out[s] = val
			}
		}
		return out, true
	}
	return nil, false
}

// parseContainerSpec normalises a container/service value. The value may be a
// bare image string (`container: node:18`) or a mapping with `image:` and
// optional `credentials:`.
func parseContainerSpec(value interface{}, jobName, origin string) (containerSpec, bool) {
	spec := containerSpec{jobName: jobName, origin: origin}

	switch v := value.(type) {
	case string:
		spec.image = strings.TrimSpace(v)
	default:
		m, ok := normalizeMap(value)
		if !ok {
			return spec, false
		}
		if img, ok := m["image"].(string); ok {
			spec.image = strings.TrimSpace(img)
		}
		if creds, ok := normalizeMap(m["credentials"]); ok {
			spec.credentials = creds
		}
	}

	if spec.image == "" && spec.credentials == nil {
		return spec, false
	}

	return spec, true
}

// collectContainerSpecs gathers every container and service definition across
// all jobs in the workflow.
func collectContainerSpecs(workflow parser.WorkflowFile) []containerSpec {
	var specs []containerSpec

	for jobName, job := range workflow.Workflow.Jobs {
		if job.Container != nil {
			if spec, ok := parseContainerSpec(job.Container, jobName, "Job container"); ok {
				specs = append(specs, spec)
			}
		}

		for serviceName, serviceValue := range job.Services {
			origin := fmt.Sprintf("Service `%s`", serviceName)
			if spec, ok := parseContainerSpec(serviceValue, jobName, origin); ok {
				specs = append(specs, spec)
			}
		}
	}

	return specs
}

// digestPinnedPattern matches an image reference pinned by content digest,
// e.g. ubuntu@sha256:0f8f5f2a...
var digestPinnedPattern = regexp.MustCompile(`@sha(?:256|512):[0-9a-fA-F]{32,}$`)

// imageTag extracts the tag from an image reference, returning an empty string
// when no tag is present.
//
// Registry hosts may include a port (registry:5000/image), so a colon only
// denotes a tag when it appears after the final path separator.
func imageTag(image string) string {
	lastSlash := strings.LastIndex(image, "/")
	candidate := image
	if lastSlash != -1 {
		candidate = image[lastSlash+1:]
	}

	colon := strings.Index(candidate, ":")
	if colon == -1 {
		return ""
	}
	return candidate[colon+1:]
}

// checkUnpinnedContainerImage detects container and service images that are not
// pinned to an immutable content digest.
//
// A mutable tag such as `node:18` or `postgres:latest` can be repointed at
// different content by whoever controls the registry namespace, so a compromised
// or hijacked upstream image silently executes in the job's context with access
// to the job's secrets. Only a `@sha256:` digest makes the image immutable.
//
// Step-level `uses: docker://...` references are covered here too, since they
// pull an image in exactly the same way.
func checkUnpinnedContainerImage(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	addFinding := func(jobName, stepName, origin, image string, lineNumber int) {
		dedupKey := fmt.Sprintf("%s|%s|%d", origin, image, lineNumber)
		if seen[dedupKey] {
			return
		}
		seen[dedupKey] = true

		tag := imageTag(image)

		// An untagged or `latest` image floats to whatever the registry
		// currently serves, so it is strictly worse than a version tag.
		severity := Low
		detail := fmt.Sprintf("pinned only to mutable tag `%s`", tag)
		switch {
		case tag == "":
			severity = Medium
			detail = "has no tag, so it implicitly resolves to `latest`"
		case strings.EqualFold(tag, "latest"):
			severity = Medium
			detail = "uses the `latest` tag, which changes without notice"
		}

		findings = append(findings, Finding{
			RuleID:      "UNPINNED_CONTAINER_IMAGE",
			RuleName:    "Unpinned Container Image",
			Description: "Container image is not pinned to an immutable digest, allowing upstream content to change silently",
			Severity:    severity,
			Category:    SupplyChain,
			FilePath:    workflow.Path,
			JobName:     jobName,
			StepName:    stepName,
			Evidence:    fmt.Sprintf("%s image `%s` %s", origin, image, detail),
			Remediation: fmt.Sprintf("Pin the image by digest, e.g. `%s@sha256:<digest>`. Resolve the digest with `docker buildx imagetools inspect %s`", stripTag(image), image),
			LineNumber:  lineNumber,
		})
	}

	for _, spec := range collectContainerSpecs(workflow) {
		if spec.image == "" {
			continue
		}
		// Runtime-resolved images cannot be evaluated statically.
		if strings.Contains(spec.image, "${{") {
			continue
		}
		if digestPinnedPattern.MatchString(spec.image) {
			continue
		}

		lineNumber := 0
		if result := lineMapper.FindLineNumber(linenum.FindPattern{
			Key:   "image",
			Value: spec.image,
		}); result != nil {
			lineNumber = result.LineNumber
		}

		addFinding(spec.jobName, "", spec.origin, spec.image, lineNumber)
	}

	// Step-level Docker action references (uses: docker://image:tag).
	for jobName, job := range workflow.Workflow.Jobs {
		for stepIdx, step := range job.Steps {
			if !strings.HasPrefix(step.Uses, "docker://") {
				continue
			}

			image := strings.TrimPrefix(step.Uses, "docker://")
			if image == "" || strings.Contains(image, "${{") {
				continue
			}
			if digestPinnedPattern.MatchString(image) {
				continue
			}

			stepName := step.Name
			if stepName == "" {
				stepName = fmt.Sprintf("Step %d", stepIdx+1)
			}

			lineNumber := 0
			if result := lineMapper.FindLineNumber(linenum.FindPattern{
				Key:   "uses",
				Value: step.Uses,
			}); result != nil {
				lineNumber = result.LineNumber
			}

			addFinding(jobName, stepName, "Step Docker action", image, lineNumber)
		}
	}

	return findings
}

// stripTag removes a trailing tag from an image reference so a digest can be
// appended in remediation guidance.
func stripTag(image string) string {
	lastSlash := strings.LastIndex(image, "/")
	colon := strings.Index(image[lastSlash+1:], ":")
	if colon == -1 {
		return image
	}
	return image[:lastSlash+1+colon]
}

// credentialSecretPattern matches values that resolve a secret at runtime rather
// than embedding it, e.g. ${{ secrets.REGISTRY_TOKEN }}.
var credentialSecretPattern = regexp.MustCompile(`\$\{\{\s*(secrets|env|vars|inputs)\.`)

// checkHardcodedContainerCredentials detects registry credentials embedded
// directly in a job's container or service definition.
//
// Credentials committed into a workflow file are visible to everyone with read
// access to the repository, are captured in git history forever, and are exposed
// to every fork and pull request. Because these credentials authenticate to a
// container registry, leaking them typically permits pushing malicious images
// that later run inside CI.
func checkHardcodedContainerCredentials(workflow parser.WorkflowFile) []Finding {
	var findings []Finding

	lineMapper := linenum.NewLineMapper(workflow.Content)
	seen := make(map[string]bool)

	// Only the password field is treated as sensitive; a registry username is
	// not a secret on its own.
	const credentialField = "password"

	for _, spec := range collectContainerSpecs(workflow) {
		if spec.credentials == nil {
			continue
		}

		raw, ok := spec.credentials[credentialField]
		if !ok {
			continue
		}

		value, ok := raw.(string)
		if !ok || strings.TrimSpace(value) == "" {
			continue
		}

		// Values sourced from secrets/env/vars/inputs are the correct pattern.
		if credentialSecretPattern.MatchString(value) {
			continue
		}

		lineNumber := 0
		if result := lineMapper.FindLineNumber(linenum.FindPattern{
			Key:   credentialField,
			Value: value,
		}); result != nil {
			lineNumber = result.LineNumber
		}

		dedupKey := fmt.Sprintf("%s|%s|%d", spec.jobName, spec.origin, lineNumber)
		if seen[dedupKey] {
			continue
		}
		seen[dedupKey] = true

		findings = append(findings, Finding{
			RuleID:      "HARDCODED_CONTAINER_CREDENTIALS",
			RuleName:    "Hardcoded Container Registry Credentials",
			Description: "Container registry password is hardcoded in the workflow instead of being sourced from a secret",
			Severity:    Critical,
			Category:    SecretExposure,
			FilePath:    workflow.Path,
			JobName:     spec.jobName,
			Evidence:    fmt.Sprintf("%s declares a literal `credentials.password` value: %s", spec.origin, redactCredential(value)),
			Remediation: "Store the registry password as a repository or organization secret and reference it, e.g. `password: ${{ secrets.REGISTRY_PASSWORD }}`. Rotate the exposed credential, since it remains in git history.",
			LineNumber:  lineNumber,
		})
	}

	return findings
}

// redactCredential shortens a secret value so the finding is actionable without
// reprinting the full credential into logs and reports.
func redactCredential(value string) string {
	const prefixLen = 3
	if len(value) <= prefixLen {
		return strings.Repeat("*", len(value))
	}
	return value[:prefixLen] + strings.Repeat("*", len(value)-prefixLen)
}
