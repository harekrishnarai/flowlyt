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
	"regexp"
	"strings"

	"github.com/harekrishnarai/flowlyt/pkg/parser"
)

// AdvancedExfiltrationDetector detects advanced data exfiltration techniques
// Addresses Issue #16: Exfiltration Scanner Misses DNS, Tunneling & Encoded Data Patterns
type AdvancedExfiltrationDetector struct {
	// DNS exfiltration patterns
	dnsPatterns []*regexp.Regexp

	// Tunneling tool patterns
	tunnelPatterns []*regexp.Regexp

	// Encoding/obfuscation patterns
	encodingPatterns []*regexp.Regexp

	// Steganography patterns
	stegoPatterns []*regexp.Regexp

	// Covert channel patterns
	covertPatterns []*regexp.Regexp
}

// NewAdvancedExfiltrationDetector creates a new advanced exfiltration detector
func NewAdvancedExfiltrationDetector() *AdvancedExfiltrationDetector {
	return &AdvancedExfiltrationDetector{
		dnsPatterns: []*regexp.Regexp{
			// DNS exfiltration via subdomain
			regexp.MustCompile(`\$\{\{[^}]+\}\}\.[a-z0-9-]+\.(com|net|org|io|xyz|tk)`),
			// nslookup/dig with variable
			regexp.MustCompile(`(nslookup|dig|host).*\$\{\{[^}]+\}\}`),
			// DNS over HTTPS exfiltration
			regexp.MustCompile(`curl.*https://(dns\.google|cloudflare-dns\.com|[18]\.1\.1\.1).*\$\{\{`),
		},
		tunnelPatterns: []*regexp.Regexp{
			// ngrok
			regexp.MustCompile(`(ngrok|./ngrok)\s+(http|tcp|start)`),
			// cloudflared (Cloudflare Tunnel)
			regexp.MustCompile(`cloudflared\s+tunnel`),
			// localtunnel
			regexp.MustCompile(`(lt|localtunnel)\s+--port`),
			// serveo
			regexp.MustCompile(`ssh.*serveo\.net`),
			// pagekite
			regexp.MustCompile(`pagekite\.py`),
			// bore
			regexp.MustCompile(`bore\s+(local|server)`),
		},
		encodingPatterns: []*regexp.Regexp{
			// Base64 encode with curl/wget
			regexp.MustCompile(`\$\{\{[^}]+\}\}.*\|\s*base64\s*\|\s*(curl|wget)`),
			// Hex encode
			regexp.MustCompile(`\$\{\{[^}]+\}\}.*\|\s*(xxd|hexdump).*\|\s*(curl|wget)`),
			// Gzip + Base64
			regexp.MustCompile(`\$\{\{[^}]+\}\}.*\|\s*gzip\s*\|\s*base64\s*\|\s*(curl|wget)`),
			// URL encode
			regexp.MustCompile(`\$\{\{[^}]+\}\}.*\|\s*jq\s+-sRr\s+@uri\s*\|\s*(curl|wget)`),
		},
		stegoPatterns: []*regexp.Regexp{
			// steghide
			regexp.MustCompile(`steghide\s+embed`),
			// exiftool with data
			regexp.MustCompile(`exiftool.*-Comment=.*\$\{\{`),
			// Data hidden in images
			regexp.MustCompile(`(convert|magick).*\$\{\{[^}]+\}\}`),
		},
		covertPatterns: []*regexp.Regexp{
			// ICMP exfiltration
			regexp.MustCompile(`ping.*-p\s+[0-9a-fA-F]+`),
			// Timing-based covert channel
			regexp.MustCompile(`sleep\s+\$\(\(.*\$\{\{[^}]+\}\}`),
			// File size covert channel
			regexp.MustCompile(`dd.*count=\$\{\{[^}]+\}\}`),
		},
	}
}

// DetectAdvancedExfiltration scans for advanced exfiltration techniques
func (d *AdvancedExfiltrationDetector) DetectAdvancedExfiltration(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	// 1. DNS exfiltration
	findings = append(findings, d.detectDNSExfiltration(workflow)...)

	// 2. Tunneling tools
	findings = append(findings, d.detectTunneling(workflow)...)

	// 3. Encoded exfiltration
	findings = append(findings, d.detectEncodedExfiltration(workflow)...)

	// 4. Steganography
	findings = append(findings, d.detectSteganography(workflow)...)

	// 5. Covert channels
	findings = append(findings, d.detectCovertChannels(workflow)...)

	return findings
}

// detectDNSExfiltration finds DNS-based exfiltration
func (d *AdvancedExfiltrationDetector) detectDNSExfiltration(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check DNS patterns
			for _, pattern := range d.dnsPatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:      "DNS_EXFILTRATION",
						RuleName:        "Data Exfiltration via DNS",
						Severity:    "CRITICAL",
						Category:    "injection",
						Description:     "Detected potential DNS-based data exfiltration",
						Remediation: "Never include secrets or sensitive data in DNS queries. Use secure, monitored channels for data transfer.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncateContext(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectTunneling finds tunneling tool usage
func (d *AdvancedExfiltrationDetector) detectTunneling(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check for tunneling tools
			for _, pattern := range d.tunnelPatterns {
				if matches := pattern.FindString(step.Run); matches != "" {
					toolName := extractTunnelTool(matches)

					findings = append(findings, Finding{
						RuleID:      "TUNNELING_EXFILTRATION",
						RuleName:        "Data Exfiltration via Tunneling",
						Severity:    "CRITICAL",
						Category:    "injection",
						Description:     "Detected use of tunneling tool: " + toolName,
						Remediation: "Avoid using tunneling tools in CI/CD. If needed, use approved tools with proper monitoring and access controls.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncateContext(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectEncodedExfiltration finds encoded data exfiltration
func (d *AdvancedExfiltrationDetector) detectEncodedExfiltration(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check encoding patterns
			for _, pattern := range d.encodingPatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:      "ENCODED_EXFILTRATION",
						RuleName:        "Data Exfiltration with Encoding",
						Severity:    "HIGH",
						Category:    "injection",
						Description:     "Detected encoded data exfiltration attempt",
						Remediation: "Monitor and restrict encoding of sensitive data. Ensure all data transfers are through approved, secure channels.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncateContext(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectSteganography finds steganographic exfiltration
func (d *AdvancedExfiltrationDetector) detectSteganography(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check steganography patterns
			for _, pattern := range d.stegoPatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:      "STEGANOGRAPHIC_EXFILTRATION",
						RuleName:        "Data Exfiltration via Steganography",
						Severity:    "HIGH",
						Category:    "injection",
						Description:     "Detected steganographic data hiding technique",
						Remediation: "Restrict use of steganography tools. Monitor file uploads and artifact generation.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncateContext(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// detectCovertChannels finds covert channel exfiltration
func (d *AdvancedExfiltrationDetector) detectCovertChannels(workflow *parser.Workflow) []Finding {
	findings := []Finding{}

	for jobName, job := range workflow.Jobs {
		for _, step := range job.Steps {
			if step.Run == "" {
				continue
			}

			// Check covert channel patterns
			for _, pattern := range d.covertPatterns {
				if pattern.MatchString(step.Run) {
					findings = append(findings, Finding{
						RuleID:      "COVERT_CHANNEL_EXFILTRATION",
						RuleName:        "Data Exfiltration via Covert Channel",
						Severity:    "MEDIUM",
						Category:    "injection",
						Description:     "Detected potential covert channel usage",
						Remediation: "Monitor unusual patterns in network timing, file operations, and ICMP traffic.",
						FilePath:        workflow.Name,
						LineNumber:        0,
						JobName:     jobName,
						StepName:    step.Name,
						Evidence:     truncateContext(step.Run, 200),
					})
				}
			}
		}
	}

	return findings
}

// Helper functions

func truncateContext(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

func extractTunnelTool(match string) string {
	if strings.Contains(match, "ngrok") {
		return "ngrok"
	} else if strings.Contains(match, "cloudflared") {
		return "cloudflared"
	} else if strings.Contains(match, "localtunnel") || strings.Contains(match, "lt ") {
		return "localtunnel"
	} else if strings.Contains(match, "serveo") {
		return "serveo.net"
	} else if strings.Contains(match, "pagekite") {
		return "pagekite"
	} else if strings.Contains(match, "bore") {
		return "bore"
	}
	return "unknown"
}
