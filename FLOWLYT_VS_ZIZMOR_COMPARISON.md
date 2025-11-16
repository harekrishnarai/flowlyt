# Flowlyt vs Zizmor Comparison Analysis

## Executive Summary

**Flowlyt:** 215 findings  
**Zizmor:** 99 findings

Flowlyt detects **2.2x more findings** than Zizmor, which suggests either:
- ✅ Better coverage and detection capabilities
- ⚠️ More false positives (needs tuning)

## Findings Breakdown

### Zizmor Findings (99 total)

| Rule | Count | Description |
|------|-------|-------------|
| `zizmor/unpinned-uses` | 42 | Unpinned action references |
| `zizmor/artipacked` | 26 | Credential persistence through artifacts (missing `persist-credentials: false`) |
| `zizmor/excessive-permissions` | 23 | Overly broad permissions |
| `zizmor/known-vulnerable-actions` | 7 | Actions with known CVEs (GHSA IDs) |
| `zizmor/template-injection` | 4 | Code injection via template expansion |
| `zizmor/dangerous-triggers` | 3 | Insecure workflow triggers (`pull_request_target`) |

### Flowlyt Findings (215 total)

| Rule | Count | Description |
|------|-------|-------------|
| `REF_CONFUSION` | 64 | Git reference confusion (version tags) |
| `UNTRUSTED_ACTION_SOURCE` | 42 | Actions from untrusted publishers |
| `UNPINNED_ACTION` | 41 | Unpinned GitHub Actions |
| `REPO_JACKING_VULNERABILITY` | 33 | Repository jacking vulnerability |
| `EXTERNAL_TRIGGER_DEBUG` | 21 | External triggers (`workflow_dispatch`, `pull_request_target`) |
| `STALE_ACTION_REFS` | 4 | Stale action references |
| `MALICIOUS_DATA_EXFILTRATION` | 4 | Data exfiltration patterns |
| `SHELL_SCRIPT_ISSUES` | 4 | Shell script security issues |
| `AST_SENSITIVE_DATA_FLOW` | 2 | **NEW** - AST-based sensitive data flow detection |

## Key Differences

### ✅ Flowlyt Advantages

1. **AST-Based Analysis**
   - ✅ **2 AST data flow findings** - Zizmor doesn't have this
   - ✅ Reachability analysis (suppresses unreachable code findings)
   - ✅ Metadata enrichment (trigger, runner_type context)

2. **Broader Rule Coverage**
   - ✅ `REF_CONFUSION` (64 findings) - Detects git reference confusion
   - ✅ `UNTRUSTED_ACTION_SOURCE` (42 findings) - Flags untrusted publishers
   - ✅ `REPO_JACKING_VULNERABILITY` (33 findings) - Repository jacking detection
   - ✅ `STALE_ACTION_REFS` (4 findings) - Old action versions
   - ✅ `MALICIOUS_DATA_EXFILTRATION` (4 findings) - Data exfiltration patterns
   - ✅ `SHELL_SCRIPT_ISSUES` (4 findings) - Shell script security

3. **Better Context**
   - ✅ All findings include `trigger` and `runner_type` metadata
   - ✅ AST-generated insights for data flow analysis

### ⚠️ Zizmor Advantages (Missing in Flowlyt)

1. **Credential Persistence Detection (Artipacked)**
   - ❌ **Missing:** `persist-credentials: false` check in `actions/checkout`
   - **Zizmor:** 26 findings for this issue
   - **Impact:** HIGH - Credentials can persist in artifacts
   - **Recommendation:** Add rule to check for `persist-credentials: false` in checkout actions

2. **Known Vulnerable Actions (CVE Database)**
   - ❌ **Missing:** Integration with GHSA (GitHub Security Advisory) database
   - **Zizmor:** 7 findings for actions with known CVEs (e.g., `GHSA-mrrh-fwg8-r2c3`)
   - **Impact:** HIGH - Detects actions with known security vulnerabilities
   - **Recommendation:** Integrate OSV.dev or GHSA API to check action versions

3. **Comprehensive Permissions Analysis**
   - ⚠️ **Partial:** Flowlyt has `BROAD_PERMISSIONS` but may not detect all cases
   - **Zizmor:** 23 findings for excessive permissions
   - **Flowlyt:** 0 findings for `BROAD_PERMISSIONS` (not triggered in Goat repo)
   - **Issue:** Flowlyt only checks for `write-all`, not default permissions or missing `permissions: block`
   - **Recommendation:** Enhance permissions detection to check for:
     - Missing `permissions: block` (defaults to write-all)
     - Jobs without explicit permissions
     - Overly permissive permission sets

4. **Template Injection Detection**
   - ⚠️ **Partial:** Flowlyt has injection detection but may not cover all template injection cases
   - **Zizmor:** 4 findings for template injection
   - **Flowlyt:** Has `INJECTION_VULNERABILITY` but may not be as comprehensive
   - **Recommendation:** Review and enhance template injection detection

5. **Dangerous Triggers**
   - ⚠️ **Partial:** Flowlyt has `EXTERNAL_TRIGGER_DEBUG` and `INSECURE_PULL_REQUEST_TARGET`
   - **Zizmor:** 3 findings for `pull_request_target`
   - **Flowlyt:** 21 findings for `EXTERNAL_TRIGGER_DEBUG` (includes `workflow_dispatch` too)
   - **Note:** Flowlyt is more comprehensive but may have more false positives

## False Positive Analysis

### Flowlyt False Positives (Likely)

1. **REF_CONFUSION (64 findings)**
   - **Issue:** Flags ALL version tags (e.g., `@v3`, `@v4`)
   - **Context:** While not ideal, version tags are common and often acceptable
   - **Zizmor approach:** Only flags unpinned actions (42 findings)
   - **Recommendation:** 
     - Downgrade severity to LOW for well-known actions (e.g., `actions/checkout@v3`)
     - Only flag as HIGH for untrusted actions
     - Consider allow-list for verified actions

2. **UNTRUSTED_ACTION_SOURCE (42 findings)**
   - **Issue:** Flags actions from individual developers
   - **Context:** Many legitimate actions are from individual developers
   - **Zizmor approach:** Doesn't have this rule
   - **Recommendation:**
     - Add allow-list for popular/verified actions
     - Consider severity downgrade to MEDIUM
     - Only flag as HIGH for truly suspicious patterns

3. **EXTERNAL_TRIGGER_DEBUG (21 findings)**
   - **Issue:** Flags `workflow_dispatch` (manual triggers)
   - **Context:** `workflow_dispatch` is legitimate for many workflows
   - **Zizmor approach:** Only flags `pull_request_target` (3 findings)
   - **Recommendation:**
     - Downgrade `workflow_dispatch` to LOW severity
     - Keep `pull_request_target` as HIGH/CRITICAL
     - Add context-aware detection (e.g., only flag if combined with dangerous patterns)

4. **REPO_JACKING_VULNERABILITY (33 findings)**
   - **Issue:** May flag legitimate actions with version tags
   - **Overlap:** Similar to `UNPINNED_ACTION` (41 findings)
   - **Recommendation:** Consider consolidating or refining this rule

### Zizmor False Positives (Likely)

1. **artipacked (26 findings)**
   - **Issue:** Flags all `actions/checkout` without `persist-credentials: false`
   - **Context:** Not always a security issue if artifacts don't contain secrets
   - **Recommendation:** This is a valid security concern, but severity could be MEDIUM

## Missing Features in Flowlyt

### Critical Missing Features

1. **`persist-credentials: false` Detection**
   ```yaml
   # Zizmor detects this:
   - uses: actions/checkout@v4
     # Missing: with: { persist-credentials: false }
   ```
   - **Priority:** HIGH
   - **Impact:** Credentials can persist in artifacts
   - **Implementation:** Add check in `checkArtipackedVulnerability` or create new rule

2. **Known Vulnerable Actions (CVE Database)**
   ```yaml
   # Zizmor detects:
   - uses: tj-actions/changed-files@v40  # GHSA-mrrh-fwg8-r2c3
   ```
   - **Priority:** HIGH
   - **Impact:** Detects actions with known security vulnerabilities
   - **Implementation:** Integrate OSV.dev API (already have `--enable-vuln-intel` flag, but not for actions)

3. **Default Permissions Detection**
   ```yaml
   # Zizmor detects missing permissions: block
   jobs:
     build:  # No permissions: block = defaults to write-all
   ```
   - **Priority:** HIGH
   - **Impact:** Missing `permissions: block` grants write-all by default
   - **Implementation:** Enhance `checkBroadPermissions` to detect missing permissions

### Medium Priority Missing Features

4. **Enhanced Template Injection**
   - **Priority:** MEDIUM
   - **Impact:** May miss some template injection patterns
   - **Implementation:** Review and enhance `checkInjectionVulnerabilities`

5. **Better Permissions Granularity**
   - **Priority:** MEDIUM
   - **Impact:** May miss subtle permission issues
   - **Implementation:** Add more granular permission checks

## Recommendations

### Immediate Actions (High Priority)

1. **Add `persist-credentials` Detection**
   ```go
   // In checkArtipackedVulnerability or new rule
   if step.Uses != "" && strings.Contains(step.Uses, "checkout") {
       if step.With == nil || step.With["persist-credentials"] != "false" {
           // Flag as security issue
       }
   }
   ```

2. **Integrate GHSA/OSV Database for Actions**
   ```go
   // Check action version against OSV.dev or GHSA
   // Use existing --enable-vuln-intel infrastructure
   // Add action-specific vulnerability checking
   ```

3. **Enhance Permissions Detection**
   ```go
   // Check for missing permissions: block
   // Check for default permissions (write-all)
   // Check for overly permissive permission sets
   ```

### False Positive Reduction

1. **Refine REF_CONFUSION Rule**
   - Downgrade to LOW for well-known actions (`actions/checkout`, `actions/setup-node`)
   - Only flag as HIGH for untrusted actions
   - Add allow-list for verified actions

2. **Refine UNTRUSTED_ACTION_SOURCE**
   - Add allow-list for popular actions
   - Downgrade severity to MEDIUM
   - Only flag as HIGH for truly suspicious patterns

3. **Refine EXTERNAL_TRIGGER_DEBUG**
   - Downgrade `workflow_dispatch` to LOW
   - Keep `pull_request_target` as HIGH/CRITICAL
   - Add context-aware detection

4. **Consolidate Overlapping Rules**
   - `REPO_JACKING_VULNERABILITY` vs `UNPINNED_ACTION` - Consider merging or refining

### Feature Parity

1. **Template Injection Enhancement**
   - Review Zizmor's template injection patterns
   - Enhance Flowlyt's injection detection
   - Add specific template injection rule if needed

2. **Permissions Analysis**
   - Match Zizmor's comprehensive permissions detection
   - Add detection for missing `permissions: block`
   - Add detection for default permissions

## Comparison Summary

| Feature | Flowlyt | Zizmor | Winner |
|---------|---------|--------|--------|
| **Total Findings** | 215 | 99 | Flowlyt (more comprehensive) |
| **AST Analysis** | ✅ Yes (2 findings) | ❌ No | **Flowlyt** |
| **Data Flow Analysis** | ✅ Yes | ❌ No | **Flowlyt** |
| **Credential Persistence** | ❌ No | ✅ Yes (26 findings) | **Zizmor** |
| **CVE Database Integration** | ⚠️ Partial (OSV.dev) | ✅ Yes (GHSA) | **Zizmor** |
| **Permissions Detection** | ⚠️ Basic | ✅ Comprehensive | **Zizmor** |
| **Template Injection** | ⚠️ Partial | ✅ Yes | **Zizmor** |
| **Unpinned Actions** | ✅ Yes (41 findings) | ✅ Yes (42 findings) | **Tie** |
| **Dangerous Triggers** | ✅ Yes (21 findings) | ✅ Yes (3 findings) | **Flowlyt** (more comprehensive) |
| **False Positive Rate** | ⚠️ Higher (needs tuning) | ✅ Lower (more focused) | **Zizmor** |
| **Rule Coverage** | ✅ 46+ rules | ⚠️ 6 rules | **Flowlyt** |

## Conclusion

### Strengths

**Flowlyt:**
- ✅ **More comprehensive** - 2.2x more findings
- ✅ **AST-based analysis** - Unique data flow detection
- ✅ **Broader rule coverage** - 46+ rules vs 6 rules
- ✅ **Better metadata** - Context enrichment

**Zizmor:**
- ✅ **More focused** - Lower false positive rate
- ✅ **CVE integration** - Known vulnerable actions
- ✅ **Credential persistence** - Artipacked detection
- ✅ **Better permissions** - Comprehensive permissions analysis

### Action Items

**Priority 1 (Critical):**
1. Add `persist-credentials: false` detection
2. Integrate GHSA/OSV database for action vulnerabilities
3. Enhance permissions detection (missing `permissions: block`)

**Priority 2 (High):**
4. Reduce false positives in `REF_CONFUSION` (64 findings)
5. Refine `UNTRUSTED_ACTION_SOURCE` (42 findings)
6. Tune `EXTERNAL_TRIGGER_DEBUG` severity

**Priority 3 (Medium):**
7. Enhance template injection detection
8. Consolidate overlapping rules
9. Add allow-lists for trusted actions

### Expected Impact

After implementing these improvements:
- **False Positive Reduction:** 30-50% (from 215 to ~120-150 findings)
- **Missing Detection:** Add 3 critical features (credential persistence, CVE database, permissions)
- **Feature Parity:** Match or exceed Zizmor's capabilities while maintaining Flowlyt's comprehensive coverage


