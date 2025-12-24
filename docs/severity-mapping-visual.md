# Flowlyt SARIF Severity Mapping for GitHub Advanced Security

## Visual Mapping

```
┌─────────────────────────────────────────────────────────────────────┐
│                    Flowlyt → SARIF → GitHub                         │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  CRITICAL (Flowlyt)                                                 │
│       ↓                                                              │
│  security-severity: 9.0  +  level: error                           │
│       ↓                                                              │
│  🔴 Critical (GitHub Security Tab)                                  │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  HIGH (Flowlyt)                                                     │
│       ↓                                                              │
│  security-severity: 8.0  +  level: error                           │
│       ↓                                                              │
│  🟠 High (GitHub Security Tab)                                      │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  MEDIUM (Flowlyt)                                                   │
│       ↓                                                              │
│  security-severity: 5.0  +  level: warning                         │
│       ↓                                                              │
│  🟡 Medium (GitHub Security Tab)                                    │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  LOW (Flowlyt)                                                      │
│       ↓                                                              │
│  security-severity: 3.0  +  level: warning                         │
│       ↓                                                              │
│  🔵 Low (GitHub Security Tab)                                       │
│                                                                      │
├─────────────────────────────────────────────────────────────────────┤
│                                                                      │
│  INFO (Flowlyt)                                                     │
│       ↓                                                              │
│  security-severity: 0.0  +  level: note                            │
│       ↓                                                              │
│  ⚪ Note (GitHub Security Tab)                                      │
│                                                                      │
└─────────────────────────────────────────────────────────────────────┘
```

## GitHub Advanced Security Severity Score Ranges

GitHub Advanced Security interprets the `security-severity` property using these ranges:

| Score Range | Severity Display | Color in UI |
|-------------|-----------------|-------------|
| 9.0 - 10.0  | Critical        | 🔴 Red       |
| 7.0 - 8.9   | High            | 🟠 Orange    |
| 4.0 - 6.9   | Medium          | 🟡 Yellow    |
| 0.1 - 3.9   | Low             | 🔵 Blue      |
| 0.0         | Note            | ⚪ Gray      |

## Example: Before and After

### Before (Generic Error/Warning)
```
GitHub Security Tab:
├── Error: Untrusted Action Source
├── Error: Repository Jacking Vulnerability  
├── Error: Git Reference Confusion
└── Warning: Missing Permissions
```

### After (Specific Severity Levels)
```
GitHub Security Tab:
├── 🔴 Critical: Repository Jacking Vulnerability (9.0)
├── 🟠 High: Untrusted Action Source (8.0)
├── 🟠 High: Git Reference Confusion (8.0)
└── 🔵 Low: Missing Permissions (3.0)
```

## How It Works

When Flowlyt generates SARIF output, it now includes two complementary properties:

1. **SARIF `level`**: Required by the SARIF specification
   - `error`: For critical and high severity
   - `warning`: For medium and low severity  
   - `note`: For informational findings

2. **`security-severity`**: GitHub-specific numeric score
   - Provides precise severity mapping
   - Used by GitHub Advanced Security for display
   - Allows fine-grained filtering and sorting

Both properties work together to ensure findings display correctly across all platforms:
- **GitHub Advanced Security**: Uses `security-severity` for precise severity display
- **Other SARIF viewers**: Fall back to standard `level` property
- **IDEs and tools**: Compatible with both approaches

## Usage Example

```bash
# Generate SARIF report
flowlyt scan --repo . --output sarif --output-file results.sarif

# Upload to GitHub
gh api /repos/OWNER/REPO/code-scanning/sarifs \
  -F sarif=@results.sarif \
  -F commit_sha=$(git rev-parse HEAD) \
  -F ref=refs/heads/main
```

Or use GitHub Actions:

```yaml
- name: Upload SARIF to GitHub
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
    category: flowlyt-security
```

## Benefits

✅ **Clear Prioritization**: Instantly see which issues need immediate attention  
✅ **Better Filtering**: Filter by severity in GitHub's UI  
✅ **Accurate Metrics**: Security dashboards show correct severity distribution  
✅ **Compliance Ready**: Meets security scanning standards for enterprise environments  
✅ **Team Alignment**: Consistent severity language across tools

## Technical Details

The implementation adds the `security-severity` property to each rule definition in the SARIF output:

```json
{
  "rules": [{
    "id": "UNTRUSTED_ACTION_SOURCE",
    "name": "Untrusted Action Source",
    "defaultConfiguration": {
      "level": "error"
    },
    "properties": {
      "security-severity": "9.0",
      "severity": "CRITICAL",
      "category": "SUPPLY_CHAIN"
    }
  }]
}
```

This ensures GitHub Advanced Security displays the finding with the correct severity badge and allows proper filtering and sorting in the Security tab.
