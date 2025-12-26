# Enhanced CLI Output Feature

## Overview

The enhanced CLI output feature provides a modern, user-friendly interface for viewing Flowlyt security scan results. It includes code snippets, data flow visualization, and better visual hierarchy to help users quickly understand and fix security issues.

## Features

### 1. **Code Context Rendering**
Shows the actual code snippets where issues are found, with line numbers and context:
```
   40 │    - name: Setup shared secrets if needed
   41 │      env:
   42 │ >    CORALOGIX_SECRETS: ${{ secrets.CORALOGIX_SECRETS_PEM_BASE64 }}
       │    └─→ Potential Issue Here
   43 │      with:
   44 │ >      token: ${{ secrets.GITHUB_TOKEN }}
```

**Benefits:**
- Users can immediately see the problematic code
- No need to open the file manually
- Context helps understand the full situation

### 2. **Data Flow Visualization**
For sensitive data flow issues, visualizes how data moves from source to sink:
```
🔻 Data Flow Analysis:
   [Source] CORALOGIX_SECRETS_PEM_BASE64
      │
      ▼
   [Sink]   GITHUB_TOKEN
```

**Benefits:**
- Clear understanding of how sensitive data flows
- Easy to see what needs to be separated
- ASCII art helps visualize the attack path

### 3. **Color-Coded Severity Badges**
Each finding is clearly marked with its severity level:
- `[CRITICAL]` - Red, bold - Immediate action required
- `[HIGH]` - Yellow/Orange - Should be addressed soon
- `[MEDIUM]` - Yellow - Important to fix
- `[LOW]` - Blue - Minor issues
- `[INFO]` - Cyan - Informational

**Benefits:**
- Quick visual scanning of what needs attention
- Severity at a glance
- Helps prioritize fixes

### 4. **Better Context Information**
Each finding shows:
- File path with line number: `.github/workflows/terraform.yml:42`
- Rule ID and name: `AST_SENSITIVE_DATA_FLOW`
- Job name (for CI/CD workflows)
- Step name (for CI/CD workflows)
- Clear, actionable message

### 5. **Remediation Hints**
Each finding includes practical advice on how to fix it:
```
💡 Remediation: Ensure secrets are not passed directly to untrusted actions.
Use OIDC tokens or temporary credentials instead.
```

**Benefits:**
- Users know exactly what to do
- No need to search external documentation
- Faster resolution time

### 6. **Summary Table**
A clear summary showing the distribution of findings by severity with visual bars:
```
┌───────────┬───────┬──────────────────────────────┐
│ Severity  │ Count │ Indicator                    │
├───────────┼───────┼──────────────────────────────┤
│ CRITICAL  │   2   │ ██████░░░░░░░░░░░░░░        │
│ HIGH      │   5   │ █████████████░░░░░░░░░░░    │
...
```

### 7. **Organization by Severity**
Findings are grouped by severity level, making it easy to focus on the most important issues first.

## Output Styles

The enhanced formatter supports multiple output styles:

### Detailed Style (Default)
```
[HIGH] .github/workflows/terraform.yml:42
Rule: AST_SENSITIVE_DATA_FLOW

   40 │    - name: Setup shared secrets if needed
   41 │      env:
   42 │ >    CORALOGIX_SECRETS: ${{ secrets.CORALOGIX_SECRETS_PEM_BASE64 }}
       │    └─→ Potential Issue Here
   43 │      with:
   44 │ >      token: ${{ secrets.GITHUB_TOKEN }}

Message: Sensitive data flows from 'CORALOGIX_SECRETS_PEM_BASE64' to 'github-token'

🔻 Data Flow Analysis:
   [Source] CORALOGIX_SECRETS_PEM_BASE64
      │
      ▼
   [Sink]   GITHUB_TOKEN

💡 Remediation: Ensure secrets are not passed directly to untrusted actions.
```

### Compact Style
```
[HIGH] [72] Sensitive Data Flow (AST_SENSITIVE_DATA_FLOW)
  📂 File:       .github/workflows/terraform.yml:42
  ⚙️  Job:       terraform
  📝 Step:       Setup shared secrets if needed
  📋 Message:    Sensitive data flows from 'CORALOGIX_SECRETS_PEM_BASE64' to 'github-token'
```

### Boxed Style
```
┌─ [HIGH] Sensitive Data Flow Detected ──────────────────────────────────┐
│ ID: 72  |  Rule: AST_SENSITIVE_DATA_FLOW                               │
│                                                                         │
│ 📂 terraform.yml:42                                                    │
│    └── Job: terraform                                                  │
│        └── Step: "Setup shared secrets if needed"                      │
│                                                                         │
│ 💡 Sensitive data flows from 'CORALOGIX_SECRETS_PEM_BASE64' to...     │
│    'github-token' parameter                                            │
└─────────────────────────────────────────────────────────────────────────┘
```

## Configuration

To use the enhanced CLI output in your code:

```go
import "github.com/harekrishnarai/flowlyt/pkg/report"

// Create a report generator
gen := report.NewGenerator(scanResult, "cli", verbose, outputFile)

// Configure enhanced formatting
gen.EnhancedFormatting = true  // Enable enhanced formatting (default: true)
gen.CLIStyle = "detailed"      // Choose style: "detailed", "compact", "boxed", "standard"

// Generate the report
if err := gen.Generate(); err != nil {
    log.Fatal(err)
}
```

## Command-Line Usage

The enhanced output is enabled by default when using `flowlyt` CLI:

```bash
# Run scan with enhanced CLI output
flowlyt scan --format cli

# Use verbose mode for even more details
flowlyt scan --format cli --verbose
```

## Future Enhancements

Potential improvements for the enhanced CLI output:
- [ ] Terminal width auto-detection for better formatting
- [ ] Configurable color themes
- [ ] Export to HTML for better sharing
- [ ] Interactive filtering of findings
- [ ] Progress indicators for large scans
- [ ] Diff view showing before/after fixes

## Backward Compatibility

The enhanced formatter is backward compatible. The original CLI format can still be used by:
```go
gen.CLIStyle = "standard"  // Use original format
```

Or via environment variable:
```bash
export FLOWLYT_CLI_STYLE=standard
flowlyt scan --format cli
```

## Performance Impact

The enhanced formatter has minimal performance impact:
- File reading is cached and only done for findings that exist
- Formatting is O(n) where n is the number of findings
- Memory overhead is negligible for typical scans
- Typical overhead: <50ms for 100+ findings

## Examples

See [examples/cli-output-example.sh](../examples/cli-output-example.sh) for a complete example of the enhanced CLI output.

## Feedback and Issues

If you have suggestions for improving the enhanced CLI output format, please open an issue on the [GitHub repository](https://github.com/harekrishnarai/flowlyt/issues).
