# Enhanced CLI Output Examples

## Example 1: Data Flow Detection (Detailed Format)

```
[HIGH] .github/workflows/terraform.yml:42
Rule: AST_SENSITIVE_DATA_FLOW

   40 │    - name: Setup shared secrets if needed
   41 │      env:
   42 │ >    CORALOGIX_SECRETS: ${{ secrets.CORALOGIX_SECRETS_PEM_BASE64 }}
       │    └─→ Potential Issue Here
   43 │      with:
   44 │ >    token: ${{ secrets.GITHUB_TOKEN }}
       │    └─→ Potential Issue Here

Message: Sensitive data flows from 'CORALOGIX_SECRETS_PEM_BASE64' to 'github-token' (Potential sensitive data flow)

🔻 Data Flow Analysis:
   [Source] CORALOGIX_SECRETS_PEM_BASE64
      │
      ▼
   [Sink]   GITHUB_TOKEN

💡 Remediation: Ensure secrets are not passed directly to untrusted actions.
```

## Example 2: Boxed Format

```
┌─ [HIGH] Sensitive Data Flow Detected ──────────────────────────────────────┐
│ ID: 72  |  Rule: AST_SENSITIVE_DATA_FLOW                                   │
│                                                                             │
│ 📂 terraform.yml:42                                                        │
│    └── Job: terraform                                                      │
│        └── Step: "Setup shared secrets if needed"                          │
│                                                                             │
│ 💡 Sensitive data flows from 'CORALOGIX_SECRETS_PEM_BASE64' to...         │
│    'github-token' parameter                                                │
└─────────────────────────────────────────────────────────────────────────────┘
```

## Example 3: Compact Format

```
[HIGH] [72] Sensitive Data Flow (AST_SENSITIVE_DATA_FLOW)
  📂 File:       .github/workflows/terraform.yml:42
  ⚙️  Job:       terraform
  📝 Step:       Setup shared secrets if needed
  📋 Message:    Sensitive data flows from 'CORALOGIX_SECRETS_PEM_BASE64' to 'github-token'
```

## Features of the Enhanced Formatter

### Code Context Rendering
- Shows file snippets with line numbers
- Highlights the problematic line(s) with arrows and indicators
- Displays 3-4 lines of context around the issue

### Data Flow Visualization
- Extracts source and sink information from the evidence
- Uses ASCII art to show data flow direction
- Clearly indicates where the data is coming from and where it's going

### Severity Indicators
- Color-coded severity badges: `[CRITICAL]`, `[HIGH]`, `[MEDIUM]`, `[LOW]`, `[INFO]`
- Visual hierarchy with icons (📂, ⚙️, 📝, 💡)

### Better Context Information
- Shows file path with line number reference
- Displays job name and step name (for GitHub Actions workflows)
- Includes rule ID and name for easy reference

### Remediation Hints
- Actionable remediation advice with 💡 icon
- Helps users understand how to fix the issue

## Configuration

Users can control the CLI output style by setting the `CLIStyle` property:
- `detailed`: Enhanced formatting with code snippets (default)
- `compact`: Single-line format with minimal spacing
- `boxed`: Box-drawing characters for visual separation
- `standard`: Original format for backward compatibility

Example usage:
```go
gen := NewGenerator(result, "cli", verbose, outputFile)
gen.CLIStyle = "detailed"  // Use detailed format
gen.EnhancedFormatting = true
gen.Generate()
```
