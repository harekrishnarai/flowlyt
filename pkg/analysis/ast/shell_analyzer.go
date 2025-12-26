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

package ast

import (
	"fmt"
	"regexp"
	"strings"
)

// ShellAnalyzer provides enhanced shell command analysis
type ShellAnalyzer struct {
	variablePattern     *regexp.Regexp
	commandPattern      *regexp.Regexp
	redirectionPattern  *regexp.Regexp
	pipePattern         *regexp.Regexp
	substitutionPattern *regexp.Regexp
}

// ShellCommand represents a parsed shell command with its components
type ShellCommand struct {
	OriginalCommand string
	ParsedCommands  []*CommandSegment
	Variables       []*VariableReference
	Redirections    []*Redirection
	Pipes           []*Pipe
	Substitutions   []*CommandSubstitution
	SecurityRisks   []string
	DataFlowRisks   []string
}

// CommandSegment represents a single command in a pipeline
type CommandSegment struct {
	Command     string
	Arguments   []string
	Environment map[string]string
	Dangerous   bool
	Category    string // "network", "file", "system", "data"
}

// VariableReference represents a variable used in the command
type VariableReference struct {
	Name      string
	Value     string
	Source    string // "env", "github", "secret", "input"
	Sensitive bool
	Usage     string // "read", "write", "expand"
}

// Redirection represents input/output redirection
type Redirection struct {
	Type   string // "input", "output", "append", "error"
	Source string
	Target string
	Risky  bool
}

// Pipe represents a pipe between commands
type Pipe struct {
	LeftCommand  string
	RightCommand string
	DataFlow     bool // Whether sensitive data flows through the pipe
}

// CommandSubstitution represents command substitution $(command) or `command`
type CommandSubstitution struct {
	Command   string
	Context   string // Where it's used
	Dangerous bool
}

// NewShellAnalyzer creates a new enhanced shell analyzer
func NewShellAnalyzer() *ShellAnalyzer {
	return &ShellAnalyzer{
		variablePattern:     regexp.MustCompile(`\$\{?([A-Z_][A-Z0-9_]*)\}?|\$\{\{\s*([^}]+)\s*\}\}`),
		commandPattern:      regexp.MustCompile(`(?:^|\s)([a-zA-Z_][a-zA-Z0-9_.-]*)`),
		redirectionPattern:  regexp.MustCompile(`([12]?>[>&]?|<[<]?)\s*([^\s|&;]+)`),
		pipePattern:         regexp.MustCompile(`\|\s*([^|&;]+)`),
		substitutionPattern: regexp.MustCompile(`\$\(([^)]+)\)|` + "`" + `([^` + "`" + `]+)` + "`"),
	}
}

// AnalyzeShellCommand performs comprehensive analysis of a shell command
func (sa *ShellAnalyzer) AnalyzeShellCommand(command string, context map[string]string) (*ShellCommand, error) {
	if command == "" {
		return nil, fmt.Errorf("empty command")
	}

	shellCmd := &ShellCommand{
		OriginalCommand: command,
		ParsedCommands:  []*CommandSegment{},
		Variables:       []*VariableReference{},
		Redirections:    []*Redirection{},
		Pipes:           []*Pipe{},
		Substitutions:   []*CommandSubstitution{},
		SecurityRisks:   []string{},
		DataFlowRisks:   []string{},
	}

	// Parse different components
	sa.parseCommands(shellCmd)
	sa.parseVariables(shellCmd, context)
	sa.parseRedirections(shellCmd)
	sa.parsePipes(shellCmd)
	sa.parseSubstitutions(shellCmd)

	// Analyze security risks
	sa.analyzeSecurityRisks(shellCmd)
	sa.analyzeDataFlowRisks(shellCmd)

	return shellCmd, nil
}

// parseCommands extracts and categorizes commands from the shell script
func (sa *ShellAnalyzer) parseCommands(shellCmd *ShellCommand) {
	lines := strings.Split(shellCmd.OriginalCommand, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Split by pipes and semicolons to get individual commands
		commands := sa.splitCommands(line)

		for _, cmd := range commands {
			segment := sa.parseCommandSegment(cmd)
			if segment != nil {
				shellCmd.ParsedCommands = append(shellCmd.ParsedCommands, segment)
			}
		}
	}
}

// splitCommands splits a command line into individual commands
func (sa *ShellAnalyzer) splitCommands(line string) []string {
	// Simple split on pipes and semicolons (could be enhanced with proper parsing)
	delimiters := []string{"|", ";", "&&", "||"}
	commands := []string{line}

	for _, delimiter := range delimiters {
		var newCommands []string
		for _, cmd := range commands {
			parts := strings.Split(cmd, delimiter)
			for _, part := range parts {
				part = strings.TrimSpace(part)
				if part != "" {
					newCommands = append(newCommands, part)
				}
			}
		}
		commands = newCommands
	}

	return commands
}

// parseCommandSegment parses a single command segment
func (sa *ShellAnalyzer) parseCommandSegment(cmd string) *CommandSegment {
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return nil
	}

	segment := &CommandSegment{
		Command:     parts[0],
		Arguments:   parts[1:],
		Environment: make(map[string]string),
		Category:    sa.categorizeCommand(parts[0]),
	}

	// Check if command is dangerous
	segment.Dangerous = sa.isDangerousCommand(parts[0])

	return segment
}

// categorizeCommand categorizes a command by its primary function
func (sa *ShellAnalyzer) categorizeCommand(command string) string {
	networkCommands := []string{"curl", "wget", "nc", "netcat", "ssh", "scp", "rsync", "git", "pip", "npm", "docker"}
	fileCommands := []string{"cat", "head", "tail", "grep", "awk", "sed", "cut", "sort", "uniq", "find", "ls", "cp", "mv", "rm"}
	systemCommands := []string{"sudo", "su", "chmod", "chown", "mount", "umount", "ps", "kill", "systemctl", "service"}
	dataCommands := []string{"base64", "openssl", "gpg", "gzip", "tar", "zip", "unzip"}

	commandCategories := map[string]string{
		"network": strings.Join(networkCommands, "|"),
		"file":    strings.Join(fileCommands, "|"),
		"system":  strings.Join(systemCommands, "|"),
		"data":    strings.Join(dataCommands, "|"),
	}

	for category, pattern := range commandCategories {
		if matched, _ := regexp.MatchString(fmt.Sprintf(`\b(%s)\b`, pattern), command); matched {
			return category
		}
	}

	return "other"
}

// isDangerousCommand checks if a command is potentially dangerous
func (sa *ShellAnalyzer) isDangerousCommand(command string) bool {
	dangerousCommands := []string{
		"rm", "rmdir", "dd", "mkfs", "fdisk", "parted",
		"sudo", "su", "chmod", "chown",
		"nc", "netcat", "telnet", "ssh",
		"curl", "wget", "python", "python3", "node", "ruby", "perl",
		"docker", "kubectl", "helm",
		"eval", "exec", "source", ".",
		"bash", "sh", "zsh", "fish",
	}

	for _, dangerous := range dangerousCommands {
		if command == dangerous {
			return true
		}
	}

	return false
}

// parseVariables extracts and analyzes variable references
func (sa *ShellAnalyzer) parseVariables(shellCmd *ShellCommand, context map[string]string) {
	matches := sa.variablePattern.FindAllStringSubmatch(shellCmd.OriginalCommand, -1)

	for _, match := range matches {
		var varName string
		if match[1] != "" {
			varName = match[1] // Standard variable $VAR or ${VAR}
		} else if match[2] != "" {
			varName = match[2] // GitHub expression ${{ expr }}
		}

		if varName == "" {
			continue
		}

		variable := &VariableReference{
			Name:   varName,
			Value:  context[varName],
			Source: sa.determineVariableSource(varName),
			Usage:  "read",
		}

		variable.Sensitive = sa.isVariableSensitive(varName)

		shellCmd.Variables = append(shellCmd.Variables, variable)
	}
}

// determineVariableSource determines where a variable comes from
func (sa *ShellAnalyzer) determineVariableSource(varName string) string {
	githubPatterns := []string{"github", "runner", "job", "steps", "env", "vars", "secrets"}
	secretPatterns := []string{"secret", "token", "key", "password", "pass", "credential", "auth", "api"}
	envPatterns := []string{"path", "home", "user", "shell", "term"}

	lowerName := strings.ToLower(varName)

	for _, pattern := range githubPatterns {
		if strings.Contains(lowerName, pattern) {
			return "github"
		}
	}

	for _, pattern := range secretPatterns {
		if strings.Contains(lowerName, pattern) {
			return "secret"
		}
	}

	for _, pattern := range envPatterns {
		if strings.Contains(lowerName, pattern) {
			return "env"
		}
	}

	return "unknown"
}

// isVariableSensitive checks if a variable contains sensitive information
func (sa *ShellAnalyzer) isVariableSensitive(varName string) bool {
	sensitivePatterns := []string{
		"secret", "token", "key", "password", "pass", "credential",
		"auth", "api", "private", "cert", "certificate", "oauth",
	}

	lowerName := strings.ToLower(varName)
	for _, pattern := range sensitivePatterns {
		if strings.Contains(lowerName, pattern) {
			return true
		}
	}

	return false
}

// parseRedirections extracts input/output redirections
func (sa *ShellAnalyzer) parseRedirections(shellCmd *ShellCommand) {
	matches := sa.redirectionPattern.FindAllStringSubmatch(shellCmd.OriginalCommand, -1)

	for _, match := range matches {
		if len(match) < 3 {
			continue
		}

		operator := match[1]
		target := match[2]

		redirection := &Redirection{
			Type:   sa.getRedirectionType(operator),
			Source: operator,
			Target: target,
			Risky:  sa.isRiskyRedirection(target),
		}

		shellCmd.Redirections = append(shellCmd.Redirections, redirection)
	}
}

// getRedirectionType determines the type of redirection
func (sa *ShellAnalyzer) getRedirectionType(operator string) string {
	switch {
	case strings.Contains(operator, ">>"):
		return "append"
	case strings.Contains(operator, ">"):
		return "output"
	case strings.Contains(operator, "<<"):
		return "heredoc"
	case strings.Contains(operator, "<"):
		return "input"
	default:
		return "unknown"
	}
}

// isRiskyRedirection checks if a redirection target is risky
func (sa *ShellAnalyzer) isRiskyRedirection(target string) bool {
	riskyTargets := []string{
		"/dev/tcp/", "/dev/udp/", "/proc/", "/sys/",
		"http://", "https://", "ftp://", "sftp://",
	}

	for _, risky := range riskyTargets {
		if strings.Contains(target, risky) {
			return true
		}
	}

	return false
}

// parsePipes extracts and analyzes command pipes
func (sa *ShellAnalyzer) parsePipes(shellCmd *ShellCommand) {
	parts := strings.Split(shellCmd.OriginalCommand, "|")

	for i := 0; i < len(parts)-1; i++ {
		leftCmd := strings.TrimSpace(parts[i])
		rightCmd := strings.TrimSpace(parts[i+1])

		pipe := &Pipe{
			LeftCommand:  leftCmd,
			RightCommand: rightCmd,
			DataFlow:     sa.hasSensitiveDataFlow(leftCmd, rightCmd),
		}

		shellCmd.Pipes = append(shellCmd.Pipes, pipe)
	}
}

// hasSensitiveDataFlow checks if a pipe might transfer sensitive data
func (sa *ShellAnalyzer) hasSensitiveDataFlow(leftCmd, rightCmd string) bool {
	// Check if left command reads sensitive data
	sensitiveCommands := []string{"env", "printenv", "cat /proc", "grep"}
	networkCommands := []string{"curl", "wget", "nc", "netcat"}

	leftSensitive := false
	for _, sensitive := range sensitiveCommands {
		if strings.Contains(leftCmd, sensitive) {
			leftSensitive = true
			break
		}
	}

	rightNetwork := false
	for _, network := range networkCommands {
		if strings.Contains(rightCmd, network) {
			rightNetwork = true
			break
		}
	}

	return leftSensitive && rightNetwork
}

// parseSubstitutions extracts command substitutions
func (sa *ShellAnalyzer) parseSubstitutions(shellCmd *ShellCommand) {
	matches := sa.substitutionPattern.FindAllStringSubmatch(shellCmd.OriginalCommand, -1)

	for _, match := range matches {
		var command string
		if match[1] != "" {
			command = match[1] // $(command)
		} else if match[2] != "" {
			command = match[2] // `command`
		}

		if command == "" {
			continue
		}

		substitution := &CommandSubstitution{
			Command:   command,
			Context:   "substitution",
			Dangerous: sa.isDangerousSubstitution(command),
		}

		shellCmd.Substitutions = append(shellCmd.Substitutions, substitution)
	}
}

// isDangerousSubstitution checks if a command substitution is dangerous
func (sa *ShellAnalyzer) isDangerousSubstitution(command string) bool {
	dangerousPatterns := []string{
		"curl", "wget", "nc", "netcat", "ssh",
		"eval", "exec", "bash", "sh",
		"rm", "dd", "sudo",
	}

	for _, pattern := range dangerousPatterns {
		if strings.Contains(command, pattern) {
			return true
		}
	}

	return false
}

// analyzeSecurityRisks identifies security risks in the shell command
func (sa *ShellAnalyzer) analyzeSecurityRisks(shellCmd *ShellCommand) {
	risks := []string{}

	// Check for dangerous commands
	for _, cmd := range shellCmd.ParsedCommands {
		if cmd.Dangerous {
			risks = append(risks, fmt.Sprintf("dangerous_command_%s", cmd.Command))
		}
	}

	// Check for risky redirections
	for _, redir := range shellCmd.Redirections {
		if redir.Risky {
			risks = append(risks, "risky_redirection")
		}
	}

	// Check for dangerous substitutions
	for _, sub := range shellCmd.Substitutions {
		if sub.Dangerous {
			risks = append(risks, "dangerous_substitution")
		}
	}

	// Check for privilege escalation
	if sa.hasPrivilegeEscalation(shellCmd) {
		risks = append(risks, "privilege_escalation")
	}

	// Check for code injection risks
	if sa.hasCodeInjectionRisk(shellCmd) {
		risks = append(risks, "code_injection")
	}

	shellCmd.SecurityRisks = risks
}

// analyzeDataFlowRisks identifies data flow risks
func (sa *ShellAnalyzer) analyzeDataFlowRisks(shellCmd *ShellCommand) {
	risks := []string{}

	// Check for sensitive variable usage
	for _, variable := range shellCmd.Variables {
		if variable.Sensitive {
			risks = append(risks, "sensitive_variable_usage")
		}
	}

	// Check for data exfiltration patterns
	if sa.hasDataExfiltrationPattern(shellCmd) {
		risks = append(risks, "data_exfiltration")
	}

	// Check for credential exposure
	if sa.hasCredentialExposure(shellCmd) {
		risks = append(risks, "credential_exposure")
	}

	// Check for sensitive data in pipes
	for _, pipe := range shellCmd.Pipes {
		if pipe.DataFlow {
			risks = append(risks, "sensitive_data_pipe")
		}
	}

	shellCmd.DataFlowRisks = risks
}

// hasPrivilegeEscalation checks for privilege escalation patterns
func (sa *ShellAnalyzer) hasPrivilegeEscalation(shellCmd *ShellCommand) bool {
	escalationPatterns := []string{"sudo", "su", "chmod +s", "setuid", "setgid"}

	for _, pattern := range escalationPatterns {
		if strings.Contains(shellCmd.OriginalCommand, pattern) {
			return true
		}
	}

	return false
}

// hasCodeInjectionRisk checks for code injection risks
func (sa *ShellAnalyzer) hasCodeInjectionRisk(shellCmd *ShellCommand) bool {
	// Check for eval with user input
	if strings.Contains(shellCmd.OriginalCommand, "eval") {
		for _, variable := range shellCmd.Variables {
			if variable.Source == "github" || variable.Source == "unknown" {
				return true
			}
		}
	}

	// Check for unquoted variables in dangerous contexts
	dangerousContexts := []string{"bash -c", "sh -c", "eval", "exec"}
	for _, context := range dangerousContexts {
		if strings.Contains(shellCmd.OriginalCommand, context) {
			return true
		}
	}

	return false
}

// hasDataExfiltrationPattern checks for data exfiltration patterns
func (sa *ShellAnalyzer) hasDataExfiltrationPattern(shellCmd *ShellCommand) bool {
	// Check for network commands with sensitive data
	networkCommands := []string{"curl", "wget", "nc", "netcat"}

	for _, cmd := range shellCmd.ParsedCommands {
		if cmd.Category == "network" {
			// Check if sensitive variables are used with network commands
			for _, variable := range shellCmd.Variables {
				if variable.Sensitive {
					return true
				}
			}
		}
	}

	// Check for base64 encoding + network
	hasEncoding := strings.Contains(shellCmd.OriginalCommand, "base64")
	hasNetwork := false
	for _, network := range networkCommands {
		if strings.Contains(shellCmd.OriginalCommand, network) {
			hasNetwork = true
			break
		}
	}

	return hasEncoding && hasNetwork
}

// hasCredentialExposure checks for credential exposure patterns
func (sa *ShellAnalyzer) hasCredentialExposure(shellCmd *ShellCommand) bool {
	exposurePatterns := []string{"echo", "printf", "cat", "head", "tail"}

	for _, pattern := range exposurePatterns {
		if strings.Contains(shellCmd.OriginalCommand, pattern) {
			// Check if sensitive variables are being echoed
			for _, variable := range shellCmd.Variables {
				if variable.Sensitive {
					return true
				}
			}
		}
	}

	return false
}
