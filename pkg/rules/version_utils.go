package rules

import (
	"strconv"
	"strings"
	"time"
)

// compareVersions compares current version with latest and determines if it's outdated
// Returns (isOutdated bool, severity Severity)
func compareVersions(current, latest string, latestPublishedAt time.Time) (bool, Severity) {
	// If versions are the same, not outdated
	if current == latest {
		return false, ""
	}

	// Parse semantic versions
	currentMajor, currentMinor := parseSemanticVersion(current)
	latestMajor, latestMinor := parseSemanticVersion(latest)

	// Calculate how many days old the latest release is
	daysSinceLatest := time.Since(latestPublishedAt).Hours() / 24

	// Major version behind - HIGH severity
	if latestMajor > currentMajor && latestMajor-currentMajor >= 1 {
		return true, High
	}

	// Minor version behind (2+ versions) - MEDIUM severity
	if latestMajor == currentMajor && latestMinor > currentMinor && latestMinor-currentMinor >= 2 {
		return true, Medium
	}

	// Same major version, 1 minor behind, and latest is >6 months old - LOW severity
	if latestMajor == currentMajor && latestMinor == currentMinor+1 && daysSinceLatest > 180 {
		return true, Low
	}

	// Not significantly outdated
	return false, ""
}

// parseSemanticVersion extracts major and minor version numbers from a version string
// Handles formats like: v1.2.3, 1.2.3, v1, 1
func parseSemanticVersion(version string) (major, minor int) {
	// Remove 'v' prefix if present
	version = strings.TrimPrefix(version, "v")

	// Split by dots
	parts := strings.Split(version, ".")
	if len(parts) == 0 {
		return 0, 0
	}

	// Parse major version
	if major, err := strconv.Atoi(parts[0]); err == nil {
		majorResult := major
		minorResult := 0

		// Parse minor version if present
		if len(parts) > 1 {
			if minor, err := strconv.Atoi(parts[1]); err == nil {
				minorResult = minor
			}
		}

		return majorResult, minorResult
	}

	return 0, 0
}
