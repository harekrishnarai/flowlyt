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

// Package dependabot discovers and audits Dependabot configuration files.
//
// Dependabot configuration is a distinct input type from CI workflows: it does
// not describe jobs or steps, but it does govern how third-party code enters
// the repository. Because its schema shares nothing with a workflow, it is
// parsed and audited through a parallel pipeline rather than being coerced into
// the workflow model.
package dependabot

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

// ConfigFile is a discovered and parsed Dependabot configuration file.
type ConfigFile struct {
	// Path is the location of the file, relative to the repository root where
	// possible, for use in findings and report URLs.
	Path string
	Name string
	// Content is the raw file bytes, retained for line-number resolution.
	Content []byte
	Config  Config
}

// Config models the subset of the Dependabot schema relevant to security
// auditing. Unknown fields are ignored so that unrelated schema additions do
// not break parsing.
type Config struct {
	Version int      `yaml:"version"`
	Updates []Update `yaml:"updates"`
}

// Update is a single entry in the `updates:` list, describing one ecosystem.
type Update struct {
	PackageEcosystem string   `yaml:"package-ecosystem"`
	Directory        string   `yaml:"directory"`
	Directories      []string `yaml:"directories"`
	Schedule         Schedule `yaml:"schedule"`
	// Cooldown delays adoption of newly published releases. A nil pointer
	// distinguishes "absent" from "explicitly set to zero".
	Cooldown *Cooldown `yaml:"cooldown"`
	// InsecureExternalCodeExecution opts in to running dependency manifest code
	// during resolution. Valid values are "allow" and "deny".
	InsecureExternalCodeExecution string      `yaml:"insecure-external-code-execution"`
	Registries                    interface{} `yaml:"registries"`
}

// Schedule describes how often Dependabot checks for updates.
type Schedule struct {
	Interval string `yaml:"interval"`
}

// Cooldown describes the delay applied before a newly released version is
// proposed.
type Cooldown struct {
	DefaultDays     int `yaml:"default-days"`
	SemverMajorDays int `yaml:"semver-major-days"`
	SemverMinorDays int `yaml:"semver-minor-days"`
	SemverPatchDays int `yaml:"semver-patch-days"`
}

// candidateFilenames are the paths GitHub recognises for Dependabot config,
// in the order they should be probed.
var candidateFilenames = []string{
	filepath.Join(".github", "dependabot.yml"),
	filepath.Join(".github", "dependabot.yaml"),
}

// FindConfigs locates and parses Dependabot configuration in a repository.
//
// A repository with no Dependabot configuration is a normal, valid state, so
// this returns an empty slice rather than an error in that case. Callers should
// treat "no configuration" as "nothing to audit", not as a failure.
func FindConfigs(repoPath string) ([]ConfigFile, error) {
	var configs []ConfigFile

	for _, candidate := range candidateFilenames {
		fullPath := filepath.Join(repoPath, candidate)

		info, err := os.Stat(fullPath)
		if err != nil || info.IsDir() {
			continue
		}

		configFile, err := LoadConfig(fullPath)
		if err != nil {
			// A malformed Dependabot file should not abort the whole scan;
			// surface it to the caller but keep any other configs.
			return configs, fmt.Errorf("parsing %s: %w", candidate, err)
		}

		// Report the repository-relative path so findings and generated URLs
		// line up with the other input types.
		configFile.Path = candidate
		configs = append(configs, configFile)
	}

	return configs, nil
}

// LoadConfig reads and parses a single Dependabot configuration file.
func LoadConfig(path string) (ConfigFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return ConfigFile{}, fmt.Errorf("reading %s: %w", path, err)
	}

	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return ConfigFile{}, fmt.Errorf("invalid YAML in %s: %w", path, err)
	}

	return ConfigFile{
		Path:    path,
		Name:    filepath.Base(path),
		Content: content,
		Config:  cfg,
	}, nil
}

// EcosystemLabel returns a human-readable identifier for an update entry, used
// to make findings actionable when a config declares several ecosystems.
func (u Update) EcosystemLabel() string {
	ecosystem := u.PackageEcosystem
	if ecosystem == "" {
		ecosystem = "unknown"
	}

	directory := u.Directory
	if directory == "" && len(u.Directories) > 0 {
		directory = u.Directories[0]
	}
	if directory == "" {
		directory = "/"
	}

	return fmt.Sprintf("%s (%s)", ecosystem, directory)
}
