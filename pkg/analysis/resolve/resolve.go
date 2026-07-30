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

// Package resolve loads the definitions behind local `uses:` references.
//
// Analysis that stops at the file boundary misses a whole class of problem: a
// workflow passes attacker-controlled data into a local composite action or
// reusable workflow, and the execution happens inside that other file. The
// calling workflow looks clean because it only passes a parameter, and the
// callee looks clean because it only uses its own declared input.
//
// Only repository-local references are resolved. A remote reference
// (`owner/repo/action@ref`) would require fetching the other repository, which
// is a network operation with its own trust questions; those are covered by the
// supply chain rules instead.
package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// Kind distinguishes the two things a local `uses:` can point at.
type Kind int

const (
	// KindCompositeAction is an action.yml with `runs.using: composite`.
	KindCompositeAction Kind = iota
	// KindReusableWorkflow is a workflow invoked as `jobs.<id>.uses`.
	KindReusableWorkflow
)

// Definition is a resolved local `uses:` target.
type Definition struct {
	Kind Kind
	// Path is the file on disk, for reporting.
	Path string
	// RelPath is the path relative to the repository root.
	RelPath string
	Content []byte

	// Inputs are the input names the definition declares.
	Inputs map[string]bool

	// Steps are the composite action's steps. Empty for reusable workflows.
	Steps []parser.Step
	// Jobs are the reusable workflow's jobs. Empty for composite actions.
	Jobs map[string]parser.Job
}

// Repo resolves local references relative to a repository root.
//
// Definitions are cached because the same action is commonly used by many
// workflows in a repository, and a scan would otherwise re-read and re-parse it
// for each one.
type Repo struct {
	root string

	mu    sync.Mutex
	cache map[string]*Definition
	// misses records paths already known not to resolve, so a broken reference
	// is not re-attempted for every caller.
	misses map[string]bool
}

// NewRepo creates a resolver rooted at the given directory.
func NewRepo(root string) *Repo {
	return &Repo{
		root:   root,
		cache:  map[string]*Definition{},
		misses: map[string]bool{},
	}
}

// RepoRootFor derives the repository root from a workflow file path.
//
// Workflows are discovered under <root>/.github/workflows, so the root is
// recovered by trimming that suffix. An empty string is returned when the path
// does not have that shape, in which case no local resolution is attempted.
func RepoRootFor(workflowPath string) string {
	dir := filepath.Dir(workflowPath)
	if filepath.Base(dir) != "workflows" {
		return ""
	}
	githubDir := filepath.Dir(dir)
	if filepath.Base(githubDir) != ".github" {
		return ""
	}
	return filepath.Dir(githubDir)
}

// IsLocal reports whether a `uses:` value refers to something in this
// repository.
func IsLocal(uses string) bool {
	u := strings.TrimSpace(uses)
	return strings.HasPrefix(u, "./") || strings.HasPrefix(u, "../")
}

// ResolveUses loads the definition a local `uses:` value points at.
//
// Returns false when the reference is remote, missing, unparseable, or an
// action that is not composite. A JavaScript or Docker action has no steps to
// analyse from source, so it is deliberately not resolved.
func (r *Repo) ResolveUses(uses string) (*Definition, bool) {
	if r == nil || r.root == "" || !IsLocal(uses) {
		return nil, false
	}

	// Strip any @ref: a local reference is always the working tree.
	ref := strings.TrimSpace(uses)
	if i := strings.Index(ref, "@"); i != -1 {
		ref = ref[:i]
	}

	target, ok := r.safeJoin(ref)
	if !ok {
		return nil, false
	}

	r.mu.Lock()
	if def, hit := r.cache[target]; hit {
		r.mu.Unlock()
		return def, true
	}
	if r.misses[target] {
		r.mu.Unlock()
		return nil, false
	}
	r.mu.Unlock()

	def, ok := r.load(target)

	r.mu.Lock()
	if ok {
		r.cache[target] = def
	} else {
		r.misses[target] = true
	}
	r.mu.Unlock()

	return def, ok
}

// safeJoin resolves a reference against the repository root and refuses to
// escape it.
//
// A `uses:` value is repository data, so it must not be trusted to stay inside
// the tree: `./../../etc/passwd` would otherwise make the analyzer read
// arbitrary files.
func (r *Repo) safeJoin(ref string) (string, bool) {
	joined := filepath.Join(r.root, filepath.FromSlash(ref))

	absRoot, err := filepath.Abs(r.root)
	if err != nil {
		return "", false
	}
	absTarget, err := filepath.Abs(joined)
	if err != nil {
		return "", false
	}

	rel, err := filepath.Rel(absRoot, absTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return "", false
	}
	return absTarget, true
}

// load reads and parses a resolved path.
func (r *Repo) load(target string) (*Definition, bool) {
	info, err := os.Stat(target)
	if err != nil {
		return nil, false
	}

	if info.IsDir() {
		// A directory reference means an action; GitHub accepts either filename.
		for _, name := range []string{"action.yml", "action.yaml"} {
			if def, ok := r.loadAction(filepath.Join(target, name)); ok {
				return def, true
			}
		}
		return nil, false
	}

	// A file reference is a reusable workflow, unless it is an action manifest.
	base := filepath.Base(target)
	if base == "action.yml" || base == "action.yaml" {
		return r.loadAction(target)
	}
	return r.loadReusableWorkflow(target)
}

// actionYAML is the subset of an action manifest needed for analysis.
type actionYAML struct {
	Inputs map[string]struct {
		Description string `yaml:"description"`
		Required    bool   `yaml:"required"`
	} `yaml:"inputs"`
	Runs struct {
		Using string        `yaml:"using"`
		Steps []parser.Step `yaml:"steps"`
	} `yaml:"runs"`
}

func (r *Repo) loadAction(path string) (*Definition, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var a actionYAML
	if err := yaml.Unmarshal(content, &a); err != nil {
		return nil, false
	}

	// Only composite actions expose their steps as YAML. JavaScript and Docker
	// actions execute code this analysis cannot see.
	if !strings.EqualFold(strings.TrimSpace(a.Runs.Using), "composite") {
		return nil, false
	}

	inputs := make(map[string]bool, len(a.Inputs))
	for name := range a.Inputs {
		inputs[name] = true
	}

	return &Definition{
		Kind:    KindCompositeAction,
		Path:    path,
		RelPath: r.relative(path),
		Content: content,
		Inputs:  inputs,
		Steps:   a.Runs.Steps,
	}, true
}

// workflowCallInputs extracts the inputs a reusable workflow declares under
// `on.workflow_call.inputs`.
func workflowCallInputs(on interface{}) map[string]bool {
	inputs := map[string]bool{}

	asMap := func(v interface{}) map[string]interface{} {
		switch m := v.(type) {
		case map[string]interface{}:
			return m
		case map[interface{}]interface{}:
			out := make(map[string]interface{}, len(m))
			for k, val := range m {
				if ks, ok := k.(string); ok {
					out[ks] = val
				}
			}
			return out
		}
		return nil
	}

	onMap := asMap(on)
	if onMap == nil {
		return inputs
	}
	call := asMap(onMap["workflow_call"])
	if call == nil {
		return inputs
	}
	declared := asMap(call["inputs"])
	for name := range declared {
		inputs[name] = true
	}
	return inputs
}

func (r *Repo) loadReusableWorkflow(path string) (*Definition, bool) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}

	var wf parser.Workflow
	if err := yaml.Unmarshal(content, &wf); err != nil {
		return nil, false
	}

	inputs := workflowCallInputs(wf.On)
	if len(wf.Jobs) == 0 {
		return nil, false
	}

	return &Definition{
		Kind:    KindReusableWorkflow,
		Path:    path,
		RelPath: r.relative(path),
		Content: content,
		Inputs:  inputs,
		Jobs:    wf.Jobs,
	}, true
}

// relative renders a path relative to the repository root for reporting.
func (r *Repo) relative(path string) string {
	if rel, err := filepath.Rel(r.root, path); err == nil {
		return filepath.ToSlash(rel)
	}
	return path
}
