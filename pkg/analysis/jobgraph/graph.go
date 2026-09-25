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

// Package jobgraph models a workflow's jobs as a directed acyclic graph and
// propagates taint across it.
//
// Existing analysis in Flowlyt is per-step or per-job. That misses a real and
// exploited attack shape: one job writes attacker-controlled data into a job
// output, and a second, more privileged job consumes it and executes it. Neither
// job looks dangerous on its own — the vulnerability exists only in the edge
// between them.
//
// Jobs form a DAG through `needs:`, and data flows only from a dependency to
// its dependents. Processing jobs in topological order therefore guarantees
// that every input to a job is fully resolved before the job is examined, so a
// single pass suffices and no iteration to a fixpoint is required. That is the
// property this package is built around.
package jobgraph

import (
	"fmt"
	"sort"

	"github.com/harekrishnarai/flowlyt/v2/pkg/parser"
)

// Node is one job in the graph.
type Node struct {
	ID  string
	Job parser.Job

	// Needs are the job IDs this job depends on, in declaration order.
	Needs []string
	// Dependents are the job IDs that depend on this job.
	Dependents []string
}

// Graph is the job dependency DAG for a single workflow.
type Graph struct {
	// Nodes is keyed by job ID.
	Nodes map[string]*Node
	// order is the topological order, computed at build time.
	order []string
	// cyclic holds job IDs that participate in a dependency cycle. GitHub
	// rejects such workflows, but a file on disk can still contain one and the
	// analyzer must not hang or panic on it.
	cyclic []string
}

// Build constructs the dependency graph for a workflow.
//
// A `needs:` entry naming a job that does not exist is ignored rather than
// treated as an error: the workflow is invalid, but the remaining edges are
// still worth analyzing.
//
// Runs in O(V + E).
func Build(workflow parser.Workflow) *Graph {
	g := &Graph{Nodes: make(map[string]*Node, len(workflow.Jobs))}

	// Job IDs are iterated in sorted order throughout so that results do not
	// depend on Go's randomized map iteration.
	ids := make([]string, 0, len(workflow.Jobs))
	for id := range workflow.Jobs {
		ids = append(ids, id)
	}
	sort.Strings(ids)

	for _, id := range ids {
		g.Nodes[id] = &Node{ID: id, Job: workflow.Jobs[id]}
	}

	for _, id := range ids {
		node := g.Nodes[id]
		for _, need := range normalizeNeeds(workflow.Jobs[id].Needs) {
			dep, ok := g.Nodes[need]
			if !ok {
				continue // dangling dependency; workflow is invalid
			}
			node.Needs = append(node.Needs, need)
			dep.Dependents = append(dep.Dependents, id)
		}
	}

	g.order, g.cyclic = g.topologicalOrder()
	return g
}

// TopologicalOrder returns job IDs ordered so that every job appears after all
// of its dependencies.
//
// Jobs involved in a dependency cycle are excluded; use Cyclic to retrieve them.
func (g *Graph) TopologicalOrder() []string { return g.order }

// Cyclic returns the job IDs that participate in a dependency cycle, if any.
func (g *Graph) Cyclic() []string { return g.cyclic }

// topologicalOrder implements Kahn's algorithm.
//
// Kahn is used rather than a DFS-based sort because it detects cycles as a
// natural by-product: any node never reaching in-degree zero is in, or
// downstream of, a cycle. Ties are broken by job ID so the order is
// deterministic for a given workflow.
//
// Runs in O(V log V + E); the log factor is the deterministic tie-break.
func (g *Graph) topologicalOrder() (order []string, cyclic []string) {
	inDegree := make(map[string]int, len(g.Nodes))
	for id, node := range g.Nodes {
		inDegree[id] = len(node.Needs)
	}

	ready := make([]string, 0, len(g.Nodes))
	for id, deg := range inDegree {
		if deg == 0 {
			ready = append(ready, id)
		}
	}
	sort.Strings(ready)

	order = make([]string, 0, len(g.Nodes))
	for len(ready) > 0 {
		id := ready[0]
		ready = ready[1:]
		order = append(order, id)

		// Releasing a node can make several dependents ready at once; collect
		// them and merge in sorted order to keep the result deterministic.
		var freed []string
		for _, dep := range g.Nodes[id].Dependents {
			inDegree[dep]--
			if inDegree[dep] == 0 {
				freed = append(freed, dep)
			}
		}
		if len(freed) > 0 {
			ready = append(ready, freed...)
			sort.Strings(ready)
		}
	}

	if len(order) < len(g.Nodes) {
		for id := range g.Nodes {
			if inDegree[id] > 0 {
				cyclic = append(cyclic, id)
			}
		}
		sort.Strings(cyclic)
	}

	return order, cyclic
}

// Ancestors returns every job that the given job transitively depends on.
//
// Used to explain a finding: the path from where data became untrusted to where
// it was executed.
func (g *Graph) Ancestors(id string) []string {
	seen := map[string]bool{}
	var walk func(string)
	walk = func(cur string) {
		node, ok := g.Nodes[cur]
		if !ok {
			return
		}
		for _, need := range node.Needs {
			if seen[need] {
				continue
			}
			seen[need] = true
			walk(need)
		}
	}
	walk(id)

	out := make([]string, 0, len(seen))
	for a := range seen {
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// normalizeNeeds flattens the scalar-or-list `needs:` field.
func normalizeNeeds(needs interface{}) []string {
	switch v := needs.(type) {
	case string:
		if v == "" {
			return nil
		}
		return []string{v}
	case []interface{}:
		out := make([]string, 0, len(v))
		for _, item := range v {
			if s, ok := item.(string); ok && s != "" {
				out = append(out, s)
			}
		}
		return out
	case []string:
		return v
	}
	return nil
}

// String renders the graph in dependency order, for debugging.
func (g *Graph) String() string {
	s := ""
	for _, id := range g.order {
		s += fmt.Sprintf("%s <- %v\n", id, g.Nodes[id].Needs)
	}
	for _, id := range g.cyclic {
		s += fmt.Sprintf("%s <- (cycle)\n", id)
	}
	return s
}
