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

package platform

import "testing"

// fakePlatform is a minimal Platform implementation for registry tests.
type fakePlatform struct {
	name      string
	workflows []string
	detectErr error
}

func (f *fakePlatform) Name() string { return f.name }
func (f *fakePlatform) DetectWorkflows(string) ([]string, error) {
	return f.workflows, f.detectErr
}
func (f *fakePlatform) ParseWorkflow(string) (*Workflow, error)       { return &Workflow{}, nil }
func (f *fakePlatform) GetSecurityContext(*Workflow) *SecurityContext { return &SecurityContext{} }
func (f *fakePlatform) ValidateWorkflow(*Workflow) error              { return nil }

func TestRegistryRegisterGetList(t *testing.T) {
	r := NewPlatformRegistry()
	r.Register(&fakePlatform{name: "alpha"})
	r.Register(&fakePlatform{name: "beta"})

	got, err := r.Get("alpha")
	if err != nil {
		t.Fatalf("Get(alpha): %v", err)
	}
	if got.Name() != "alpha" {
		t.Errorf("Name = %q, want alpha", got.Name())
	}

	if _, err := r.Get("missing"); err == nil {
		t.Error("expected error for missing platform")
	}

	if list := r.List(); len(list) != 2 {
		t.Errorf("List len = %d, want 2", len(list))
	}
}

func TestRegistryDetectPlatform(t *testing.T) {
	r := NewPlatformRegistry()
	r.Register(&fakePlatform{name: "empty", workflows: nil})
	r.Register(&fakePlatform{name: "has-workflows", workflows: []string{"a.yml"}})

	p, err := r.DetectPlatform("/some/path")
	if err != nil {
		t.Fatalf("DetectPlatform: %v", err)
	}
	if p.Name() != "has-workflows" {
		t.Errorf("detected %q, want has-workflows", p.Name())
	}
}

func TestRegistryDetectPlatform_None(t *testing.T) {
	r := NewPlatformRegistry()
	r.Register(&fakePlatform{name: "empty", workflows: nil})

	if _, err := r.DetectPlatform("/some/path"); err == nil {
		t.Error("expected error when no platform detects workflows")
	}
}
