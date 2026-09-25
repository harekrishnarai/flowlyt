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

package matcher

import "testing"

// FuzzScan checks that the Aho-Corasick automaton never panics and agrees with
// a naive substring search for the reported matches.
func FuzzScan(f *testing.F) {
	f.Add("on: pull_request_target\njobs:", "pull_request_target")
	f.Add("", "x")
	f.Add("aaaa", "aa")
	f.Add("curl ${{ secrets.TOKEN }}", "secrets")
	f.Add("no match here", "absent")
	f.Fuzz(func(t *testing.T, text, literal string) {
		m := New([]string{literal})
		got := m.Scan(text)
		want := literal != "" && contains(text, literal)
		if len(got) > 0 && got[0] != want {
			t.Fatalf("Scan(%q) with literal %q = %v, want %v", text, literal, got[0], want)
		}
	})
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
