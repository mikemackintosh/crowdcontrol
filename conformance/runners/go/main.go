// Conformance runner — the Go reference implementation.
//
// Reads every conformance/suite/*.json file, evaluates the embedded policy
// against the embedded input, and verifies the results match the expected
// decisions. Exits 0 on full pass, 1 on any failure.
//
// Usage:
//
//	go run ./conformance/runners/go -suite ./conformance/suite
//	go run ./conformance/runners/go -suite ./conformance/suite -case 003_permit
//	go run ./conformance/runners/go -suite ./conformance/suite -v
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/mikemackintosh/crowdcontrol"
	"github.com/mikemackintosh/crowdcontrol/types"
)

type expectedDecision struct {
	Rule            string `json:"rule"`
	Kind            string `json:"kind"`
	Passed          bool   `json:"passed"`
	MessageContains string `json:"message_contains,omitempty"`
	MessageExact    string `json:"message_exact,omitempty"`
}

type expectation struct {
	Decisions []expectedDecision `json:"decisions"`
}

type conformanceCase struct {
	Name          string         `json:"name"`
	Description   string         `json:"description,omitempty"`
	Policy        string         `json:"policy"`
	Input         map[string]any `json:"input"`
	DefaultEffect string         `json:"default_effect,omitempty"`
	Expect        expectation    `json:"expect"`
}

func main() {
	suiteDir := flag.String("suite", "./conformance/suite", "directory containing conformance/*.json cases")
	filter := flag.String("case", "", "only run cases whose name contains this substring")
	verbose := flag.Bool("v", false, "show all results, not just failures")
	flag.Parse()

	entries, err := os.ReadDir(*suiteDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading suite dir %s: %v\n", *suiteDir, err)
		os.Exit(2)
	}

	var files []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		files = append(files, filepath.Join(*suiteDir, e.Name()))
	}
	sort.Strings(files)

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "no conformance cases found in %s\n", *suiteDir)
		os.Exit(2)
	}

	pass, fail := 0, 0
	for _, f := range files {
		c, err := loadCase(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s — load error: %v\n", filepath.Base(f), err)
			fail++
			continue
		}
		if *filter != "" && !strings.Contains(c.Name, *filter) {
			continue
		}

		ok, msg := runCase(c)
		if ok {
			pass++
			if *verbose {
				fmt.Printf("PASS: %s\n", c.Name)
			}
		} else {
			fail++
			fmt.Printf("FAIL: %s — %s\n", c.Name, msg)
		}
	}

	fmt.Printf("\n%d passed, %d failed\n", pass, fail)
	if fail > 0 {
		os.Exit(1)
	}
}

func loadCase(path string) (*conformanceCase, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c conformanceCase
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	if c.Name == "" {
		c.Name = strings.TrimSuffix(filepath.Base(path), ".json")
	}
	return &c, nil
}

func runCase(c *conformanceCase) (bool, string) {
	var opts []crowdcontrol.Option
	switch c.DefaultEffect {
	case "", "allow":
		opts = append(opts, crowdcontrol.WithDefaultEffect(types.DefaultAllow))
	case "deny":
		opts = append(opts, crowdcontrol.WithDefaultEffect(types.DefaultDeny))
	default:
		return false, fmt.Sprintf("unknown default_effect %q", c.DefaultEffect)
	}

	eng, err := crowdcontrol.NewFromSource([]string{c.Policy}, opts...)
	if err != nil {
		return false, fmt.Sprintf("parsing policy: %v", err)
	}

	results := eng.Evaluate(c.Input)

	if len(results) != len(c.Expect.Decisions) {
		return false, fmt.Sprintf("expected %d decisions, got %d (results: %s)",
			len(c.Expect.Decisions), len(results), summarize(results))
	}

	for i, want := range c.Expect.Decisions {
		got := results[i]
		if got.Rule != want.Rule {
			return false, fmt.Sprintf("decision[%d]: rule = %q, want %q", i, got.Rule, want.Rule)
		}
		if got.Kind != want.Kind {
			return false, fmt.Sprintf("decision[%d] (%s): kind = %q, want %q", i, got.Rule, got.Kind, want.Kind)
		}
		if got.Passed != want.Passed {
			return false, fmt.Sprintf("decision[%d] (%s): passed = %v, want %v", i, got.Rule, got.Passed, want.Passed)
		}
		if want.MessageExact != "" && got.Message != want.MessageExact {
			return false, fmt.Sprintf("decision[%d] (%s): message = %q, want exact %q",
				i, got.Rule, got.Message, want.MessageExact)
		}
		if want.MessageContains != "" && !strings.Contains(got.Message, want.MessageContains) {
			return false, fmt.Sprintf("decision[%d] (%s): message = %q, want contains %q",
				i, got.Rule, got.Message, want.MessageContains)
		}
	}

	return true, ""
}

func summarize(results []crowdcontrol.Result) string {
	parts := make([]string, len(results))
	for i, r := range results {
		parts[i] = fmt.Sprintf("[%s/%s passed=%v]", r.Rule, r.Kind, r.Passed)
	}
	return strings.Join(parts, " ")
}
