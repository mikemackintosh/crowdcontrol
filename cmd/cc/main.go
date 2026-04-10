// Command cc is the CrowdControl reference CLI. It loads .cc policy files,
// evaluates them against JSON input, validates them against an optional
// schema, or runs JSON-defined test suites against them.
//
// Usage:
//
//	cc evaluate --input doc.json --policy ./policies [--policy ./more] [--explain]
//	cc validate --policy ./policies [--schema schema.json] [path/to/file.cc ...]
//	cc test ./tests/                                  # run a directory of test files
//	cc parse path/to/file.cc                          # syntax-check a single file
//	cc serve --policy ./policies [--addr :8080]       # run as an HTTP PDP
//	cc version
//
// cc has zero non-stdlib dependencies. It is the reference implementation
// for SDKs in other languages — every native port should produce the same
// decisions for the same inputs.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/mikemackintosh/crowdcontrol"
	"github.com/mikemackintosh/crowdcontrol/evaluator"
	"github.com/mikemackintosh/crowdcontrol/parser"
	"github.com/mikemackintosh/crowdcontrol/types"
)

func main() {
	log.SetFlags(0)
	log.SetPrefix("cc: ")

	if len(os.Args) < 2 {
		usage()
		os.Exit(2)
	}

	switch os.Args[1] {
	case "evaluate", "eval":
		runEvaluate(os.Args[2:])
	case "validate":
		runValidate(os.Args[2:])
	case "test":
		runTest(os.Args[2:])
	case "parse":
		runParse(os.Args[2:])
	case "serve":
		runServe(os.Args[2:])
	case "version", "--version", "-v":
		fmt.Printf("cc %s\n", crowdcontrol.Version)
	case "help", "--help", "-h":
		usage()
	default:
		fmt.Fprintf(os.Stderr, "cc: unknown command %q\n\n", os.Args[1])
		usage()
		os.Exit(2)
	}
}

func usage() {
	fmt.Fprint(os.Stderr, `cc — CrowdControl reference CLI

USAGE:
    cc <command> [options]

COMMANDS:
    evaluate   Run policies against an input document
    validate   Syntax-check .cc files; optionally validate against a schema
    test       Run JSON test suites against policies
    parse      Parse a single .cc file and print the rule summary
    serve      Run as an HTTP policy decision point (PDP)
    version    Print version information
    help       Show this message

EXAMPLES:
    cc evaluate --input doc.json --policy ./policies
    cc evaluate --input doc.json --policy ./policies --explain
    cc evaluate --input doc.json --policy ./policies --default-effect deny
    cc validate --policy ./policies --schema ./schema.json
    cc test ./tests/
    cc serve --policy ./policies --addr :8080 --audit-log /var/log/cc.jsonl

For each command, run "cc <command> --help" for command-specific options.
`)
}

// ---------------------------------------------------------------------------
// evaluate
// ---------------------------------------------------------------------------

func runEvaluate(args []string) {
	fs := flag.NewFlagSet("evaluate", flag.ExitOnError)
	inputFile := fs.String("input", "", "path to input JSON document (required)")
	explain := fs.Bool("explain", false, "show per-condition evaluation trace")
	defaultEffect := fs.String("default-effect", "allow", "default effect when no rule matches: allow | deny")

	var policyDirs multiFlag
	fs.Var(&policyDirs, "policy", "policy directory (repeatable)")
	fs.Parse(args)

	if *inputFile == "" {
		log.Fatal("evaluate requires --input")
	}
	if len(policyDirs) == 0 {
		log.Fatal("evaluate requires at least one --policy directory")
	}

	data, err := os.ReadFile(*inputFile)
	if err != nil {
		log.Fatalf("reading input %s: %v", *inputFile, err)
	}

	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		log.Fatalf("parsing input JSON: %v", err)
	}

	var opts []evaluator.Option
	switch *defaultEffect {
	case "allow":
		opts = append(opts, evaluator.WithDefaultEffect(types.DefaultAllow))
	case "deny":
		opts = append(opts, evaluator.WithDefaultEffect(types.DefaultDeny))
	default:
		log.Fatalf("invalid --default-effect %q (allow|deny)", *defaultEffect)
	}
	if *explain {
		opts = append(opts, evaluator.WithExplain(true))
	}

	eng, err := crowdcontrol.New(policyDirs, opts...)
	if err != nil {
		log.Fatalf("loading policies: %v", err)
	}

	results := eng.Evaluate(doc)

	if *explain {
		fmt.Print(evaluator.FormatExplain(results))
	}
	output, allPassed := evaluator.FormatResults(results)
	fmt.Print(output)

	if !allPassed {
		os.Exit(1)
	}
}

// ---------------------------------------------------------------------------
// validate
// ---------------------------------------------------------------------------

func runValidate(args []string) {
	fs := flag.NewFlagSet("validate", flag.ExitOnError)
	var policyDirs multiFlag
	fs.Var(&policyDirs, "policy", "policy directory (repeatable)")
	schemaFile := fs.String("schema", "", "path to JSON schema file for field validation")
	fs.Parse(args)

	var files []string
	for _, dir := range policyDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			log.Fatalf("reading directory %s: %v", dir, err)
		}
		for _, entry := range entries {
			if !entry.IsDir() && strings.HasSuffix(entry.Name(), crowdcontrol.PolicyExt) {
				files = append(files, filepath.Join(dir, entry.Name()))
			}
		}
	}
	files = append(files, fs.Args()...)

	if len(files) == 0 {
		log.Fatal("validate requires at least one --policy directory or file path")
	}

	var schema *types.Schema
	if *schemaFile != "" {
		s, err := loadSchema(*schemaFile)
		if err != nil {
			log.Fatalf("loading schema %s: %v", *schemaFile, err)
		}
		schema = s
	}

	allValid := true
	totalRules := 0
	var allPolicies []*types.Policy
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s — %v\n", f, err)
			allValid = false
			continue
		}
		policy, err := parser.Parse(string(data))
		if err != nil {
			fmt.Fprintf(os.Stderr, "FAIL: %s — %v\n", f, err)
			allValid = false
			continue
		}
		totalRules += len(policy.Rules)
		allPolicies = append(allPolicies, policy)
		fmt.Fprintf(os.Stderr, "  OK: %s (%d rules)\n", f, len(policy.Rules))
	}

	if schema != nil && len(allPolicies) > 0 {
		warnings := evaluator.ValidatePolicy(allPolicies, schema)
		if len(warnings) > 0 {
			fmt.Fprintf(os.Stderr, "\nSchema warnings:\n")
			fmt.Fprint(os.Stderr, evaluator.FormatWarnings(warnings))
			fmt.Fprintf(os.Stderr, "%d warning(s) found\n", len(warnings))
		}
	}

	if allValid {
		fmt.Fprintf(os.Stderr, "PASS: %d files, %d rules\n", len(files), totalRules)
		return
	}
	fmt.Fprintf(os.Stderr, "FAIL: validation errors found\n")
	os.Exit(1)
}

// loadSchema reads a JSON schema file describing expected field types.
//
//	{
//	  "fields": {
//	    "resource.type": "string",
//	    "user.teams": "list",
//	    "approvals": "number"
//	  }
//	}
func loadSchema(path string) (*types.Schema, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var raw struct {
		Fields map[string]string `json:"fields"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, fmt.Errorf("parsing schema JSON: %w", err)
	}

	schema := &types.Schema{Fields: make(map[string]types.FieldType, len(raw.Fields))}
	for field, typeName := range raw.Fields {
		switch types.FieldType(typeName) {
		case types.FieldString, types.FieldNumber, types.FieldBool, types.FieldList, types.FieldMap, types.FieldAny:
			schema.Fields[field] = types.FieldType(typeName)
		default:
			return nil, fmt.Errorf("unknown type %q for field %q (valid: string, number, bool, list, map, any)", typeName, field)
		}
	}
	return schema, nil
}

// ---------------------------------------------------------------------------
// test
// ---------------------------------------------------------------------------

func runTest(args []string) {
	fs := flag.NewFlagSet("test", flag.ExitOnError)
	fs.Parse(args)

	var files []string
	for _, arg := range fs.Args() {
		info, err := os.Stat(arg)
		if err != nil {
			log.Fatalf("reading %s: %v", arg, err)
		}
		if info.IsDir() {
			entries, err := os.ReadDir(arg)
			if err != nil {
				log.Fatalf("reading directory %s: %v", arg, err)
			}
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasSuffix(name, ".json") {
					files = append(files, filepath.Join(arg, name))
				}
			}
		} else {
			files = append(files, arg)
		}
	}

	if len(files) == 0 {
		log.Fatal("test requires at least one test file or directory")
	}

	totalTests, totalPassed, totalFailed := 0, 0, 0
	for _, f := range files {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("reading %s: %v", f, err)
		}

		var suite testSuite
		if err := json.Unmarshal(data, &suite); err != nil {
			log.Fatalf("parsing %s: %v", f, err)
		}

		fmt.Fprintf(os.Stderr, "=== %s ===\n", f)
		for _, tc := range suite.Tests {
			totalTests++
			if runTestCase(tc) {
				totalPassed++
				fmt.Fprintf(os.Stderr, "  PASS: %s\n", tc.Name)
				continue
			}
			totalFailed++
			fmt.Fprintf(os.Stderr, "  FAIL: %s\n", tc.Name)
		}
	}

	fmt.Fprintf(os.Stderr, "\n%d tests, %d passed, %d failed\n", totalTests, totalPassed, totalFailed)
	if totalFailed > 0 {
		os.Exit(1)
	}
}

type testSuite struct {
	Tests []testCase `json:"tests"`
}

type testCase struct {
	Name   string         `json:"name"`
	Policy string         `json:"policy"` // path to policy directory
	Input  map[string]any `json:"input"`
	Expect string         `json:"expect"` // "deny" | "allow" | "warn"
	Rule   string         `json:"rule"`   // optional: pin a specific rule
}

func runTestCase(tc testCase) bool {
	if tc.Policy == "" {
		fmt.Fprintf(os.Stderr, "    ERROR: test %q missing 'policy' field\n", tc.Name)
		return false
	}

	eng, err := evaluator.New([]string{tc.Policy})
	if err != nil {
		fmt.Fprintf(os.Stderr, "    ERROR: loading policies from %s: %v\n", tc.Policy, err)
		return false
	}

	results := eng.Evaluate(tc.Input)

	switch tc.Expect {
	case "deny":
		for _, r := range results {
			if !r.Passed && r.Kind == "forbid" {
				if tc.Rule == "" || r.Rule == tc.Rule {
					return true
				}
			}
		}
		if tc.Rule != "" {
			fmt.Fprintf(os.Stderr, "    expected rule %q to deny, but it did not\n", tc.Rule)
		} else {
			fmt.Fprintf(os.Stderr, "    expected a denial, but all rules passed\n")
		}
		return false

	case "allow", "pass":
		for _, r := range results {
			if !r.Passed && r.Kind != "warn" {
				if tc.Rule == "" || r.Rule == tc.Rule {
					fmt.Fprintf(os.Stderr, "    expected allow, but rule %q denied: %s\n", r.Rule, r.Message)
					return false
				}
			}
		}
		return true

	case "warn":
		for _, r := range results {
			if !r.Passed && r.Kind == "warn" {
				if tc.Rule == "" || r.Rule == tc.Rule {
					return true
				}
			}
		}
		fmt.Fprintf(os.Stderr, "    expected a warning, but none fired\n")
		return false

	default:
		fmt.Fprintf(os.Stderr, "    ERROR: unknown expect value %q (deny|allow|warn)\n", tc.Expect)
		return false
	}
}

// ---------------------------------------------------------------------------
// parse
// ---------------------------------------------------------------------------

func runParse(args []string) {
	fs := flag.NewFlagSet("parse", flag.ExitOnError)
	fs.Parse(args)
	if fs.NArg() == 0 {
		log.Fatal("parse requires at least one .cc file path")
	}

	for _, f := range fs.Args() {
		data, err := os.ReadFile(f)
		if err != nil {
			log.Fatalf("reading %s: %v", f, err)
		}
		policy, err := parser.Parse(string(data))
		if err != nil {
			log.Fatalf("parsing %s: %v", f, err)
		}
		fmt.Printf("%s: %d rules\n", f, len(policy.Rules))
		for _, r := range policy.Rules {
			fmt.Printf("  %s %q (%d conditions, %d unlesses)\n",
				r.Kind, r.Name, len(r.Conditions), len(r.Unlesses))
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

type multiFlag []string

func (m *multiFlag) String() string { return strings.Join(*m, ", ") }
func (m *multiFlag) Set(v string) error {
	*m = append(*m, v)
	return nil
}
