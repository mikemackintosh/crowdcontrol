package crowdcontrol_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/mikemackintosh/crowdcontrol"
)

const samplePolicy = `
forbid "no-public-s3" {
  description "Public-read S3 buckets are forbidden in production"
  resource.type == "aws_s3_bucket"
  resource.change.after.acl == "public-read"
  message "bucket {resource.name} would be public"
}

permit "security-team-override" {
  resource.type == "aws_s3_bucket"
  author.teams contains "security"
  message "approved by security team"
}

warn "large-blast-radius" {
  count(plan.changes) > 5
  message "this PR touches {count(plan.changes)} resources"
}
`

func writePolicy(t *testing.T, dir, name, source string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(source), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestEngineFromSource(t *testing.T) {
	eng, err := crowdcontrol.NewFromSource([]string{samplePolicy})
	if err != nil {
		t.Fatalf("NewFromSource: %v", err)
	}

	doc := map[string]any{
		"resource": map[string]any{
			"type": "aws_s3_bucket",
			"name": "logs",
			"change": map[string]any{
				"after": map[string]any{"acl": "public-read"},
			},
		},
		"author": map[string]any{
			"teams": []any{"platform"},
		},
		"plan": map[string]any{"changes": []any{1, 2, 3}},
	}

	results := eng.Evaluate(doc)

	var deniedNoPublic bool
	for _, r := range results {
		if r.Rule == "no-public-s3" && r.Kind == "forbid" && !r.Passed {
			deniedNoPublic = true
		}
	}
	if !deniedNoPublic {
		t.Errorf("expected no-public-s3 forbid to fire, got results: %+v", results)
	}
}

func TestEngineFromDirectory(t *testing.T) {
	dir := t.TempDir()
	writePolicy(t, dir, "rules.cc", samplePolicy)

	eng, err := crowdcontrol.New([]string{dir})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if got := len(eng.Policies()); got != 1 {
		t.Fatalf("expected 1 policy loaded, got %d", got)
	}

	doc := map[string]any{
		"resource": map[string]any{
			"type": "aws_s3_bucket",
			"name": "logs",
			"change": map[string]any{
				"after": map[string]any{"acl": "private"},
			},
		},
		"author": map[string]any{"teams": []any{}},
		"plan":   map[string]any{"changes": []any{}},
	}

	results := eng.Evaluate(doc)
	for _, r := range results {
		if r.Kind == "forbid" && !r.Passed {
			t.Errorf("unexpected forbid denial: %+v", r)
		}
	}
}

func TestPermitOverridesNothingAtTopLevel(t *testing.T) {
	// At the engine level (no Thera adapter), permit firing does NOT override
	// a forbid denial. That semantic is part of the Thera adapter, not the
	// core engine. This test pins that contract.
	eng, err := crowdcontrol.NewFromSource([]string{samplePolicy})
	if err != nil {
		t.Fatal(err)
	}

	doc := map[string]any{
		"resource": map[string]any{
			"type": "aws_s3_bucket",
			"name": "logs",
			"change": map[string]any{
				"after": map[string]any{"acl": "public-read"},
			},
		},
		"author": map[string]any{"teams": []any{"security"}},
		"plan":   map[string]any{"changes": []any{}},
	}

	results := eng.Evaluate(doc)

	var forbidFired, permitFired bool
	for _, r := range results {
		if r.Rule == "no-public-s3" && !r.Passed {
			forbidFired = true
		}
		if r.Rule == "security-team-override" && r.Kind == "permit" && r.Message != "" {
			permitFired = true
		}
	}
	if !forbidFired {
		t.Error("expected forbid to fire even with permit present")
	}
	if !permitFired {
		t.Error("expected permit to fire and emit message")
	}
}

func TestSchemaValidation(t *testing.T) {
	policy := `
forbid "typo-check" {
  resoruce.type == "aws_s3_bucket"
  message "should warn about resoruce typo"
}
`
	eng, err := crowdcontrol.NewFromSource([]string{policy})
	if err != nil {
		t.Fatal(err)
	}

	schema := &crowdcontrol.Schema{
		Fields: map[string]crowdcontrol.FieldType{
			"resource.type": crowdcontrol.FieldString,
		},
	}

	warnings := eng.Validate(schema)
	if len(warnings) == 0 {
		t.Error("expected at least one schema warning for unknown field 'resoruce.type'")
	}
}

func TestVersionConstantPresent(t *testing.T) {
	if crowdcontrol.Version == "" {
		t.Error("Version constant should be set")
	}
	if crowdcontrol.PolicyExt != ".cc" {
		t.Errorf("PolicyExt = %q, want .cc", crowdcontrol.PolicyExt)
	}
}
