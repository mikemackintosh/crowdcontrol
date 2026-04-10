package evaluator

import (
	"os"
	"strings"
	"testing"

	"github.com/mikemackintosh/crowdcontrol/parser"
	"github.com/mikemackintosh/crowdcontrol/types"
)

// ===========================================================================
// Generic engine tests — pure field comparisons
// ===========================================================================

func TestFieldEquals(t *testing.T) {
	doc := map[string]any{
		"user": map[string]any{"role": "admin"},
	}
	results := eval(t, `forbid "admin-gate" {
  user.role == "admin"
  message "admins not allowed"
}`, doc)
	assertDeniedRule(t, results, "admin-gate")
}

func TestFieldNotEquals(t *testing.T) {
	doc := map[string]any{
		"user": map[string]any{"role": "viewer"},
	}
	results := eval(t, `forbid "admin-gate" {
  user.role == "admin"
  message "admins not allowed"
}`, doc)
	assertAllPassed(t, results)
}

func TestFieldIn(t *testing.T) {
	doc := map[string]any{
		"event": map[string]any{"type": "deploy"},
	}
	results := eval(t, `forbid "blocked-events" {
  event.type in ["deploy", "rollback"]
  message "event blocked"
}`, doc)
	assertDeniedRule(t, results, "blocked-events")
}

func TestFieldMatches(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
	}
	results := eval(t, `forbid "aws-gate" {
  resource.type matches "aws_iam_*"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "aws-gate")
}

func TestFieldMatchesNoMatch(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "google_compute_instance"},
	}
	results := eval(t, `forbid "aws-gate" {
  resource.type matches "aws_*"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestNestedFieldAccess(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{
			"type": "aws_s3_bucket",
			"change": map[string]any{
				"after": map[string]any{
					"acl": "public-read",
				},
			},
		},
	}
	results := eval(t, `forbid "no-public" {
  resource.change.after.acl == "public-read"
  message "no public buckets"
}`, doc)
	assertDeniedRule(t, results, "no-public")
}

func TestNumericComparison(t *testing.T) {
	doc := map[string]any{
		"metrics": map[string]any{"error_rate": 15},
	}
	results := eval(t, `forbid "high-errors" {
  metrics.error_rate > 10
  message "error rate too high"
}`, doc)
	assertDeniedRule(t, results, "high-errors")
}

func TestBooleanField(t *testing.T) {
	doc := map[string]any{
		"request": map[string]any{"dry_run": true},
	}
	results := eval(t, `forbid "no-dry-run" {
  request.dry_run == true
  message "dry run not allowed"
}`, doc)
	assertDeniedRule(t, results, "no-dry-run")
}

func TestUnless(t *testing.T) {
	doc := map[string]any{
		"user":     map[string]any{"role": "admin"},
		"resource": map[string]any{"type": "sensitive"},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "sensitive"
  unless user.role == "admin"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestMultipleUnless_NoneSaves(t *testing.T) {
	doc := map[string]any{
		"user":     map[string]any{"role": "viewer"},
		"resource": map[string]any{"type": "sensitive"},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "sensitive"
  unless user.role == "admin"
  unless user.role == "superadmin"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

// ===========================================================================
// contains operator
// ===========================================================================

func TestContains_ListMembership(t *testing.T) {
	doc := map[string]any{
		"tags": []any{"production", "critical", "monitored"},
	}
	results := eval(t, `forbid "gate" {
  tags contains "critical"
  message "critical resource"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestContains_NotInList(t *testing.T) {
	doc := map[string]any{
		"tags": []any{"staging", "test"},
	}
	results := eval(t, `forbid "gate" {
  tags contains "critical"
  message "critical resource"
}`, doc)
	assertAllPassed(t, results)
}

func TestContains_EmptyList(t *testing.T) {
	doc := map[string]any{
		"tags": []any{},
	}
	results := eval(t, `forbid "gate" {
  tags contains "anything"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestContains_StringSubstring(t *testing.T) {
	doc := map[string]any{
		"msg": map[string]any{"text": "hello world"},
	}
	results := eval(t, `forbid "gate" {
  msg.text contains "world"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestContains_InUnless(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "sensitive"},
		"teams":    []any{"security", "platform"},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "sensitive"
  unless teams contains "security"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// has operator
// ===========================================================================

func TestHas_FieldExists(t *testing.T) {
	doc := map[string]any{
		"config": map[string]any{"timeout": 30},
	}
	results := eval(t, `forbid "gate" {
  has config.timeout
  message "timeout configured"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestHas_FieldMissing(t *testing.T) {
	doc := map[string]any{
		"config": map[string]any{"retries": 3},
	}
	results := eval(t, `forbid "gate" {
  has config.timeout
  message "timeout configured"
}`, doc)
	assertAllPassed(t, results)
}

func TestHas_Negated(t *testing.T) {
	doc := map[string]any{
		"config": map[string]any{"retries": 3},
	}
	results := eval(t, `forbid "gate" {
  not has config.timeout
  message "timeout not configured"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

// ===========================================================================
// not operator
// ===========================================================================

func TestNot(t *testing.T) {
	doc := map[string]any{
		"env": map[string]any{"name": "staging"},
	}
	results := eval(t, `forbid "non-prod" {
  not env.name == "production"
  message "only production allowed"
}`, doc)
	assertDeniedRule(t, results, "non-prod")
}

func TestNotNegatesTrue(t *testing.T) {
	doc := map[string]any{
		"env": map[string]any{"name": "production"},
	}
	results := eval(t, `forbid "non-prod" {
  not env.name == "production"
  message "only production allowed"
}`, doc)
	assertAllPassed(t, results)
}

func TestNotWithGlob(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "google_compute_instance"},
	}
	results := eval(t, `forbid "aws-only" {
  not resource.type matches "aws_*"
  message "only AWS allowed"
}`, doc)
	assertDeniedRule(t, results, "aws-only")
}

// ===========================================================================
// or operator
// ===========================================================================

func TestOr(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_kms_key"},
	}
	results := eval(t, `forbid "sensitive" {
  resource.type == "aws_iam_role" or resource.type == "aws_kms_key"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "sensitive")
}

func TestOrNoMatch(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_s3_bucket"},
	}
	results := eval(t, `forbid "sensitive" {
  resource.type == "aws_iam_role" or resource.type == "aws_kms_key"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestOrThreeWay(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "c"},
	}
	results := eval(t, `forbid "multi" {
  resource.type == "a" or resource.type == "b" or resource.type == "c"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "multi")
}

func TestOrWithAnd(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"env":      map[string]any{"name": "staging"},
	}
	results := eval(t, `forbid "prod-gate" {
  resource.type == "aws_iam_role" or resource.type == "aws_kms_key"
  env.name == "production"
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // env doesn't match
}

// ===========================================================================
// count() aggregates
// ===========================================================================

func TestCountList(t *testing.T) {
	doc := map[string]any{
		"items": []any{"a", "b", "c", "d", "e", "f"},
	}
	results := eval(t, `forbid "too-many" {
  count(items) > 5
  message "too many items"
}`, doc)
	assertDeniedRule(t, results, "too-many")
}

func TestCountListBelowThreshold(t *testing.T) {
	doc := map[string]any{
		"items": []any{"a", "b"},
	}
	results := eval(t, `forbid "too-many" {
  count(items) > 5
  message "too many items"
}`, doc)
	assertAllPassed(t, results)
}

func TestCountNestedList(t *testing.T) {
	doc := map[string]any{
		"plan": map[string]any{
			"destroys": []any{
				map[string]any{"address": "a"},
				map[string]any{"address": "b"},
				map[string]any{"address": "c"},
			},
		},
	}
	results := eval(t, `forbid "blast" {
  count(plan.destroys) > 2
  message "too many destroys"
}`, doc)
	assertDeniedRule(t, results, "blast")
}

func TestCountNumericField(t *testing.T) {
	doc := map[string]any{
		"stats": map[string]any{"error_count": 10},
	}
	results := eval(t, `forbid "errors" {
  count(stats.error_count) > 5
  message "too many errors"
}`, doc)
	assertDeniedRule(t, results, "errors")
}

// ===========================================================================
// any / all quantifiers
// ===========================================================================

func TestAnyMatches(t *testing.T) {
	doc := map[string]any{
		"files": map[string]any{
			"changed": []any{"src/main.go", "infra/vpc.tf", "README.md"},
		},
	}
	results := eval(t, `forbid "infra-gate" {
  any files.changed matches "infra/*"
  message "infra changes blocked"
}`, doc)
	assertDeniedRule(t, results, "infra-gate")
}

func TestAnyNoMatch(t *testing.T) {
	doc := map[string]any{
		"files": map[string]any{
			"changed": []any{"src/main.go", "README.md"},
		},
	}
	results := eval(t, `forbid "infra-gate" {
  any files.changed matches "infra/*"
  message "infra changes blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestAnyInList(t *testing.T) {
	doc := map[string]any{
		"files": map[string]any{
			"changed": []any{"main.tf", "secrets.tf"},
		},
	}
	results := eval(t, `forbid "sensitive" {
  any files.changed in ["secrets.tf", "iam.tf"]
  message "sensitive file"
}`, doc)
	assertDeniedRule(t, results, "sensitive")
}

func TestAnyEmptyList(t *testing.T) {
	doc := map[string]any{
		"files": map[string]any{
			"changed": []any{},
		},
	}
	results := eval(t, `forbid "gate" {
  any files.changed matches "*"
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // any over empty list is false
}

func TestAllEquals(t *testing.T) {
	doc := map[string]any{
		"tags": []any{"approved", "approved", "approved"},
	}
	results := eval(t, `forbid "not-all-approved" {
  not all tags == "approved"
  message "all tags must be approved"
}`, doc)
	assertAllPassed(t, results) // all are "approved", so not-all is false
}

func TestAllEqualsOneFailure(t *testing.T) {
	doc := map[string]any{
		"tags": []any{"approved", "pending", "approved"},
	}
	results := eval(t, `forbid "not-all-approved" {
  not all tags == "approved"
  message "all tags must be approved"
}`, doc)
	assertDeniedRule(t, results, "not-all-approved")
}

func TestAnyWithMapElements(t *testing.T) {
	doc := map[string]any{
		"users": []any{
			map[string]any{"name": "alice", "role": "admin"},
			map[string]any{"name": "bob", "role": "viewer"},
		},
	}
	results := eval(t, `forbid "gate" {
  any users == "alice"
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // maps don't match string comparison
}

// ===========================================================================
// warn rules
// ===========================================================================

func TestWarnDoesNotBlock(t *testing.T) {
	doc := map[string]any{
		"items": []any{"a"},
	}
	results := eval(t, `warn "low-items" {
  count(items) < 5
  message "consider adding more items"
}`, doc)
	_, allPassed := FormatResults(toGenericResults(results))
	if !allPassed {
		t.Error("warn should not cause failure")
	}
}

// ===========================================================================
// permit rules
// ===========================================================================

func TestPermitSetsMessage(t *testing.T) {
	doc := map[string]any{
		"user":     map[string]any{"role": "admin"},
		"resource": map[string]any{"type": "sensitive"},
	}
	results := eval(t, `permit "admin-override" {
  user.role == "admin"
  resource.type == "sensitive"
  message "admin permitted"
}`, doc)
	for _, r := range results {
		if r.Rule == "admin-override" {
			if !r.Passed {
				t.Error("permit should pass")
			}
			if r.Message != "admin permitted" {
				t.Errorf("expected message, got %q", r.Message)
			}
		}
	}
}

// ===========================================================================
// metadata
// ===========================================================================

func TestMetadata(t *testing.T) {
	doc := map[string]any{
		"x": map[string]any{"y": "z"},
	}
	results := eval(t, `forbid "gate" {
  description "test description"
  owner "test-owner"
  link "https://example.com"
  x.y == "z"
  message "blocked"
}`, doc)
	for _, r := range results {
		if r.Rule == "gate" {
			if r.Description != "test description" {
				t.Errorf("expected description, got %q", r.Description)
			}
			if r.Owner != "test-owner" {
				t.Errorf("expected owner, got %q", r.Owner)
			}
			if r.Link != "https://example.com" {
				t.Errorf("expected link, got %q", r.Link)
			}
		}
	}
}

func TestMetadataInOutput(t *testing.T) {
	doc := map[string]any{
		"x": map[string]any{"y": "z"},
	}
	results := eval(t, `forbid "gate" {
  owner "security"
  link "https://wiki.example.com"
  x.y == "z"
  message "blocked"
}`, doc)
	output, _ := FormatResults(toGenericResults(results))
	if !strings.Contains(output, "owner: security") {
		t.Errorf("expected owner in output: %s", output)
	}
	if !strings.Contains(output, "link: https://wiki.example.com") {
		t.Errorf("expected link in output: %s", output)
	}
}

// ===========================================================================
// message interpolation
// ===========================================================================

func TestInterpolation(t *testing.T) {
	doc := map[string]any{
		"user":     map[string]any{"name": "alice"},
		"env":      map[string]any{"region": "us-east-1"},
		"resource": map[string]any{"type": "aws_s3_bucket"},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "aws_s3_bucket"
  message "{user.name} in {env.region} blocked on {resource.type}"
}`, doc)
	for _, r := range results {
		if r.Rule == "gate" && !r.Passed {
			expected := "alice in us-east-1 blocked on aws_s3_bucket"
			if r.Message != expected {
				t.Errorf("expected %q, got %q", expected, r.Message)
			}
		}
	}
}

func TestInterpolationCount(t *testing.T) {
	doc := map[string]any{
		"items": []any{"a", "b", "c"},
	}
	results := eval(t, `forbid "gate" {
  count(items) > 2
  message "{count(items)} items is too many"
}`, doc)
	for _, r := range results {
		if r.Rule == "gate" && !r.Passed {
			if r.Message != "3 items is too many" {
				t.Errorf("expected count interpolation, got %q", r.Message)
			}
		}
	}
}

func TestInterpolationUnresolved(t *testing.T) {
	doc := map[string]any{
		"x": map[string]any{"y": "z"},
	}
	results := eval(t, `forbid "gate" {
  x.y == "z"
  message "missing: {nonexistent.field}"
}`, doc)
	for _, r := range results {
		if r.Rule == "gate" && !r.Passed {
			if !strings.Contains(r.Message, "{nonexistent.field}") {
				t.Errorf("unresolved placeholders should be kept as-is, got %q", r.Message)
			}
		}
	}
}

// ===========================================================================
// Flat field team/label checks (replaces old Functions interface tests)
// ===========================================================================

func TestTeamMembership_ViaContains(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"author":   map[string]any{"teams": []any{"security", "platform"}},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "aws_iam_role"
  unless author.teams contains "security"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestTeamMembership_Denied(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"author":   map[string]any{"teams": []any{"dev"}},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "aws_iam_role"
  unless author.teams contains "security"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestApproverTeams_ViaContains(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_route53_record"},
		"approver": map[string]any{"teams": []any{"security"}},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "aws_route53_record"
  unless approver.teams contains "security"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestLabels_ViaContains(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"labels":   []any{"security-approved", "reviewed"},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "aws_iam_role"
  unless labels contains "security-approved"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestAuthorName_InList(t *testing.T) {
	doc := map[string]any{
		"author": map[string]any{"name": "alice"},
	}
	results := eval(t, `forbid "gate" {
  author.name in ["alice", "bob"]
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestNotContains(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"author":   map[string]any{"teams": []any{"dev"}},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "aws_iam_role"
  not author.teams contains "security"
  message "must be security"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

// ===========================================================================
// Multiple rules
// ===========================================================================

func TestMultipleRules(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"env":      map[string]any{"name": "production"},
	}
	results := eval(t, `
forbid "rule-a" {
  resource.type == "aws_iam_role"
  message "a"
}
forbid "rule-b" {
  env.name == "production"
  message "b"
}
`, doc)
	assertDeniedRule(t, results, "rule-a")
	assertDeniedRule(t, results, "rule-b")
}

// ===========================================================================
// Edge cases
// ===========================================================================

func TestEmptyDocument(t *testing.T) {
	doc := map[string]any{}
	results := eval(t, `forbid "gate" {
  user.role == "admin"
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // field resolves to nil, doesn't match
}

func TestNilListInDocument(t *testing.T) {
	doc := map[string]any{
		"items": nil,
	}
	results := eval(t, `forbid "gate" {
  count(items) > 0
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // nil doesn't resolve as list
}

func TestArbitraryDocShape(t *testing.T) {
	doc := map[string]any{
		"order": map[string]any{
			"total":    250,
			"currency": "USD",
			"items": []any{
				map[string]any{"sku": "A", "qty": 2},
				map[string]any{"sku": "B", "qty": 1},
			},
		},
		"customer": map[string]any{
			"tier":    "free",
			"country": "US",
		},
	}
	results := eval(t, `
forbid "order-limit" {
  order.total > 200
  customer.tier == "free"
  message "free tier limited to $200 orders"
}

warn "international" {
  customer.country != "US"
  message "international order detected"
}
`, doc)
	assertDeniedRule(t, results, "order-limit")
	for _, r := range results {
		if r.Rule == "international" && !r.Passed {
			t.Error("international warn should not fire for US customer")
		}
	}
}

// ===========================================================================
// File loading
// ===========================================================================

func TestLoadFromDirectory(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/test.cc", `forbid "x" { count(items) > 0 message "y" }`)

	eng, err := New([]string{dir})
	if err != nil {
		t.Fatal(err)
	}

	doc := map[string]any{"items": []any{"a"}}
	results := eng.Evaluate(doc)
	assertDeniedRule(t, results, "x")
}

func TestNonexistentDir(t *testing.T) {
	eng, err := New([]string{"/nonexistent"})
	if err != nil {
		t.Fatal(err)
	}
	results := eng.Evaluate(map[string]any{})
	if len(results) != 0 {
		t.Errorf("expected 0 results from empty evaluator, got %d", len(results))
	}
}

func TestEvaluateJSON(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/test.cc", `forbid "x" { value.name == "test" message "y" }`)

	eng, err := New([]string{dir})
	if err != nil {
		t.Fatal(err)
	}

	results, err := eng.EvaluateJSON([]byte(`{"value": {"name": "test"}}`))
	if err != nil {
		t.Fatal(err)
	}
	assertDeniedRule(t, results, "x")
}

// ===========================================================================
// Field resolution edge cases
// ===========================================================================

func TestResolveField_DeepNesting(t *testing.T) {
	doc := map[string]any{
		"a": map[string]any{
			"b": map[string]any{
				"c": map[string]any{
					"d": "deep",
				},
			},
		},
	}
	results := eval(t, `forbid "deep" { a.b.c.d == "deep" message "found" }`, doc)
	assertDeniedRule(t, results, "deep")
}

func TestResolveField_MidPathNil(t *testing.T) {
	doc := map[string]any{
		"a": map[string]any{
			"b": nil,
		},
	}
	results := eval(t, `forbid "gate" { a.b.c == "x" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestResolveField_MidPathNonMap(t *testing.T) {
	doc := map[string]any{
		"a": map[string]any{
			"b": "string-not-map",
		},
	}
	results := eval(t, `forbid "gate" { a.b.c == "x" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestResolveField_TopLevelField(t *testing.T) {
	doc := map[string]any{"simple": "value"}
	val := ResolveField("simple", doc)
	if val != "value" {
		t.Errorf("expected 'value', got %v", val)
	}
}

// ===========================================================================
// Type coercion edge cases
// ===========================================================================

func TestCompare_StringVsInt(t *testing.T) {
	doc := map[string]any{
		"val": map[string]any{"x": "not-a-number"},
	}
	results := eval(t, `forbid "gate" { val.x > 5 message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestCompare_FloatField(t *testing.T) {
	doc := map[string]any{
		"metrics": map[string]any{"rate": 3.14},
	}
	results := eval(t, `forbid "gate" { metrics.rate > 3 message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestCompare_IntEquality(t *testing.T) {
	doc := map[string]any{
		"stats": map[string]any{"total": float64(5)},
	}
	results := eval(t, `forbid "gate" { stats.total == 5 message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestCompare_NilEquality(t *testing.T) {
	doc := map[string]any{}
	results := eval(t, `forbid "gate" { missing.field == "x" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestCompare_NilNotEquals(t *testing.T) {
	doc := map[string]any{}
	results := eval(t, `forbid "gate" { missing.field != "x" message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestCompare_BoolFalse(t *testing.T) {
	doc := map[string]any{
		"flag": map[string]any{"enabled": false},
	}
	results := eval(t, `forbid "gate" { flag.enabled == false message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestCompare_LessThanOrEqual(t *testing.T) {
	doc := map[string]any{"val": map[string]any{"x": 5}}
	results := eval(t, `forbid "gate" { val.x <= 5 message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestCompare_GreaterThanOrEqual(t *testing.T) {
	doc := map[string]any{"val": map[string]any{"x": 5}}
	results := eval(t, `forbid "gate" { val.x >= 5 message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestCompare_NotEqualsInt(t *testing.T) {
	doc := map[string]any{"val": map[string]any{"x": 3}}
	results := eval(t, `forbid "gate" { val.x != 5 message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

// ===========================================================================
// Glob matching edge cases
// ===========================================================================

func TestGlob_Suffix(t *testing.T) {
	doc := map[string]any{"f": map[string]any{"name": "report.pdf"}}
	results := eval(t, `forbid "gate" { f.name matches "*.pdf" message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestGlob_Middle(t *testing.T) {
	doc := map[string]any{"f": map[string]any{"name": "aws_iam_role_policy"}}
	results := eval(t, `forbid "gate" { f.name matches "aws_*_policy" message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestGlob_Exact(t *testing.T) {
	doc := map[string]any{"f": map[string]any{"name": "exact"}}
	results := eval(t, `forbid "gate" { f.name matches "exact" message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestGlob_ExactNoMatch(t *testing.T) {
	doc := map[string]any{"f": map[string]any{"name": "nope"}}
	results := eval(t, `forbid "gate" { f.name matches "exact" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestGlob_Star(t *testing.T) {
	doc := map[string]any{"f": map[string]any{"name": "anything"}}
	results := eval(t, `forbid "gate" { f.name matches "*" message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestGlob_EmptyString(t *testing.T) {
	doc := map[string]any{"f": map[string]any{"name": ""}}
	results := eval(t, `forbid "gate" { f.name matches "aws_*" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// count() edge cases
// ===========================================================================

func TestCount_EmptyList(t *testing.T) {
	doc := map[string]any{"items": []any{}}
	results := eval(t, `forbid "gate" { count(items) > 0 message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestCount_ExactBoundary(t *testing.T) {
	doc := map[string]any{"items": []any{"a", "b", "c", "d", "e"}}
	results := eval(t, `forbid "gate" { count(items) > 5 message "blocked" }`, doc)
	assertAllPassed(t, results) // 5 is not > 5
}

func TestCount_NonexistentPath(t *testing.T) {
	doc := map[string]any{}
	results := eval(t, `forbid "gate" { count(missing.list) > 0 message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestCount_NonListValue(t *testing.T) {
	doc := map[string]any{"val": map[string]any{"x": "string"}}
	results := eval(t, `forbid "gate" { count(val.x) > 0 message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestCount_LessThan(t *testing.T) {
	doc := map[string]any{"items": []any{"a"}}
	results := eval(t, `forbid "gate" { count(items) < 5 message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestCount_Equals(t *testing.T) {
	doc := map[string]any{"items": []any{"a", "b"}}
	results := eval(t, `forbid "gate" { count(items) == 2 message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

// ===========================================================================
// any/all edge cases
// ===========================================================================

func TestAny_NilField(t *testing.T) {
	doc := map[string]any{"items": nil}
	results := eval(t, `forbid "gate" { any items == "x" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestAll_EmptyList(t *testing.T) {
	doc := map[string]any{"items": []any{}}
	results := eval(t, `forbid "gate" { all items == "x" message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate") // all over empty → true → rule fires
}

func TestAny_NotEquals(t *testing.T) {
	doc := map[string]any{"items": []any{"a", "b", "c"}}
	results := eval(t, `forbid "gate" { any items != "a" message "blocked" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestAny_Equality(t *testing.T) {
	doc := map[string]any{"items": []any{"x", "y", "z"}}
	results := eval(t, `forbid "gate" { any items == "y" message "found y" }`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestAny_NoPredicateNilSafe(t *testing.T) {
	eng := NewFromPolicies([]*types.Policy{{
		Rules: []types.Rule{{
			Kind: "forbid",
			Name: "broken",
			Conditions: []types.Condition{{
				Type:      types.CondAny,
				ListField: "items",
				Predicate: nil,
			}},
			Message: "broken",
		}},
	}})
	doc := map[string]any{"items": []any{"a"}}
	results := eng.Evaluate(doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// or edge cases
// ===========================================================================

func TestOr_SingleItem(t *testing.T) {
	eng := NewFromPolicies([]*types.Policy{{
		Rules: []types.Rule{{
			Kind: "forbid",
			Name: "single-or",
			Conditions: []types.Condition{{
				Type: types.CondOr,
				OrGroup: []types.Condition{{
					Type:  types.CondField,
					Field: "x.y",
					Op:    "==",
					Value: "z",
				}},
			}},
			Message: "blocked",
		}},
	}})
	doc := map[string]any{"x": map[string]any{"y": "z"}}
	results := eng.Evaluate(doc)
	assertDeniedRule(t, results, "single-or")
}

func TestOr_AllFalse(t *testing.T) {
	doc := map[string]any{"x": map[string]any{"v": "d"}}
	results := eval(t, `forbid "gate" { x.v == "a" or x.v == "b" or x.v == "c" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// not edge cases
// ===========================================================================

func TestNot_DoubleNegation(t *testing.T) {
	eng := NewFromPolicies([]*types.Policy{{
		Rules: []types.Rule{{
			Kind: "forbid",
			Name: "double-not",
			Conditions: []types.Condition{{
				Type:    types.CondField,
				Negated: true,
				Field:   "x.v",
				Op:      "==",
				Value:   "a",
			}},
			Message: "blocked",
		}},
	}})
	doc := map[string]any{"x": map[string]any{"v": "a"}}
	results := eng.Evaluate(doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// EvaluateJSON edge cases
// ===========================================================================

func TestEvaluateJSON_InvalidJSON(t *testing.T) {
	eng := NewFromPolicies([]*types.Policy{})
	_, err := eng.EvaluateJSON([]byte(`{invalid json`))
	if err == nil {
		t.Error("expected error for invalid JSON")
	}
}

func TestEvaluateJSON_EmptyObject(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir+"/test.cc", `forbid "gate" { x.y == "z" message "blocked" }`)
	eng, _ := New([]string{dir})
	results, err := eng.EvaluateJSON([]byte(`{}`))
	if err != nil {
		t.Fatal(err)
	}
	assertAllPassed(t, results)
}

// ===========================================================================
// Format output edge cases
// ===========================================================================

func TestFormatResults_Empty(t *testing.T) {
	output, allPassed := FormatResults(nil)
	if !allPassed {
		t.Error("nil results should be all passed")
	}
	if !strings.Contains(output, "PASS: 0 rules") {
		t.Errorf("expected pass message, got: %s", output)
	}
}

func TestFormatResults_MixedWarnAndDeny(t *testing.T) {
	results := []types.Result{
		{Rule: "a", Kind: "forbid", Passed: false, Message: "denied"},
		{Rule: "b", Kind: "warn", Passed: false, Message: "warned"},
	}
	output, allPassed := FormatResults(results)
	if allPassed {
		t.Error("should not be all passed with a forbid denial")
	}
	if !strings.Contains(output, "DENY") {
		t.Errorf("expected DENY in output: %s", output)
	}
	if !strings.Contains(output, "WARN") {
		t.Errorf("expected WARN in output: %s", output)
	}
}

// ===========================================================================
// Multiple conditions interaction
// ===========================================================================

func TestAndConditions_FirstFails(t *testing.T) {
	doc := map[string]any{
		"a": map[string]any{"x": "wrong"},
		"b": map[string]any{"y": "right"},
	}
	results := eval(t, `forbid "gate" {
  a.x == "correct"
  b.y == "right"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestAndConditions_LastFails(t *testing.T) {
	doc := map[string]any{
		"a": map[string]any{"x": "correct"},
		"b": map[string]any{"y": "wrong"},
	}
	results := eval(t, `forbid "gate" {
  a.x == "correct"
  b.y == "right"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// Policy with no conditions (always fires)
// ===========================================================================

func TestNoConditions(t *testing.T) {
	doc := map[string]any{}
	results := eval(t, `forbid "always" { message "always fires" }`, doc)
	assertDeniedRule(t, results, "always")
}

func TestNoConditionsWithUnless(t *testing.T) {
	doc := map[string]any{"x": map[string]any{"v": "escape"}}
	results := eval(t, `forbid "gate" {
  unless x.v == "escape"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// permit edge cases
// ===========================================================================

func TestPermit_ConditionsNotMatched(t *testing.T) {
	doc := map[string]any{
		"user":     map[string]any{"role": "viewer"},
		"resource": map[string]any{"type": "sensitive"},
	}
	results := eval(t, `permit "admin-only" {
  user.role == "admin"
  resource.type == "sensitive"
  message "admin permitted"
}`, doc)
	for _, r := range results {
		if r.Rule == "admin-only" {
			if !r.Passed {
				t.Error("permit that doesn't match should still be Passed=true")
			}
			if r.Message != "" {
				t.Errorf("permit that doesn't match should have empty message, got %q", r.Message)
			}
		}
	}
}

func TestPermit_WithUnless(t *testing.T) {
	doc := map[string]any{
		"user":     map[string]any{"role": "admin", "suspended": "true"},
		"resource": map[string]any{"type": "sensitive"},
	}
	results := eval(t, `permit "admin-permit" {
  user.role == "admin"
  resource.type == "sensitive"
  unless user.suspended == "true"
  message "admin permitted"
}`, doc)
	for _, r := range results {
		if r.Rule == "admin-permit" {
			if !r.Passed {
				t.Error("permit escaped by unless should still be Passed=true")
			}
			if r.Message != "" {
				t.Errorf("permit escaped by unless should have empty message, got %q", r.Message)
			}
		}
	}
}

func TestPermit_NoMessage(t *testing.T) {
	doc := map[string]any{
		"user": map[string]any{"role": "admin"},
	}
	results := eval(t, `permit "allow" {
  user.role == "admin"
  message ""
}`, doc)
	for _, r := range results {
		if r.Rule == "allow" {
			if !r.Passed {
				t.Error("permit should pass")
			}
			if r.Message != "policy violation" {
				t.Errorf("expected default message, got %q", r.Message)
			}
		}
	}
}

func TestPermit_ForbidWarnInteraction(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"risk":     map[string]any{"level": "high"},
	}
	results := eval(t, `
forbid "iam-gate" {
  resource.type == "aws_iam_role"
  message "IAM blocked"
}
warn "high-risk" {
  risk.level == "high"
  message "high risk detected"
}
permit "override" {
  resource.type == "aws_iam_role"
  message "permitted"
}
`, doc)
	if len(results) != 3 {
		t.Fatalf("expected 3 results, got %d", len(results))
	}
	var forbidFired, warnFired, permitFired bool
	for _, r := range results {
		switch r.Rule {
		case "iam-gate":
			if !r.Passed {
				forbidFired = true
			}
		case "high-risk":
			if !r.Passed {
				warnFired = true
			}
		case "override":
			if r.Passed && r.Message == "permitted" {
				permitFired = true
			}
		}
	}
	if !forbidFired {
		t.Error("forbid should fire in generic engine (no override)")
	}
	if !warnFired {
		t.Error("warn should fire")
	}
	if !permitFired {
		t.Error("permit should fire")
	}
}

// ===========================================================================
// DefaultEffect
// ===========================================================================

func TestDefaultAllow_NoRulesMatch(t *testing.T) {
	doc := map[string]any{"x": map[string]any{"v": "unrelated"}}
	results := eval(t, `forbid "gate" { x.v == "something-else" message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestDefaultDeny_NoPermitFired(t *testing.T) {
	policy, _ := parser.Parse(`permit "only-admin" {
  user.role == "admin"
  message "admin allowed"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithDefaultEffect(types.DefaultDeny))
	doc := map[string]any{"user": map[string]any{"role": "viewer"}}
	results := eng.Evaluate(doc)
	var implicitDeny bool
	for _, r := range results {
		if r.Rule == "(default-deny)" && !r.Passed {
			implicitDeny = true
		}
	}
	if !implicitDeny {
		t.Error("expected implicit deny when no permit fires in DefaultDeny mode")
	}
}

func TestDefaultDeny_PermitFired(t *testing.T) {
	policy, _ := parser.Parse(`permit "admin-access" {
  user.role == "admin"
  message "admin allowed"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithDefaultEffect(types.DefaultDeny))
	doc := map[string]any{"user": map[string]any{"role": "admin"}}
	results := eng.Evaluate(doc)
	for _, r := range results {
		if r.Rule == "(default-deny)" {
			t.Error("should not have implicit deny when permit fires")
		}
	}
}

func TestDefaultDeny_ForbidAlreadyDenied(t *testing.T) {
	policy, _ := parser.Parse(`forbid "explicit-block" {
  user.role == "attacker"
  message "blocked"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithDefaultEffect(types.DefaultDeny))
	doc := map[string]any{"user": map[string]any{"role": "attacker"}}
	results := eng.Evaluate(doc)
	for _, r := range results {
		if r.Rule == "(default-deny)" {
			t.Error("should not add implicit deny when forbid already fired")
		}
	}
}

func TestDefaultDeny_NoRulesAtAll(t *testing.T) {
	eng := NewFromPolicies([]*types.Policy{}, WithDefaultEffect(types.DefaultDeny))
	doc := map[string]any{"anything": "here"}
	results := eng.Evaluate(doc)
	var implicitDeny bool
	for _, r := range results {
		if r.Rule == "(default-deny)" && !r.Passed {
			implicitDeny = true
		}
	}
	if !implicitDeny {
		t.Error("expected implicit deny with no rules in DefaultDeny mode")
	}
}

func TestDefaultAllow_Explicit(t *testing.T) {
	policy, _ := parser.Parse(`permit "x" { user.role == "admin" message "ok" }`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithDefaultEffect(types.DefaultAllow))
	doc := map[string]any{"user": map[string]any{"role": "viewer"}}
	results := eng.Evaluate(doc)
	for _, r := range results {
		if r.Rule == "(default-deny)" {
			t.Error("DefaultAllow should never add implicit deny")
		}
	}
}

func TestDefaultDeny_PermitWithForbid(t *testing.T) {
	policy, _ := parser.Parse(`
forbid "block-all" {
  message "everything blocked"
}
permit "allow-admin" {
  user.role == "admin"
  message "admin allowed"
}
`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithDefaultEffect(types.DefaultDeny))
	doc := map[string]any{"user": map[string]any{"role": "admin"}}
	results := eng.Evaluate(doc)
	for _, r := range results {
		if r.Rule == "(default-deny)" {
			t.Error("should not add implicit deny when permit fired")
		}
	}
}

// ===========================================================================
// in operator edge cases
// ===========================================================================

func TestIn_EmptyList(t *testing.T) {
	doc := map[string]any{"x": map[string]any{"v": "a"}}
	results := eval(t, `forbid "gate" { x.v in [] message "blocked" }`, doc)
	assertAllPassed(t, results)
}

func TestIn_CaseSensitive(t *testing.T) {
	doc := map[string]any{"x": map[string]any{"v": "Admin"}}
	results := eval(t, `forbid "gate" { x.v in ["admin", "root"] message "blocked" }`, doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// arithmetic expressions
// ===========================================================================

func TestArith_CountPlusCount(t *testing.T) {
	doc := map[string]any{
		"plan": map[string]any{
			"destroys": []any{"a", "b", "c"},
			"updates":  []any{"d", "e"},
		},
	}
	results := eval(t, `forbid "blast" {
  count(plan.destroys) + count(plan.updates) > 4
  message "too many destructive changes"
}`, doc)
	assertDeniedRule(t, results, "blast") // 3 + 2 = 5 > 4
}

func TestArith_CountPlusCount_BelowThreshold(t *testing.T) {
	doc := map[string]any{
		"plan": map[string]any{
			"destroys": []any{"a"},
			"updates":  []any{"b"},
		},
	}
	results := eval(t, `forbid "blast" {
  count(plan.destroys) + count(plan.updates) > 4
  message "too many"
}`, doc)
	assertAllPassed(t, results) // 1 + 1 = 2, not > 4
}

func TestArith_FieldMultiply(t *testing.T) {
	doc := map[string]any{
		"user": map[string]any{"risk_score": 8},
		"resource": map[string]any{"sensitivity": 7},
	}
	results := eval(t, `forbid "risk" {
  user.risk_score * resource.sensitivity > 50
  message "risk too high"
}`, doc)
	assertDeniedRule(t, results, "risk") // 8 * 7 = 56 > 50
}

func TestArith_FieldAddField(t *testing.T) {
	doc := map[string]any{
		"pr": map[string]any{
			"approvals":      1,
			"auto_approvals": 1,
		},
	}
	results := eval(t, `forbid "needs-more-approvals" {
  pr.approvals + pr.auto_approvals < 3
  message "need at least 3 total approvals"
}`, doc)
	assertDeniedRule(t, results, "needs-more-approvals") // 1 + 1 = 2 < 3
}

func TestArith_Subtraction_Passes(t *testing.T) {
	doc := map[string]any{
		"budget": map[string]any{"total": 1000, "spent": 800},
	}
	results := eval(t, `forbid "over-budget" {
  budget.total - budget.spent < 100
  message "budget nearly exhausted"
}`, doc)
	assertAllPassed(t, results) // 1000 - 800 = 200, not < 100
}

func TestArith_Subtraction_Fires(t *testing.T) {
	doc := map[string]any{
		"budget": map[string]any{"total": 1000, "spent": 950},
	}
	results := eval(t, `forbid "over-budget" {
  budget.total - budget.spent < 100
  message "budget nearly exhausted"
}`, doc)
	assertDeniedRule(t, results, "over-budget") // 1000 - 950 = 50 < 100
}

func TestArith_Division(t *testing.T) {
	doc := map[string]any{
		"order": map[string]any{"total": 500, "items": 10},
	}
	results := eval(t, `forbid "high-avg" {
  order.total / order.items > 40
  message "average item price too high"
}`, doc)
	assertDeniedRule(t, results, "high-avg") // 500 / 10 = 50 > 40
}

func TestArith_DivideByZero(t *testing.T) {
	doc := map[string]any{
		"order": map[string]any{"total": 500, "items": 0},
	}
	results := eval(t, `forbid "gate" {
  order.total / order.items > 40
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // divide by zero returns false, no panic
}

func TestArith_LiteralOnRight(t *testing.T) {
	doc := map[string]any{
		"plan": map[string]any{
			"destroys": []any{"a", "b", "c"},
		},
	}
	results := eval(t, `forbid "gate" {
  count(plan.destroys) * 2 > 5
  message "scaled count too high"
}`, doc)
	assertDeniedRule(t, results, "gate") // 3 * 2 = 6 > 5
}

func TestArith_ThreeTerms(t *testing.T) {
	doc := map[string]any{
		"a": map[string]any{"v": 10},
		"b": map[string]any{"v": 20},
		"c": map[string]any{"v": 30},
	}
	results := eval(t, `forbid "gate" {
  a.v + b.v + c.v > 50
  message "total too high"
}`, doc)
	assertDeniedRule(t, results, "gate") // 10 + 20 + 30 = 60 > 50
}

func TestArith_MissingField(t *testing.T) {
	doc := map[string]any{
		"a": map[string]any{"v": 10},
	}
	results := eval(t, `forbid "gate" {
  a.v + missing.field > 5
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // missing field → eval fails → false
}

func TestArith_InUnless(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "sensitive"},
		"pr": map[string]any{
			"approvals":      2,
			"auto_approvals": 1,
		},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "sensitive"
  unless pr.approvals + pr.auto_approvals >= 3
  message "blocked"
}`, doc)
	assertAllPassed(t, results) // 2 + 1 = 3 >= 3, saved by unless
}

// ===========================================================================
// string builtins: lower(), upper(), len()
// ===========================================================================

func TestLower(t *testing.T) {
	doc := map[string]any{
		"user": map[string]any{"name": "ADMIN"},
	}
	results := eval(t, `forbid "gate" {
  lower(user.name) == "admin"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestLower_NoMatch(t *testing.T) {
	doc := map[string]any{
		"user": map[string]any{"name": "VIEWER"},
	}
	results := eval(t, `forbid "gate" {
  lower(user.name) == "admin"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestUpper(t *testing.T) {
	doc := map[string]any{
		"env": map[string]any{"name": "production"},
	}
	results := eval(t, `forbid "gate" {
  upper(env.name) == "PRODUCTION"
  message "blocked"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestLen_String(t *testing.T) {
	doc := map[string]any{
		"msg": map[string]any{"text": "hello"},
	}
	results := eval(t, `forbid "gate" {
  len(msg.text) > 3
  message "long message"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestLen_List(t *testing.T) {
	doc := map[string]any{
		"items": []any{"a", "b", "c", "d"},
	}
	results := eval(t, `forbid "gate" {
  len(items) > 3
  message "too many"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestLen_Empty(t *testing.T) {
	doc := map[string]any{
		"items": []any{},
	}
	results := eval(t, `forbid "gate" {
  len(items) == 0
  message "empty"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestLower_WithContains(t *testing.T) {
	doc := map[string]any{
		"msg": map[string]any{"text": "Hello World"},
	}
	results := eval(t, `forbid "gate" {
  lower(msg.text) contains "hello"
  message "found"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestLower_InUnless(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "sensitive"},
		"user":     map[string]any{"role": "ADMIN"},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "sensitive"
  unless lower(user.role) == "admin"
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

// ===========================================================================
// set operators: intersects, is_subset
// ===========================================================================

func TestIntersects_Match(t *testing.T) {
	doc := map[string]any{
		"author": map[string]any{"teams": []any{"dev", "security"}},
	}
	results := eval(t, `forbid "gate" {
  author.teams intersects ["security", "platform"]
  message "overlap found"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestIntersects_NoMatch(t *testing.T) {
	doc := map[string]any{
		"author": map[string]any{"teams": []any{"dev", "qa"}},
	}
	results := eval(t, `forbid "gate" {
  author.teams intersects ["security", "platform"]
  message "overlap found"
}`, doc)
	assertAllPassed(t, results)
}

func TestIntersects_EmptyLHS(t *testing.T) {
	doc := map[string]any{
		"author": map[string]any{"teams": []any{}},
	}
	results := eval(t, `forbid "gate" {
  author.teams intersects ["security"]
  message "overlap"
}`, doc)
	assertAllPassed(t, results)
}

func TestIntersects_InUnless(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"author":   map[string]any{"teams": []any{"platform"}},
	}
	results := eval(t, `forbid "gate" {
  resource.type == "aws_iam_role"
  unless author.teams intersects ["security", "platform"]
  message "blocked"
}`, doc)
	assertAllPassed(t, results)
}

func TestIsSubset_True(t *testing.T) {
	doc := map[string]any{
		"labels": []any{"reviewed", "approved"},
	}
	results := eval(t, `forbid "gate" {
  labels is_subset ["reviewed", "approved", "tested"]
  message "all labels are known"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestIsSubset_False(t *testing.T) {
	doc := map[string]any{
		"labels": []any{"reviewed", "unknown-label"},
	}
	results := eval(t, `forbid "gate" {
  labels is_subset ["reviewed", "approved", "tested"]
  message "all labels are known"
}`, doc)
	assertAllPassed(t, results)
}

func TestIsSubset_EmptyLHS(t *testing.T) {
	doc := map[string]any{
		"labels": []any{},
	}
	results := eval(t, `forbid "gate" {
  labels is_subset ["reviewed", "approved"]
  message "subset"
}`, doc)
	assertDeniedRule(t, results, "gate") // empty is subset of anything
}

// ===========================================================================
// matches_regex operator
// ===========================================================================

func TestMatchesRegex(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"name": "prod-abc-123"},
	}
	results := eval(t, `forbid "gate" {
  resource.name matches_regex "^prod-[a-z]{3}-[0-9]+$"
  message "matched"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestMatchesRegex_NoMatch(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"name": "staging-abc-123"},
	}
	results := eval(t, `forbid "gate" {
  resource.name matches_regex "^prod-[a-z]{3}-[0-9]+$"
  message "matched"
}`, doc)
	assertAllPassed(t, results)
}

func TestMatchesRegex_InvalidPattern(t *testing.T) {
	doc := map[string]any{
		"resource": map[string]any{"name": "anything"},
	}
	results := eval(t, `forbid "gate" {
  resource.name matches_regex "[invalid"
  message "matched"
}`, doc)
	assertAllPassed(t, results) // invalid regex returns false, no panic
}

func TestMatchesRegex_BranchPattern(t *testing.T) {
	doc := map[string]any{
		"pr": map[string]any{"branch": "release/v2.1.0"},
	}
	results := eval(t, `forbid "gate" {
  pr.branch matches_regex "^release/v[0-9]+\\.[0-9]+\\.[0-9]+$"
  message "semver release branch"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

func TestMatchesRegex_InQuantifier(t *testing.T) {
	doc := map[string]any{
		"files": map[string]any{
			"changed": []any{"src/main.go", "infra/vpc.tf", "README.md"},
		},
	}
	results := eval(t, `forbid "gate" {
  any files.changed matches_regex "^infra/.*\\.tf$"
  message "terraform infra file changed"
}`, doc)
	assertDeniedRule(t, results, "gate")
}

// ===========================================================================
// Explain mode
// ===========================================================================

func TestExplain_DeniedRule(t *testing.T) {
	policy, _ := parser.Parse(`forbid "gate" {
  resource.type == "aws_iam_role"
  resource.action == "delete"
  unless author.teams contains "security"
  message "blocked"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithExplain(true))
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role", "action": "delete"},
		"author":   map[string]any{"teams": []any{"dev"}},
	}
	results := eng.Evaluate(doc)

	if len(results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(results))
	}
	r := results[0]
	if r.Passed {
		t.Error("expected denial")
	}
	if r.Trace == nil {
		t.Fatal("expected trace in explain mode")
	}
	if !r.Trace.AllConditionsMatched {
		t.Error("expected all conditions to match")
	}
	if r.Trace.SavedByUnless {
		t.Error("should not be saved by unless")
	}
	if len(r.Trace.Conditions) != 2 {
		t.Fatalf("expected 2 condition traces, got %d", len(r.Trace.Conditions))
	}
	if !r.Trace.Conditions[0].Result {
		t.Error("first condition should be true")
	}
	if len(r.Trace.Unlesses) != 1 {
		t.Fatalf("expected 1 unless trace, got %d", len(r.Trace.Unlesses))
	}
	if r.Trace.Unlesses[0].Result {
		t.Error("unless should be false (dev not in security)")
	}
}

func TestExplain_SavedByUnless(t *testing.T) {
	policy, _ := parser.Parse(`forbid "gate" {
  resource.type == "aws_iam_role"
  unless author.teams contains "security"
  message "blocked"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithExplain(true))
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"author":   map[string]any{"teams": []any{"security"}},
	}
	results := eng.Evaluate(doc)

	r := results[0]
	if !r.Passed {
		t.Error("expected pass (saved by unless)")
	}
	if r.Trace == nil {
		t.Fatal("expected trace")
	}
	if !r.Trace.AllConditionsMatched {
		t.Error("conditions should all match")
	}
	if !r.Trace.SavedByUnless {
		t.Error("should be saved by unless")
	}
	if !r.Trace.Unlesses[0].Result {
		t.Error("unless should be true")
	}
}

func TestExplain_ConditionNotMet(t *testing.T) {
	policy, _ := parser.Parse(`forbid "gate" {
  resource.type == "aws_iam_role"
  resource.action == "delete"
  message "blocked"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithExplain(true))
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_s3_bucket", "action": "create"},
	}
	results := eng.Evaluate(doc)

	r := results[0]
	if !r.Passed {
		t.Error("expected pass")
	}
	if r.Trace == nil {
		t.Fatal("expected trace")
	}
	if r.Trace.AllConditionsMatched {
		t.Error("conditions should not all match")
	}
	// In explain mode, all conditions are evaluated even after first failure
	if len(r.Trace.Conditions) != 2 {
		t.Fatalf("expected 2 condition traces (explain evaluates all), got %d", len(r.Trace.Conditions))
	}
	if r.Trace.Conditions[0].Result {
		t.Error("first condition should be false (s3 != iam)")
	}
}

func TestExplain_NoTraceWithoutOption(t *testing.T) {
	policy, _ := parser.Parse(`forbid "gate" {
  resource.type == "aws_iam_role"
  message "blocked"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}) // no WithExplain
	doc := map[string]any{"resource": map[string]any{"type": "aws_iam_role"}}
	results := eng.Evaluate(doc)

	if results[0].Trace != nil {
		t.Error("trace should be nil when explain is not enabled")
	}
}

func TestExplain_FormatOutput(t *testing.T) {
	policy, _ := parser.Parse(`forbid "gate" {
  resource.type == "aws_iam_role"
  unless author.teams contains "security"
  message "blocked"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithExplain(true))
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_iam_role"},
		"author":   map[string]any{"teams": []any{"dev"}},
	}
	results := eng.Evaluate(doc)

	output := FormatExplain(results)
	if !strings.Contains(output, `RULE "gate"`) {
		t.Errorf("expected rule name in output: %s", output)
	}
	if !strings.Contains(output, "DENIED") {
		t.Errorf("expected DENIED in output: %s", output)
	}
	if !strings.Contains(output, "resource.type") {
		t.Errorf("expected condition expr in output: %s", output)
	}
	if !strings.Contains(output, "true") {
		t.Errorf("expected boolean result in output: %s", output)
	}
}

func TestExplain_OrCondition(t *testing.T) {
	policy, _ := parser.Parse(`forbid "gate" {
  resource.type == "aws_iam_role" or resource.type == "aws_kms_key"
  message "blocked"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithExplain(true))
	doc := map[string]any{
		"resource": map[string]any{"type": "aws_kms_key"},
	}
	results := eng.Evaluate(doc)

	r := results[0]
	if r.Trace == nil {
		t.Fatal("expected trace")
	}
	if len(r.Trace.Conditions) != 1 {
		t.Fatalf("expected 1 condition (or group), got %d", len(r.Trace.Conditions))
	}
	ct := r.Trace.Conditions[0]
	if len(ct.Children) != 2 {
		t.Fatalf("expected 2 or-group children, got %d", len(ct.Children))
	}
	if ct.Children[0].Result {
		t.Error("first or child should be false (iam != kms)")
	}
	if !ct.Children[1].Result {
		t.Error("second or child should be true (kms == kms)")
	}
}

func TestExplain_AggregateCondition(t *testing.T) {
	policy, _ := parser.Parse(`forbid "blast" {
  count(items) > 5
  message "too many"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithExplain(true))
	doc := map[string]any{"items": []any{"a", "b", "c"}}
	results := eng.Evaluate(doc)

	r := results[0]
	if r.Trace == nil {
		t.Fatal("expected trace")
	}
	ct := r.Trace.Conditions[0]
	if ct.Result {
		t.Error("count(3) > 5 should be false")
	}
	if !strings.Contains(ct.Expr, "count(items)") {
		t.Errorf("expected count expr, got %q", ct.Expr)
	}
	if ct.Actual != "3" {
		t.Errorf("expected actual '3', got %q", ct.Actual)
	}
}

func TestExplain_HasCondition(t *testing.T) {
	policy, _ := parser.Parse(`forbid "gate" {
  has config.timeout
  message "timeout set"
}`)
	eng := NewFromPolicies([]*types.Policy{policy}, WithExplain(true))
	doc := map[string]any{"config": map[string]any{"timeout": 30}}
	results := eng.Evaluate(doc)

	ct := results[0].Trace.Conditions[0]
	if !ct.Result {
		t.Error("has should be true")
	}
	if !strings.Contains(ct.Expr, "has config.timeout") {
		t.Errorf("expected has expr, got %q", ct.Expr)
	}
	if ct.Actual != "exists" {
		t.Errorf("expected actual 'exists', got %q", ct.Actual)
	}
}

// ===========================================================================
// Helpers
// ===========================================================================

func eval(t *testing.T, policySource string, doc map[string]any) []types.Result {
	t.Helper()
	policy, err := parser.Parse(policySource)
	if err != nil {
		t.Fatalf("parse error: %v", err)
	}
	eng := NewFromPolicies([]*types.Policy{policy})
	return eng.Evaluate(doc)
}

func toGenericResults(results []types.Result) []types.Result {
	return results
}

func assertDeniedRule(t *testing.T, results []types.Result, rule string) {
	t.Helper()
	for _, r := range results {
		if r.Rule == rule && !r.Passed {
			return
		}
	}
	t.Errorf("expected rule %q to deny", rule)
}

func assertAllPassed(t *testing.T, results []types.Result) {
	t.Helper()
	for _, r := range results {
		if !r.Passed && r.Kind != "warn" {
			t.Errorf("unexpected denial: %s — %s (%s)", r.Kind, r.Message, r.Rule)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
}
