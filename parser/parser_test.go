package parser

import (
	"testing"

	"github.com/mikemackintosh/crowdcontrol/types"
)

func TestParseMinimalForbid(t *testing.T) {
	input := `forbid "test" {
  resource.type == "aws_iam_role"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(policy.Rules))
	}

	r := policy.Rules[0]
	assertRule(t, r, "forbid", "test", 1, 0)
	if r.Message != "denied" {
		t.Errorf("expected message 'denied', got %q", r.Message)
	}
}

func TestParseWarnRule(t *testing.T) {
	input := `warn "large-change" {
  count(plan.creates) > 20
  message "too many creates"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	r := policy.Rules[0]
	assertRule(t, r, "warn", "large-change", 1, 0)
}

func TestParsePermitRule(t *testing.T) {
	input := `permit "platform-infra" {
  author.teams contains "platform-team"
  resource.type in ["aws_s3_bucket", "aws_rds_instance"]
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	r := policy.Rules[0]
	assertRule(t, r, "permit", "platform-infra", 2, 0)
}

func TestParseMultipleRules(t *testing.T) {
	input := `
forbid "rule1" {
  resource.type == "a"
  message "no"
}

warn "rule2" {
  resource.type == "b"
  message "maybe"
}

permit "rule3" {
  resource.type == "c"
}
`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if len(policy.Rules) != 3 {
		t.Fatalf("expected 3 rules, got %d", len(policy.Rules))
	}

	if policy.Rules[0].Kind != "forbid" {
		t.Error("rule 0 should be forbid")
	}
	if policy.Rules[1].Kind != "warn" {
		t.Error("rule 1 should be warn")
	}
	if policy.Rules[2].Kind != "permit" {
		t.Error("rule 2 should be permit")
	}
}

func TestParseFieldOperators(t *testing.T) {
	tests := []struct {
		name string
		cond string
		op   string
	}{
		{"equals", `resource.type == "x"`, "=="},
		{"not equals", `resource.type != "x"`, "!="},
		{"less than", `pr.approvals < 2`, "<"},
		{"greater than", `pr.approvals > 0`, ">"},
		{"lte", `pr.approvals <= 5`, "<="},
		{"gte", `pr.approvals >= 1`, ">="},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := `forbid "test" { ` + tt.cond + ` message "x" }`
			policy, err := Parse(input)
			if err != nil {
				t.Fatal(err)
			}
			cond := policy.Rules[0].Conditions[0]
			if cond.Op != tt.op {
				t.Errorf("expected op %q, got %q", tt.op, cond.Op)
			}
		})
	}
}

func TestParseInList(t *testing.T) {
	input := `forbid "test" {
  resource.type in ["aws_iam_role", "aws_kms_key", "aws_s3_bucket"]
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	cond := policy.Rules[0].Conditions[0]
	if cond.Op != "in" {
		t.Fatalf("expected op 'in', got %q", cond.Op)
	}
	list, ok := cond.Value.([]string)
	if !ok {
		t.Fatal("expected []string value for 'in'")
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 items, got %d", len(list))
	}
	if list[0] != "aws_iam_role" || list[1] != "aws_kms_key" || list[2] != "aws_s3_bucket" {
		t.Errorf("unexpected list values: %v", list)
	}
}

func TestParseInListSingleItem(t *testing.T) {
	input := `forbid "test" {
  resource.type in ["aws_iam_role"]
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	list, ok := policy.Rules[0].Conditions[0].Value.([]string)
	if !ok || len(list) != 1 {
		t.Fatal("expected single-item list")
	}
}

func TestParseMatches(t *testing.T) {
	input := `forbid "test" {
  resource.type matches "okta_*"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	cond := policy.Rules[0].Conditions[0]
	if cond.Op != "matches" {
		t.Fatalf("expected op 'matches', got %q", cond.Op)
	}
	if cond.Value != "okta_*" {
		t.Errorf("expected pattern 'okta_*', got %v", cond.Value)
	}
}

func TestParseBoolValues(t *testing.T) {
	input := `forbid "test" {
  pr.draft == true
  message "no drafts"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	cond := policy.Rules[0].Conditions[0]
	v, ok := cond.Value.(bool)
	if !ok {
		t.Fatal("expected bool value")
	}
	if v != true {
		t.Error("expected true")
	}
}

func TestParseBoolFalse(t *testing.T) {
	input := `forbid "test" {
  pr.draft == false
  message "x"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	v, ok := policy.Rules[0].Conditions[0].Value.(bool)
	if !ok || v != false {
		t.Error("expected false")
	}
}

func TestParseNumericValue(t *testing.T) {
	input := `forbid "test" {
  pr.approvals < 2
  message "need approvals"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	v, ok := policy.Rules[0].Conditions[0].Value.(int)
	if !ok {
		t.Fatal("expected int value")
	}
	if v != 2 {
		t.Errorf("expected 2, got %d", v)
	}
}

func TestParseContains(t *testing.T) {
	input := `forbid "test" {
  author.teams contains "enterprise-security"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	cond := policy.Rules[0].Conditions[0]
	if cond.Type != types.CondField {
		t.Fatalf("expected CondField, got %v", cond.Type)
	}
	if cond.Op != "contains" {
		t.Errorf("expected op 'contains', got %q", cond.Op)
	}
	if cond.Field != "author.teams" {
		t.Errorf("expected field 'author.teams', got %q", cond.Field)
	}
	if cond.Value != "enterprise-security" {
		t.Errorf("expected value 'enterprise-security', got %v", cond.Value)
	}
}

func TestParseContainsInUnless(t *testing.T) {
	input := `forbid "test" {
  resource.type == "aws_iam_role"
  unless labels contains "security-approved"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	unless := policy.Rules[0].Unlesses[0]
	if unless.Op != "contains" {
		t.Fatalf("expected contains op, got %q", unless.Op)
	}
	if unless.Field != "labels" {
		t.Errorf("expected field 'labels', got %q", unless.Field)
	}
}

func TestParseHas(t *testing.T) {
	input := `forbid "test" {
  has resource.change.after.acl
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	cond := policy.Rules[0].Conditions[0]
	if cond.Type != types.CondHas {
		t.Fatalf("expected CondHas, got %v", cond.Type)
	}
	if cond.Field != "resource.change.after.acl" {
		t.Errorf("expected field path, got %q", cond.Field)
	}
}

func TestParseNotHas(t *testing.T) {
	input := `forbid "test" {
  not has config.timeout
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	cond := policy.Rules[0].Conditions[0]
	if cond.Type != types.CondHas {
		t.Fatalf("expected CondHas, got %v", cond.Type)
	}
	if !cond.Negated {
		t.Error("expected negated condition")
	}
}

func TestParseMultipleUnless(t *testing.T) {
	input := `forbid "test" {
  resource.type == "aws_iam_role"
  unless author.teams contains "enterprise-security"
  unless author.teams contains "platform-team"
  unless labels contains "security-approved"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	r := policy.Rules[0]
	if len(r.Unlesses) != 3 {
		t.Fatalf("expected 3 unless clauses, got %d", len(r.Unlesses))
	}
	for i, u := range r.Unlesses {
		if u.Op != "contains" {
			t.Errorf("unless %d: expected contains op, got %q", i, u.Op)
		}
	}
}

func TestParseAggregate(t *testing.T) {
	input := `forbid "blast" {
  count(plan.destroys) > 5
  message "too many"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	cond := policy.Rules[0].Conditions[0]
	if cond.Type != types.CondAggregate {
		t.Fatalf("expected CondAggregate, got %v", cond.Type)
	}
	if cond.AggregateFunc != "count" {
		t.Errorf("expected func 'count', got %q", cond.AggregateFunc)
	}
	if cond.AggregateTarget != "plan.destroys" {
		t.Errorf("expected target 'plan.destroys', got %q", cond.AggregateTarget)
	}
	if cond.Op != ">" {
		t.Errorf("expected op '>', got %q", cond.Op)
	}
	if v, ok := cond.Value.(int); !ok || v != 5 {
		t.Errorf("expected value 5, got %v", cond.Value)
	}
}

func TestParseAggregateTargets(t *testing.T) {
	targets := []string{"plan.destroys", "plan.creates", "plan.updates", "plan.changes"}
	for _, target := range targets {
		t.Run(target, func(t *testing.T) {
			input := `forbid "test" { count(` + target + `) > 1 message "x" }`
			policy, err := Parse(input)
			if err != nil {
				t.Fatal(err)
			}
			if policy.Rules[0].Conditions[0].AggregateTarget != target {
				t.Errorf("expected %q, got %q", target, policy.Rules[0].Conditions[0].AggregateTarget)
			}
		})
	}
}

func TestParseDottedPath(t *testing.T) {
	input := `forbid "test" {
  resource.type == "x"
  pr.draft == true
  project.workspace == "production"
  message "x"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	fields := []string{"resource.type", "pr.draft", "project.workspace"}
	for i, expected := range fields {
		if policy.Rules[0].Conditions[i].Field != expected {
			t.Errorf("condition %d: expected field %q, got %q", i, expected, policy.Rules[0].Conditions[i].Field)
		}
	}
}

func TestParseMessageInterpolation(t *testing.T) {
	input := `forbid "test" {
  resource.type == "x"
  message "{author} cannot modify {resource.type}.{resource.name} ({count(plan.destroys)})"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	expected := "{author} cannot modify {resource.type}.{resource.name} ({count(plan.destroys)})"
	if policy.Rules[0].Message != expected {
		t.Errorf("expected %q, got %q", expected, policy.Rules[0].Message)
	}
}

func TestParseCommentsInterspersed(t *testing.T) {
	input := `
# Top-level comment
forbid "test" {
  # Condition comment
  resource.type == "x"
  // Another comment style
  unless author.teams contains "y"
  # Message comment
  message "denied"
}
# Trailing comment
`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	assertRule(t, policy.Rules[0], "forbid", "test", 1, 1)
}

func TestParseFieldInList(t *testing.T) {
	input := `forbid "blocked" {
  author.name in ["user-a", "user-b", "user-c"]
  message "blocked"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	r := policy.Rules[0]
	if len(r.Conditions) != 1 {
		t.Fatalf("expected 1 condition, got %d", len(r.Conditions))
	}
	cond := r.Conditions[0]
	if cond.Type != types.CondField {
		t.Fatalf("expected CondField, got %v", cond.Type)
	}
	if cond.Op != "in" {
		t.Fatalf("expected op 'in', got %q", cond.Op)
	}
	list, ok := cond.Value.([]string)
	if !ok {
		t.Fatal("expected []string value")
	}
	if len(list) != 3 {
		t.Fatalf("expected 3 items, got %d", len(list))
	}
}

func TestParseFieldInListLong(t *testing.T) {
	input := `forbid "blocked" {
  author.name in [
    "user-1", "user-2", "user-3", "user-4", "user-5",
    "user-6", "user-7", "user-8", "user-9", "user-10"
  ]
  message "blocked"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}

	list, ok := policy.Rules[0].Conditions[0].Value.([]string)
	if !ok {
		t.Fatal("expected []string value")
	}
	if len(list) != 10 {
		t.Fatalf("expected 10 items, got %d", len(list))
	}
}

// --- Error cases ---

func TestParseErrorMissingRuleName(t *testing.T) {
	_, err := Parse(`forbid { resource.type == "x" }`)
	if err == nil {
		t.Fatal("expected error for missing rule name")
	}
}

func TestParseErrorMissingBrace(t *testing.T) {
	_, err := Parse(`forbid "test" resource.type == "x" }`)
	if err == nil {
		t.Fatal("expected error for missing opening brace")
	}
}

func TestParseErrorUnclosedBrace(t *testing.T) {
	_, err := Parse(`forbid "test" { resource.type == "x"`)
	if err == nil {
		t.Fatal("expected error for unclosed brace")
	}
}

func TestParseErrorInvalidKeyword(t *testing.T) {
	_, err := Parse(`deny "test" { resource.type == "x" }`)
	if err == nil {
		t.Fatal("expected error for invalid keyword 'deny'")
	}
}

func TestParseErrorBadOperator(t *testing.T) {
	_, err := Parse(`forbid "test" { resource.type ~ "x" message "y" }`)
	if err == nil {
		t.Fatal("expected error for invalid operator")
	}
}

func TestParseErrorBadValueInComparison(t *testing.T) {
	_, err := Parse(`forbid "test" { resource.type == [1, 2] message "y" }`)
	if err == nil {
		t.Fatal("expected error for list in == comparison")
	}
}

// ===========================================================================
// not operator
// ===========================================================================

func TestParseNot(t *testing.T) {
	input := `forbid "gate" {
  not resource.type matches "aws_*"
  message "only AWS"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	assertRule(t, r, "forbid", "gate", 1, 0)
	if !r.Conditions[0].Negated {
		t.Error("expected condition to be negated")
	}
}

func TestParseNotFieldContains(t *testing.T) {
	input := `forbid "gate" {
  not author.teams contains "security"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	if !r.Conditions[0].Negated {
		t.Error("expected negated condition")
	}
	if r.Conditions[0].Op != "contains" {
		t.Errorf("expected contains op, got %q", r.Conditions[0].Op)
	}
}

func TestParseNotInUnless(t *testing.T) {
	input := `forbid "gate" {
  resource.type == "x"
  unless not pr.draft == true
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	if len(r.Unlesses) != 1 {
		t.Fatalf("expected 1 unless, got %d", len(r.Unlesses))
	}
	if !r.Unlesses[0].Negated {
		t.Error("expected unless condition to be negated")
	}
}

// ===========================================================================
// or operator
// ===========================================================================

func TestParseOr(t *testing.T) {
	input := `forbid "gate" {
  resource.type == "a" or resource.type == "b"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	assertRule(t, r, "forbid", "gate", 1, 0)
	if r.Conditions[0].Type != types.CondOr {
		t.Fatalf("expected CondOr, got %v", r.Conditions[0].Type)
	}
	if len(r.Conditions[0].OrGroup) != 2 {
		t.Fatalf("expected 2 items in or group, got %d", len(r.Conditions[0].OrGroup))
	}
}

func TestParseOrThreeWay(t *testing.T) {
	input := `forbid "gate" {
  resource.type == "a" or resource.type == "b" or resource.type == "c"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	if r.Conditions[0].Type != types.CondOr {
		t.Fatalf("expected CondOr")
	}
	if len(r.Conditions[0].OrGroup) != 3 {
		t.Fatalf("expected 3 items in or group, got %d", len(r.Conditions[0].OrGroup))
	}
}

func TestParseOrWithAnd(t *testing.T) {
	input := `forbid "gate" {
  resource.type == "a" or resource.type == "b"
  project.workspace == "production"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	assertRule(t, r, "forbid", "gate", 2, 0)
	if r.Conditions[0].Type != types.CondOr {
		t.Errorf("first condition should be CondOr, got %v", r.Conditions[0].Type)
	}
	if r.Conditions[1].Type != types.CondField {
		t.Errorf("second condition should be CondField, got %v", r.Conditions[1].Type)
	}
}

// ===========================================================================
// any / all quantifiers
// ===========================================================================

func TestParseAny(t *testing.T) {
	input := `forbid "gate" {
  any pr.changed_files matches "infra/*"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	assertRule(t, r, "forbid", "gate", 1, 0)
	c := r.Conditions[0]
	if c.Type != types.CondAny {
		t.Fatalf("expected CondAny, got %v", c.Type)
	}
	if c.ListField != "pr.changed_files" {
		t.Errorf("expected list field pr.changed_files, got %q", c.ListField)
	}
	if c.Predicate == nil {
		t.Fatal("expected predicate")
	}
	if c.Predicate.Op != "matches" {
		t.Errorf("expected matches op, got %q", c.Predicate.Op)
	}
}

func TestParseAll(t *testing.T) {
	input := `forbid "gate" {
  all pr.commit_authors in ["alice", "bob"]
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	c := r.Conditions[0]
	if c.Type != types.CondAll {
		t.Fatalf("expected CondAll, got %v", c.Type)
	}
	if c.Predicate.Op != "in" {
		t.Errorf("expected in op, got %q", c.Predicate.Op)
	}
}

func TestParseAnyInList(t *testing.T) {
	input := `forbid "gate" {
  any pr.changed_files in ["secrets.tf", "iam.tf"]
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	c := policy.Rules[0].Conditions[0]
	if c.Type != types.CondAny {
		t.Fatalf("expected CondAny, got %v", c.Type)
	}
	if c.Predicate.Op != "in" {
		t.Errorf("expected in op, got %q", c.Predicate.Op)
	}
}

func TestParseAnyInUnless(t *testing.T) {
	input := `forbid "gate" {
  resource.type == "aws_s3_bucket"
  unless any pr.changed_files matches "safe/*"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	if len(r.Unlesses) != 1 {
		t.Fatalf("expected 1 unless, got %d", len(r.Unlesses))
	}
	if r.Unlesses[0].Type != types.CondAny {
		t.Errorf("expected CondAny in unless, got %v", r.Unlesses[0].Type)
	}
}

// ===========================================================================
// metadata
// ===========================================================================

func TestParseMetadata(t *testing.T) {
	input := `forbid "gate" {
  description "Prevents bad things"
  owner "security-team"
  link "https://wiki.example.com/policy"
  resource.type == "aws_iam_role"
  message "denied"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	if r.Description != "Prevents bad things" {
		t.Errorf("expected description, got %q", r.Description)
	}
	if r.Owner != "security-team" {
		t.Errorf("expected owner, got %q", r.Owner)
	}
	if r.Link != "https://wiki.example.com/policy" {
		t.Errorf("expected link, got %q", r.Link)
	}
	assertRule(t, r, "forbid", "gate", 1, 0)
}

// ===========================================================================
// resource.action
// ===========================================================================

func TestParseResourceAction(t *testing.T) {
	input := `forbid "delete-gate" {
  resource.action == "delete"
  message "no deletes"
}`
	policy, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	r := policy.Rules[0]
	assertRule(t, r, "forbid", "delete-gate", 1, 0)
	c := r.Conditions[0]
	if c.Field != "resource.action" {
		t.Errorf("expected field resource.action, got %q", c.Field)
	}
}

// --- Helpers ---

func assertRule(t *testing.T, r types.Rule, kind, name string, conditions, unlesses int) {
	t.Helper()
	if r.Kind != kind {
		t.Errorf("expected kind %q, got %q", kind, r.Kind)
	}
	if r.Name != name {
		t.Errorf("expected name %q, got %q", name, r.Name)
	}
	if len(r.Conditions) != conditions {
		t.Errorf("expected %d conditions, got %d", conditions, len(r.Conditions))
	}
	if len(r.Unlesses) != unlesses {
		t.Errorf("expected %d unlesses, got %d", unlesses, len(r.Unlesses))
	}
}
