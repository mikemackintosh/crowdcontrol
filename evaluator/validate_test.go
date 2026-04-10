package evaluator

import (
	"strings"
	"testing"

	"github.com/mikemackintosh/crowdcontrol/parser"
	"github.com/mikemackintosh/crowdcontrol/types"
)

func theraSchema() *types.Schema {
	return &types.Schema{
		Fields: map[string]types.FieldType{
			"resource.type":   types.FieldString,
			"resource.name":   types.FieldString,
			"resource.action": types.FieldString,
			"resource.change":  types.FieldMap,
			"author.name":     types.FieldString,
			"author.teams":    types.FieldList,
			"approver.teams":  types.FieldList,
			"labels":          types.FieldList,
			"pr.draft":        types.FieldBool,
			"pr.approvals":    types.FieldNumber,
			"pr.branch":       types.FieldString,
			"pr.changed_files": types.FieldList,
			"pr.commit_authors": types.FieldList,
			"project.workspace": types.FieldString,
			"plan.destroys":   types.FieldList,
			"plan.creates":    types.FieldList,
			"plan.updates":    types.FieldList,
		},
	}
}

func TestValidate_NoWarnings(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resource.type == "aws_iam_role"
  unless author.teams contains "security"
  message "{author.name} blocked on {resource.type}"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestValidate_UnknownField(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resorce.type == "aws_iam_role"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "resorce.type") {
		t.Errorf("expected warning about resorce.type, got: %s", warnings[0].Message)
	}
	if !strings.Contains(warnings[0].Message, "typo") {
		t.Errorf("expected typo hint, got: %s", warnings[0].Message)
	}
}

func TestValidate_TypeMismatch_NumericOnString(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resource.type > 5
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "numeric operator") {
		t.Errorf("expected numeric operator warning, got: %s", warnings[0].Message)
	}
}

func TestValidate_TypeMismatch_ContainsOnNumber(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  pr.approvals contains "something"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "contains expects list or string") {
		t.Errorf("expected contains type warning, got: %s", warnings[0].Message)
	}
}

func TestValidate_TypeMismatch_MatchesOnList(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  labels matches "something"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "matches expects a string") {
		t.Errorf("expected matches type warning, got: %s", warnings[0].Message)
	}
}

func TestValidate_TypeMismatch_IntersectsOnString(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resource.type intersects ["a", "b"]
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "intersects expects a list") {
		t.Errorf("expected intersects type warning, got: %s", warnings[0].Message)
	}
}

func TestValidate_CountOnString(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  count(resource.type) > 5
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "count") {
		t.Errorf("expected count type warning, got: %s", warnings[0].Message)
	}
}

func TestValidate_AnyOnNonList(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  any resource.type matches "aws_*"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "expects a list") {
		t.Errorf("expected list type warning, got: %s", warnings[0].Message)
	}
}

func TestValidate_NestedMapAccess_NoWarning(t *testing.T) {
	// resource.change is a map, so resource.change.after.acl should be fine
	p, _ := parser.Parse(`forbid "gate" {
  resource.change.after.acl == "public-read"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for map traversal, got %d: %v", len(warnings), warnings)
	}
}

func TestValidate_UnknownFieldInMessage(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resource.type == "x"
  message "{authro.name} blocked on {resource.type}"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "authro.name") {
		t.Errorf("expected warning about typo in message, got: %s", warnings[0].Message)
	}
}

func TestValidate_CountInMessage_Valid(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  count(plan.destroys) > 5
  message "destroying {count(plan.destroys)} resources"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 0 {
		t.Errorf("expected no warnings, got %d: %v", len(warnings), warnings)
	}
}

func TestValidate_UnknownFieldInCountMessage(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resource.type == "x"
  message "count is {count(plna.destroys)}"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "plna.destroys") {
		t.Errorf("expected warning about typo in count(), got: %s", warnings[0].Message)
	}
}

func TestValidate_UnlessField(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resource.type == "x"
  unless authro.teams contains "security"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "authro.teams") {
		t.Errorf("expected warning about typo in unless, got: %s", warnings[0].Message)
	}
}

func TestValidate_OrCondition(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  resorce.type == "a" or resource.type == "b"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning (for resorce.type), got %d: %v", len(warnings), warnings)
	}
}

func TestValidate_ArithExpr(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  pr.approvals + pr.draft > 3
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	// pr.draft is bool used in arithmetic — should warn
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "pr.draft") && !strings.Contains(warnings[0].Message, "arithmetic") {
		t.Errorf("expected warning about bool in arithmetic, got: %s", warnings[0].Message)
	}
}

func TestValidate_NilSchema(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  anything.goes == "fine"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, nil)
	if len(warnings) != 0 {
		t.Errorf("nil schema should produce no warnings, got %d", len(warnings))
	}
}

func TestValidate_EmptySchema(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  anything.goes == "fine"
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, &types.Schema{Fields: map[string]types.FieldType{}})
	if len(warnings) != 0 {
		t.Errorf("empty schema should produce no warnings, got %d", len(warnings))
	}
}

func TestValidate_MultipleRules(t *testing.T) {
	p, _ := parser.Parse(`
forbid "rule-a" {
  resorce.type == "x"
  message "a"
}
forbid "rule-b" {
  authro.teams contains "y"
  message "b"
}
`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 2 {
		t.Fatalf("expected 2 warnings, got %d: %v", len(warnings), warnings)
	}
	if warnings[0].Rule != "rule-a" {
		t.Errorf("expected rule-a, got %s", warnings[0].Rule)
	}
	if warnings[1].Rule != "rule-b" {
		t.Errorf("expected rule-b, got %s", warnings[1].Rule)
	}
}

func TestValidate_HasCondition_UnknownNamespace(t *testing.T) {
	p, _ := parser.Parse(`forbid "gate" {
  has confg.timeout
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 1 {
		t.Fatalf("expected 1 warning, got %d: %v", len(warnings), warnings)
	}
	if !strings.Contains(warnings[0].Message, "confg") {
		t.Errorf("expected warning about unknown namespace, got: %s", warnings[0].Message)
	}
}

func TestValidate_HasCondition_KnownNamespace(t *testing.T) {
	// "has resource.change.after.tags" — resource.change is a map, so this is fine
	p, _ := parser.Parse(`forbid "gate" {
  has resource.change.after.tags
  message "blocked"
}`)
	warnings := ValidatePolicy([]*types.Policy{p}, theraSchema())
	if len(warnings) != 0 {
		t.Errorf("expected no warnings for known namespace, got %d: %v", len(warnings), warnings)
	}
}

func TestFormatWarnings_Output(t *testing.T) {
	warnings := []types.SchemaWarning{
		{Rule: "gate", Field: "resorce.type", Message: `unknown field "resorce.type" — not in schema (typo?)`},
	}
	output := FormatWarnings(warnings)
	if !strings.Contains(output, "WARN") {
		t.Errorf("expected WARN prefix, got: %s", output)
	}
	if !strings.Contains(output, "gate") {
		t.Errorf("expected rule name, got: %s", output)
	}
	if !strings.Contains(output, "resorce.type") {
		t.Errorf("expected field name, got: %s", output)
	}
}

func TestFormatWarnings_Empty(t *testing.T) {
	output := FormatWarnings(nil)
	if output != "" {
		t.Errorf("expected empty string for no warnings, got: %q", output)
	}
}
