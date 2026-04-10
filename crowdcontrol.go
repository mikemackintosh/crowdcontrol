// Package crowdcontrol is a small, readable policy language for gating
// actions on arbitrary structured data. It exposes a tiny top-level API:
// load .cc files from a directory, evaluate them against a JSON document,
// inspect the per-rule results.
//
// Quick start:
//
//	eng, err := crowdcontrol.New([]string{"./policies"})
//	if err != nil { panic(err) }
//	results := eng.Evaluate(map[string]any{
//	    "user": map[string]any{"name": "alice", "role": "admin"},
//	})
//	for _, r := range results {
//	    fmt.Println(r.Rule, r.Kind, r.Passed, r.Message)
//	}
//
// CrowdControl is intentionally less powerful than CEL, Cedar, or Rego —
// the design goal is that a security engineer who has never seen a .cc file
// before can read a policy and understand it in under 30 seconds.
//
// The engine is domain-agnostic: it operates on map[string]any documents
// and has no concept of GitHub, Terraform, Kubernetes, or any other system.
// Domain-specific input shaping is the caller's responsibility.
package crowdcontrol

import (
	"github.com/mikemackintosh/crowdcontrol/evaluator"
	"github.com/mikemackintosh/crowdcontrol/parser"
	"github.com/mikemackintosh/crowdcontrol/types"
)

// Version is the current CrowdControl release. It is overridden at
// build time by goreleaser via `-ldflags "-X ...Version=<tag>"` so
// released binaries report the release tag instead of the default.
var Version = "0.1.0"

// PolicyExt is the canonical file extension for CrowdControl policy files.
const PolicyExt = evaluator.PolicyExt

// Re-exported types so callers can use the top-level package without importing
// the subpackages. The underlying types are defined in the types subpackage.
type (
	// Policy is a parsed CrowdControl policy file (one or more rules).
	Policy = types.Policy
	// Rule is a single forbid, warn, or permit block.
	Rule = types.Rule
	// Result is the outcome of evaluating one rule against one document.
	Result = types.Result
	// RuleTrace captures per-rule explain output.
	RuleTrace = types.RuleTrace
	// ConditionTrace captures per-condition explain output.
	ConditionTrace = types.ConditionTrace
	// Schema describes the expected shape of input documents for static
	// validation of policies.
	Schema = types.Schema
	// SchemaWarning is a non-fatal issue found during schema validation.
	SchemaWarning = types.SchemaWarning
	// FieldType describes the type of a field in a Schema.
	FieldType = types.FieldType
	// DefaultEffect controls what happens when no rule matches.
	DefaultEffect = types.DefaultEffect
)

const (
	// DefaultAllow allows actions unless a forbid fires.
	DefaultAllow = types.DefaultAllow
	// DefaultDeny denies actions unless a permit fires.
	DefaultDeny = types.DefaultDeny
)

const (
	FieldString FieldType = types.FieldString
	FieldNumber FieldType = types.FieldNumber
	FieldBool   FieldType = types.FieldBool
	FieldList   FieldType = types.FieldList
	FieldMap    FieldType = types.FieldMap
	FieldAny    FieldType = types.FieldAny
)

// Engine wraps the evaluator and exposes the top-level public API.
// Engines are safe for concurrent reads after construction.
type Engine struct {
	inner *evaluator.Evaluator
}

// Option configures an Engine at construction time.
type Option = evaluator.Option

// WithDefaultEffect sets the default effect when no rule matches a document.
//
//	eng, _ := crowdcontrol.New([]string{"./policies"},
//	    crowdcontrol.WithDefaultEffect(crowdcontrol.DefaultDeny))
func WithDefaultEffect(effect DefaultEffect) Option {
	return evaluator.WithDefaultEffect(effect)
}

// WithExplain enables explain mode. When enabled, every Result.Trace is
// populated with per-condition evaluation details.
func WithExplain(enabled bool) Option {
	return evaluator.WithExplain(enabled)
}

// New creates an Engine by loading every .cc file from the given directories.
// Directories that don't exist are silently skipped (consistent with how
// CrowdControl is typically configured: a list of optional policy roots).
func New(policyDirs []string, opts ...Option) (*Engine, error) {
	inner, err := evaluator.New(policyDirs, opts...)
	if err != nil {
		return nil, err
	}
	return &Engine{inner: inner}, nil
}

// NewFromSource creates an Engine from in-memory policy source. Useful for
// embedding inline policies in tests, conformance suites, or hosted services.
// Each entry in sources is parsed as a standalone policy file.
func NewFromSource(sources []string, opts ...Option) (*Engine, error) {
	var policies []*Policy
	for _, src := range sources {
		p, err := parser.Parse(src)
		if err != nil {
			return nil, err
		}
		policies = append(policies, p)
	}
	return &Engine{inner: evaluator.NewFromPolicies(policies, opts...)}, nil
}

// Evaluate runs every loaded rule against the given document and returns
// one Result per rule. The document is an arbitrary nested map (typically
// the result of json.Unmarshal into map[string]any).
func (e *Engine) Evaluate(doc map[string]any) []Result {
	return e.inner.Evaluate(doc)
}

// Validate statically checks loaded policies against a Schema, returning
// non-fatal warnings for unknown fields, type mismatches, and other issues.
func (e *Engine) Validate(schema *Schema) []SchemaWarning {
	return e.inner.Validate(schema)
}

// Policies returns the parsed policies the engine is using. Useful for
// tooling (LSPs, linters) that needs to introspect rules without re-parsing.
func (e *Engine) Policies() []*Policy {
	return e.inner.Policies()
}

// Parse parses a single CrowdControl source string into a Policy AST.
// Most callers should use New or NewFromSource instead — Parse is exposed
// for tooling that needs the raw AST (lsp, linters, formatters).
func Parse(source string) (*Policy, error) {
	return parser.Parse(source)
}
