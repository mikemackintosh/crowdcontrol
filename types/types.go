// Package types defines the AST, schema, and result types for CrowdControl
// policy documents. The CrowdControl engine is domain-agnostic: it evaluates
// policies against arbitrary JSON-like inputs (map[string]any).
package types

// Policy represents a parsed CrowdControl policy file containing multiple rules.
type Policy struct {
	Rules []Rule
}

// Rule is a single forbid, warn, or permit block.
type Rule struct {
	// Kind is "forbid", "warn", or "permit".
	Kind string
	// Name is the quoted identifier.
	Name string
	// Conditions are the AND'd clauses that must all be true for the rule to fire.
	Conditions []Condition
	// Unlesses are OR'd escape clauses — if any is true, the rule does not fire.
	Unlesses []Condition
	// Message is the template string for denial output. May contain {interpolations}.
	Message string

	// Metadata — optional annotations for policy documentation and output.
	Description string
	Owner       string
	Link        string
}

// Condition represents a single evaluable clause.
type Condition struct {
	// Type identifies what kind of condition this is.
	Type ConditionType
	// Negated inverts the boolean result when true.
	Negated bool
	// Field is the dotted path (e.g. "resource.type", "pr.draft", "labels").
	Field string
	// Op is the comparison operator (==, !=, <, >, <=, >=, in, matches, contains).
	Op string
	// Value is the right-hand side — a string, number, bool, or string list.
	Value any
	// Transform is an optional function applied to the field value before comparison.
	// Supported: "lower", "upper", "len".
	Transform string
	// AggregateFunc is "count" for aggregate conditions.
	AggregateFunc string
	// AggregateTarget is the dotted path to the list for count().
	AggregateTarget string
	// OrGroup holds sub-conditions for CondOr — true if any sub-condition is true.
	OrGroup []Condition
	// Quantifier is "any" or "all" for CondAny/CondAll.
	Quantifier string
	// ListField is the dotted path to the list for any/all quantifiers.
	ListField string
	// Predicate is the sub-condition applied to each element in any/all.
	Predicate *Condition
	// LeftExpr and RightExpr are arithmetic expressions for CondExpr.
	LeftExpr  *Expr
	RightExpr *Expr
}

// ConditionType identifies the kind of condition.
type ConditionType int

const (
	// CondField is a field comparison: field.path op value
	CondField ConditionType = iota
	// CondAggregate is a count/aggregate check: count(path) op value
	CondAggregate
	// CondOr groups sub-conditions with OR logic.
	CondOr
	// CondAny is "any <list> <predicate>" — true if any element matches.
	CondAny
	// CondAll is "all <list> <predicate>" — true if all elements match.
	CondAll
	// CondHas checks field existence: has <field.path>
	CondHas
	// CondExpr is an arithmetic expression comparison: expr op expr
	CondExpr
)

// Expr represents a numeric expression (field, count, literal, or binary op).
type Expr struct {
	// Kind identifies what this expression node is.
	Kind ExprKind
	// Field is the dotted path for ExprField.
	Field string
	// Value is the numeric literal for ExprLiteral.
	Value float64
	// AggTarget is the dotted path for ExprCount.
	AggTarget string
	// Transform is "len" for ExprLen.
	Transform string
	// Op is the arithmetic operator for ExprBinary (+, -, *, /).
	Op string
	// Left and Right are sub-expressions for ExprBinary.
	Left  *Expr
	Right *Expr
}

// ExprKind identifies the type of expression node.
type ExprKind int

const (
	ExprField   ExprKind = iota // field.path (resolved to number)
	ExprLiteral                 // numeric literal
	ExprCount                   // count(path)
	ExprLen                     // len(path)
	ExprBinary                  // left op right
)

// DefaultEffect controls what happens when no rule matches a document.
type DefaultEffect string

const (
	// DefaultAllow means actions are allowed unless explicitly forbidden.
	// This is the default — if no forbid fires, the action passes.
	DefaultAllow DefaultEffect = "allow"

	// DefaultDeny means actions are denied unless explicitly permitted.
	// If no permit fires for a document, an implicit denial is added.
	DefaultDeny DefaultEffect = "deny"
)

// Result is the outcome of evaluating a single rule against a document.
type Result struct {
	Rule    string
	Kind    string // "forbid", "warn", "permit"
	Passed  bool
	Message string

	// Metadata from the rule.
	Description string
	Owner       string
	Link        string

	// Trace is populated when explain mode is enabled.
	// Contains per-condition evaluation details for debugging and auditing.
	Trace *RuleTrace
}

// RuleTrace captures the evaluation trace for a single rule.
type RuleTrace struct {
	// Conditions records each condition's evaluation result.
	Conditions []ConditionTrace
	// Unlesses records each unless clause's evaluation result.
	Unlesses []ConditionTrace
	// AllConditionsMatched is true if every condition evaluated to true.
	AllConditionsMatched bool
	// SavedByUnless is true if an unless clause prevented the rule from firing.
	SavedByUnless bool
}

// ConditionTrace records the evaluation of a single condition.
type ConditionTrace struct {
	// Expr is the human-readable representation of the condition.
	Expr string
	// Result is the final boolean result (after negation).
	Result bool
	// Actual is the resolved left-hand value from the document (for display).
	Actual string
	// Children holds sub-traces for CondOr groups.
	Children []ConditionTrace
}

// FieldType describes the expected type of a field in a schema.
type FieldType string

const (
	FieldString FieldType = "string"
	FieldNumber FieldType = "number"
	FieldBool   FieldType = "bool"
	FieldList   FieldType = "list"
	FieldMap    FieldType = "map"
	FieldAny    FieldType = "any"
)

// Schema defines the expected shape of an input document.
// Used by ValidatePolicy to catch field typos and type mismatches at lint time.
type Schema struct {
	// Fields maps dotted field paths to their expected types.
	Fields map[string]FieldType
}

// SchemaWarning is a non-fatal issue found during schema validation.
type SchemaWarning struct {
	// Rule is the name of the rule containing the issue.
	Rule string
	// Field is the dotted path that triggered the warning.
	Field string
	// Message describes the issue.
	Message string
}
