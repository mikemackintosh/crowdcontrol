package evaluator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/mikemackintosh/crowdcontrol/parser"
	"github.com/mikemackintosh/crowdcontrol/types"
)

// Evaluator loads and runs CrowdControl policies against arbitrary JSON documents.
type Evaluator struct {
	policies      []*types.Policy
	defaultEffect types.DefaultEffect
	explain       bool
}

// Option configures an Evaluator.
type Option func(*Evaluator)

// WithDefaultEffect sets the default effect when no rule matches.
// DefaultAllow (default): actions pass unless a forbid fires.
// DefaultDeny: actions are denied unless a permit fires.
func WithDefaultEffect(effect types.DefaultEffect) Option {
	return func(e *Evaluator) {
		e.defaultEffect = effect
	}
}

// WithExplain enables explain mode. When enabled, each Result includes
// a Trace showing per-condition evaluation details for debugging and auditing.
func WithExplain(enabled bool) Option {
	return func(e *Evaluator) {
		e.explain = enabled
	}
}

// PolicyExt is the canonical file extension for CrowdControl policy files.
const PolicyExt = ".cc"

// New creates an Evaluator by loading .cc files from the given directories.
func New(policyDirs []string, opts ...Option) (*Evaluator, error) {
	e := &Evaluator{defaultEffect: types.DefaultAllow}
	for _, opt := range opts {
		opt(e)
	}

	for _, dir := range policyDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || filepath.Ext(entry.Name()) != PolicyExt {
				continue
			}
			data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
			if err != nil {
				return nil, fmt.Errorf("reading %s: %w", entry.Name(), err)
			}
			policy, err := parser.Parse(string(data))
			if err != nil {
				return nil, fmt.Errorf("parsing %s: %w", entry.Name(), err)
			}
			e.policies = append(e.policies, policy)
		}
	}

	return e, nil
}

// NewFromPolicies creates an Evaluator from pre-parsed policies.
func NewFromPolicies(policies []*types.Policy, opts ...Option) *Evaluator {
	e := &Evaluator{policies: policies, defaultEffect: types.DefaultAllow}
	for _, opt := range opts {
		opt(e)
	}
	return e
}

// Evaluate runs all loaded policies against a single document.
// Returns one Result per rule, plus an implicit deny if DefaultDeny
// is set and no permit fired.
func (e *Evaluator) Evaluate(doc map[string]any) []types.Result {
	var results []types.Result
	permitFired := false
	forbidFired := false

	for _, policy := range e.policies {
		for _, rule := range policy.Rules {
			result := e.evalRule(rule, doc)
			results = append(results, result)

			// Track whether any permit or forbid actually fired
			if result.Kind == "permit" && result.Message != "" {
				permitFired = true
			}
			if result.Kind == "forbid" && !result.Passed {
				forbidFired = true
			}
		}
	}

	// In DefaultDeny mode, if no permit fired and no forbid already denied,
	// add an implicit denial.
	if e.defaultEffect == types.DefaultDeny && !permitFired && !forbidFired {
		results = append(results, types.Result{
			Rule:    "(default-deny)",
			Kind:    "forbid",
			Passed:  false,
			Message: "no permit rule matched — denied by default",
		})
	}

	return results
}

// EvaluateJSON is a convenience that unmarshals JSON before evaluating.
func (e *Evaluator) EvaluateJSON(data []byte) ([]types.Result, error) {
	var doc map[string]any
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, fmt.Errorf("parsing JSON: %w", err)
	}
	return e.Evaluate(doc), nil
}

// IsAggregate returns true if the rule uses count() aggregate conditions.
// Exported so adapters can separate aggregate from per-resource evaluation.
func IsAggregate(rule types.Rule) bool {
	for _, c := range rule.Conditions {
		if containsAggregate(c) {
			return true
		}
	}
	return false
}

func containsAggregate(c types.Condition) bool {
	if c.Type == types.CondAggregate {
		return true
	}
	if c.Type == types.CondOr {
		for _, sub := range c.OrGroup {
			if containsAggregate(sub) {
				return true
			}
		}
	}
	return false
}

// Policies returns the parsed policies the evaluator is using. The returned
// slice should be treated as read-only.
func (e *Evaluator) Policies() []*types.Policy {
	return e.policies
}

// Validate runs schema validation across every loaded policy and returns
// the resulting warnings.
func (e *Evaluator) Validate(schema *types.Schema) []types.SchemaWarning {
	return ValidatePolicy(e.policies, schema)
}

// AggregateRuleNames returns the names of all aggregate rules across loaded policies.
func (e *Evaluator) AggregateRuleNames() map[string]bool {
	names := make(map[string]bool)
	for _, policy := range e.policies {
		for _, rule := range policy.Rules {
			if IsAggregate(rule) {
				names[rule.Name] = true
			}
		}
	}
	return names
}

// evalRule evaluates a single rule against a document.
func (e *Evaluator) evalRule(rule types.Rule, doc map[string]any) types.Result {
	result := types.Result{
		Rule:        rule.Name,
		Kind:        rule.Kind,
		Passed:      true,
		Description: rule.Description,
		Owner:       rule.Owner,
		Link:        rule.Link,
	}

	var trace *types.RuleTrace
	if e.explain {
		trace = &types.RuleTrace{}
	}

	// Check all conditions (AND'd) — all must match for rule to fire
	allMatch := true
	for _, cond := range rule.Conditions {
		matched := evalCondition(cond, doc)
		if trace != nil {
			trace.Conditions = append(trace.Conditions, traceCondition(cond, doc, matched))
		}
		if !matched {
			allMatch = false
			// In explain mode, keep evaluating remaining conditions for full trace
			if !e.explain {
				break
			}
		}
	}

	if trace != nil {
		trace.AllConditionsMatched = allMatch
	}

	if !allMatch {
		if trace != nil {
			result.Trace = trace
		}
		return result
	}

	// Conditions matched. Check unlesses (OR'd) — any one saves you.
	savedByUnless := false
	for _, unless := range rule.Unlesses {
		matched := evalCondition(unless, doc)
		if trace != nil {
			trace.Unlesses = append(trace.Unlesses, traceCondition(unless, doc, matched))
		}
		if matched {
			savedByUnless = true
			// In explain mode, keep evaluating remaining unlesses for full trace
			if !e.explain {
				break
			}
		}
	}

	if trace != nil {
		trace.SavedByUnless = savedByUnless
	}

	if savedByUnless {
		if trace != nil {
			result.Trace = trace
		}
		return result
	}

	// Rule fires
	switch rule.Kind {
	case "permit":
		result.Passed = true
		result.Message = interpolateMessage(rule.Message, doc)
	default:
		result.Passed = false
		result.Message = interpolateMessage(rule.Message, doc)
	}

	if trace != nil {
		result.Trace = trace
	}
	return result
}

// traceCondition builds a ConditionTrace for a single condition.
func traceCondition(cond types.Condition, doc map[string]any, result bool) types.ConditionTrace {
	ct := types.ConditionTrace{
		Expr:   conditionExpr(cond),
		Result: result,
		Actual: resolveActual(cond, doc),
	}

	if cond.Type == types.CondOr {
		for _, sub := range cond.OrGroup {
			subResult := evalCondition(sub, doc)
			ct.Children = append(ct.Children, traceCondition(sub, doc, subResult))
		}
	}

	return ct
}

// conditionExpr returns a human-readable string for a condition.
func conditionExpr(cond types.Condition) string {
	prefix := ""
	if cond.Negated {
		prefix = "not "
	}

	switch cond.Type {
	case types.CondField:
		field := cond.Field
		if cond.Transform != "" {
			field = fmt.Sprintf("%s(%s)", cond.Transform, cond.Field)
		}
		return prefix + fmt.Sprintf("%s %s %v", field, cond.Op, formatValue(cond.Value))
	case types.CondAggregate:
		return prefix + fmt.Sprintf("count(%s) %s %v", cond.AggregateTarget, cond.Op, cond.Value)
	case types.CondHas:
		return prefix + fmt.Sprintf("has %s", cond.Field)
	case types.CondAny:
		if cond.Predicate != nil {
			return prefix + fmt.Sprintf("any %s %s %v", cond.ListField, cond.Predicate.Op, formatValue(cond.Predicate.Value))
		}
		return prefix + fmt.Sprintf("any %s <predicate>", cond.ListField)
	case types.CondAll:
		if cond.Predicate != nil {
			return prefix + fmt.Sprintf("all %s %s %v", cond.ListField, cond.Predicate.Op, formatValue(cond.Predicate.Value))
		}
		return prefix + fmt.Sprintf("all %s <predicate>", cond.ListField)
	case types.CondOr:
		var parts []string
		for _, sub := range cond.OrGroup {
			parts = append(parts, conditionExpr(sub))
		}
		return prefix + strings.Join(parts, " or ")
	case types.CondExpr:
		left := exprString(cond.LeftExpr)
		right := exprString(cond.RightExpr)
		return prefix + fmt.Sprintf("%s %s %s", left, cond.Op, right)
	default:
		return prefix + "<unknown>"
	}
}

// exprString returns a human-readable string for an expression tree.
func exprString(expr *types.Expr) string {
	if expr == nil {
		return "<nil>"
	}
	switch expr.Kind {
	case types.ExprField:
		return expr.Field
	case types.ExprLiteral:
		if expr.Value == float64(int(expr.Value)) {
			return fmt.Sprintf("%d", int(expr.Value))
		}
		return fmt.Sprintf("%g", expr.Value)
	case types.ExprCount:
		return fmt.Sprintf("count(%s)", expr.AggTarget)
	case types.ExprLen:
		return fmt.Sprintf("len(%s)", expr.Field)
	case types.ExprBinary:
		return fmt.Sprintf("%s %s %s", exprString(expr.Left), expr.Op, exprString(expr.Right))
	}
	return "<unknown>"
}

// resolveActual returns a string representation of the actual value from the document.
func resolveActual(cond types.Condition, doc map[string]any) string {
	switch cond.Type {
	case types.CondField:
		val := ResolveField(cond.Field, doc)
		return formatActual(val)
	case types.CondAggregate:
		val := ResolveField(cond.AggregateTarget, doc)
		switch v := val.(type) {
		case []any:
			return fmt.Sprintf("%d", len(v))
		case float64:
			return fmt.Sprintf("%d", int(v))
		case int:
			return fmt.Sprintf("%d", v)
		default:
			return "<nil>"
		}
	case types.CondHas:
		val := ResolveField(cond.Field, doc)
		if val != nil {
			return "exists"
		}
		return "<nil>"
	case types.CondAny, types.CondAll:
		val := ResolveField(cond.ListField, doc)
		items := toSlice(val)
		if items == nil {
			return "<nil>"
		}
		return fmt.Sprintf("[%d items]", len(items))
	case types.CondExpr:
		if cond.LeftExpr != nil {
			left, lok := evalExpr(cond.LeftExpr, doc)
			right, rok := evalExpr(cond.RightExpr, doc)
			if lok && rok {
				return fmt.Sprintf("%g vs %g", left, right)
			}
		}
		return ""
	case types.CondOr:
		return "" // children have their own actuals
	default:
		return ""
	}
}

func formatValue(v any) string {
	switch val := v.(type) {
	case string:
		return fmt.Sprintf("%q", val)
	case []string:
		quoted := make([]string, len(val))
		for i, s := range val {
			quoted[i] = fmt.Sprintf("%q", s)
		}
		return "[" + strings.Join(quoted, ", ") + "]"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func formatActual(v any) string {
	if v == nil {
		return "<nil>"
	}
	switch val := v.(type) {
	case []any:
		if len(val) <= 5 {
			parts := make([]string, len(val))
			for i, item := range val {
				parts[i] = fmt.Sprintf("%v", item)
			}
			return "[" + strings.Join(parts, ", ") + "]"
		}
		return fmt.Sprintf("[%d items]", len(val))
	case string:
		return fmt.Sprintf("%q", val)
	case bool:
		return fmt.Sprintf("%v", val)
	default:
		return fmt.Sprintf("%v", val)
	}
}

// FormatExplain produces human-readable explain output for a set of results.
func FormatExplain(results []types.Result) string {
	var sb strings.Builder

	for _, r := range results {
		// Determine outcome label
		var outcome string
		switch {
		case r.Kind == "permit" && r.Message != "":
			outcome = "PERMITTED"
		case r.Kind == "warn" && !r.Passed:
			outcome = "WARNED"
		case !r.Passed:
			outcome = "DENIED"
		default:
			outcome = "PASSED"
		}

		sb.WriteString(fmt.Sprintf("RULE %q [%s] -> %s\n", r.Rule, r.Kind, outcome))

		if r.Trace == nil {
			if r.Message != "" {
				sb.WriteString(fmt.Sprintf("  -> %s\n", r.Message))
			}
			sb.WriteString("\n")
			continue
		}

		// Print conditions
		for _, ct := range r.Trace.Conditions {
			writeConditionTrace(&sb, ct, "condition", "  ")
		}

		// Print unlesses (only if conditions all matched)
		if r.Trace.AllConditionsMatched {
			for _, ct := range r.Trace.Unlesses {
				writeConditionTrace(&sb, ct, "unless", "  ")
			}
		}

		// Print final outcome
		switch {
		case !r.Trace.AllConditionsMatched:
			sb.WriteString("  -> conditions not met, rule did not fire\n")
		case r.Trace.SavedByUnless:
			sb.WriteString("  -> saved by unless clause\n")
		case r.Message != "":
			sb.WriteString(fmt.Sprintf("  -> %s\n", r.Message))
		}

		sb.WriteString("\n")
	}

	return sb.String()
}

func writeConditionTrace(sb *strings.Builder, ct types.ConditionTrace, label, indent string) {
	mark := "+"
	if !ct.Result {
		mark = "-"
	}

	actual := ""
	if ct.Actual != "" {
		actual = fmt.Sprintf(" (got %s)", ct.Actual)
	}

	sb.WriteString(fmt.Sprintf("%s%s %s: %s -> %v%s\n", indent, mark, label, ct.Expr, ct.Result, actual))

	for _, child := range ct.Children {
		writeConditionTrace(sb, child, "or", indent+"  ")
	}
}

// evalCondition evaluates a single condition, applying negation if set.
func evalCondition(cond types.Condition, doc map[string]any) bool {
	result := evalConditionInner(cond, doc)
	if cond.Negated {
		return !result
	}
	return result
}

func evalConditionInner(cond types.Condition, doc map[string]any) bool {
	switch cond.Type {
	case types.CondAggregate:
		return evalAggregate(cond, doc)

	case types.CondField:
		return evalFieldCondition(cond, doc)

	case types.CondOr:
		for _, sub := range cond.OrGroup {
			if evalCondition(sub, doc) {
				return true
			}
		}
		return false

	case types.CondAny:
		return evalQuantifier(cond, doc, false)

	case types.CondAll:
		return evalQuantifier(cond, doc, true)

	case types.CondHas:
		return ResolveField(cond.Field, doc) != nil

	case types.CondExpr:
		return evalExprCondition(cond, doc)

	default:
		return false
	}
}

// evalQuantifier evaluates any/all conditions against list elements.
func evalQuantifier(cond types.Condition, doc map[string]any, requireAll bool) bool {
	list := ResolveField(cond.ListField, doc)
	if list == nil {
		return requireAll // all over empty is true, any over empty is false
	}

	items := toSlice(list)
	if items == nil {
		return requireAll
	}
	if len(items) == 0 {
		return requireAll
	}

	pred := cond.Predicate
	if pred == nil {
		return false
	}

	for _, item := range items {
		matched := evalElementPredicate(*pred, doc, item)
		if requireAll && !matched {
			return false
		}
		if !requireAll && matched {
			return true
		}
	}
	return requireAll
}

// evalElementPredicate evaluates a predicate against a single list element.
func evalElementPredicate(pred types.Condition, doc map[string]any, element any) bool {
	elemStr := fmt.Sprintf("%v", element)

	switch pred.Type {
	case types.CondField:
		switch pred.Op {
		case "==":
			return elemStr == fmt.Sprintf("%v", pred.Value)
		case "!=":
			return elemStr != fmt.Sprintf("%v", pred.Value)
		case "in":
			list, ok := pred.Value.([]string)
			if !ok {
				return false
			}
			for _, item := range list {
				if elemStr == item {
					return true
				}
			}
			return false
		case "matches":
			pattern, ok := pred.Value.(string)
			if !ok {
				return false
			}
			return globMatch(pattern, elemStr)
		case "matches_regex":
			pattern, ok := pred.Value.(string)
			if !ok {
				return false
			}
			return regexMatch(pattern, elemStr)
		case "contains":
			return evalContains(element, pred.Value)
		default:
			return compareValues(element, pred.Op, pred.Value)
		}
	default:
		return false
	}
}

// evalExprCondition evaluates an arithmetic expression condition: expr op expr
func evalExprCondition(cond types.Condition, doc map[string]any) bool {
	if cond.LeftExpr == nil || cond.RightExpr == nil {
		return false
	}

	left, lok := evalExpr(cond.LeftExpr, doc)
	right, rok := evalExpr(cond.RightExpr, doc)
	if !lok || !rok {
		return false
	}

	return compareFloats(left, cond.Op, right)
}

// evalExpr recursively evaluates an expression tree to a float64.
func evalExpr(expr *types.Expr, doc map[string]any) (float64, bool) {
	switch expr.Kind {
	case types.ExprLiteral:
		return expr.Value, true

	case types.ExprField:
		val := ResolveField(expr.Field, doc)
		f := toFloat(val)
		if f == nil {
			return 0, false
		}
		return *f, true

	case types.ExprCount:
		val := ResolveField(expr.AggTarget, doc)
		switch v := val.(type) {
		case []any:
			return float64(len(v)), true
		case float64:
			return v, true
		case int:
			return float64(v), true
		default:
			return 0, false
		}

	case types.ExprLen:
		val := ResolveField(expr.Field, doc)
		switch v := val.(type) {
		case string:
			return float64(len(v)), true
		case []any:
			return float64(len(v)), true
		case []string:
			return float64(len(v)), true
		case nil:
			return 0, true
		default:
			return 0, false
		}

	case types.ExprBinary:
		left, lok := evalExpr(expr.Left, doc)
		right, rok := evalExpr(expr.Right, doc)
		if !lok || !rok {
			return 0, false
		}
		switch expr.Op {
		case "+":
			return left + right, true
		case "-":
			return left - right, true
		case "*":
			return left * right, true
		case "/":
			if right == 0 {
				return 0, false // divide by zero returns false
			}
			return left / right, true
		}
	}
	return 0, false
}

func evalAggregate(cond types.Condition, doc map[string]any) bool {
	val := ResolveField(cond.AggregateTarget, doc)

	var count int
	switch v := val.(type) {
	case []any:
		count = len(v)
	case float64:
		count = int(v)
	case int:
		count = v
	default:
		return false
	}

	target, ok := cond.Value.(int)
	if !ok {
		return false
	}

	return compareInts(count, cond.Op, target)
}

func evalFieldCondition(cond types.Condition, doc map[string]any) bool {
	val := ResolveField(cond.Field, doc)

	// Apply transform if present
	if cond.Transform != "" {
		val = applyTransform(cond.Transform, val)
	}

	switch cond.Op {
	case "==":
		return fmt.Sprintf("%v", val) == fmt.Sprintf("%v", cond.Value)
	case "!=":
		return fmt.Sprintf("%v", val) != fmt.Sprintf("%v", cond.Value)
	case "<", ">", "<=", ">=":
		return compareValues(val, cond.Op, cond.Value)
	case "in":
		list, ok := cond.Value.([]string)
		if !ok {
			return false
		}
		s := fmt.Sprintf("%v", val)
		for _, item := range list {
			if s == item {
				return true
			}
		}
		return false
	case "matches":
		pattern, ok := cond.Value.(string)
		if !ok {
			return false
		}
		return globMatch(pattern, fmt.Sprintf("%v", val))
	case "matches_regex":
		pattern, ok := cond.Value.(string)
		if !ok {
			return false
		}
		return regexMatch(pattern, fmt.Sprintf("%v", val))
	case "contains":
		return evalContains(val, cond.Value)
	case "intersects":
		return evalIntersects(val, cond.Value)
	case "is_subset":
		return evalIsSubset(val, cond.Value)
	}

	return false
}

// evalContains checks if a list/slice value contains the target value.
// If val is a slice, checks membership. If val is a string, checks substring.
func evalContains(val any, target any) bool {
	targetStr := fmt.Sprintf("%v", target)

	switch v := val.(type) {
	case []any:
		for _, item := range v {
			if fmt.Sprintf("%v", item) == targetStr {
				return true
			}
		}
		return false
	case []string:
		for _, item := range v {
			if item == targetStr {
				return true
			}
		}
		return false
	case string:
		return strings.Contains(v, targetStr)
	default:
		return false
	}
}

// evalIntersects checks if any element in the LHS list appears in the RHS list.
func evalIntersects(val any, target any) bool {
	rhs, ok := target.([]string)
	if !ok {
		return false
	}
	rhsSet := make(map[string]bool, len(rhs))
	for _, s := range rhs {
		rhsSet[s] = true
	}

	switch v := val.(type) {
	case []any:
		for _, item := range v {
			if rhsSet[fmt.Sprintf("%v", item)] {
				return true
			}
		}
	case []string:
		for _, item := range v {
			if rhsSet[item] {
				return true
			}
		}
	}
	return false
}

// evalIsSubset checks if every element in the LHS list appears in the RHS list.
func evalIsSubset(val any, target any) bool {
	rhs, ok := target.([]string)
	if !ok {
		return false
	}
	rhsSet := make(map[string]bool, len(rhs))
	for _, s := range rhs {
		rhsSet[s] = true
	}

	switch v := val.(type) {
	case []any:
		if len(v) == 0 {
			return true
		}
		for _, item := range v {
			if !rhsSet[fmt.Sprintf("%v", item)] {
				return false
			}
		}
		return true
	case []string:
		if len(v) == 0 {
			return true
		}
		for _, item := range v {
			if !rhsSet[item] {
				return false
			}
		}
		return true
	}
	return false
}

// ResolveField resolves a dotted path against an arbitrary document.
// Exported so adapters can use it for document introspection.
func ResolveField(path string, doc map[string]any) any {
	if doc == nil {
		return nil
	}
	parts := strings.Split(path, ".")
	var current any = doc
	for _, part := range parts {
		switch v := current.(type) {
		case map[string]any:
			current = v[part]
		default:
			return nil
		}
	}
	return current
}

// toSlice normalizes a value to []any for iteration.
func toSlice(v any) []any {
	switch list := v.(type) {
	case []any:
		return list
	case []string:
		items := make([]any, len(list))
		for i, s := range list {
			items[i] = s
		}
		return items
	case []int:
		items := make([]any, len(list))
		for i, n := range list {
			items[i] = n
		}
		return items
	case []float64:
		items := make([]any, len(list))
		for i, f := range list {
			items[i] = f
		}
		return items
	case []map[string]any:
		items := make([]any, len(list))
		for i, m := range list {
			items[i] = m
		}
		return items
	default:
		return nil
	}
}

func compareInts(a int, op string, b int) bool {
	switch op {
	case "<":
		return a < b
	case ">":
		return a > b
	case "<=":
		return a <= b
	case ">=":
		return a >= b
	case "==":
		return a == b
	case "!=":
		return a != b
	}
	return false
}

func compareValues(a any, op string, b any) bool {
	aNum := toFloat(a)
	bNum := toFloat(b)
	if aNum != nil && bNum != nil {
		return compareFloats(*aNum, op, *bNum)
	}
	return false
}

func compareFloats(a float64, op string, b float64) bool {
	switch op {
	case "<":
		return a < b
	case ">":
		return a > b
	case "<=":
		return a <= b
	case ">=":
		return a >= b
	case "==":
		return a == b
	case "!=":
		return a != b
	}
	return false
}

func toFloat(v any) *float64 {
	switch n := v.(type) {
	case int:
		f := float64(n)
		return &f
	case float64:
		return &n
	case string:
		return nil
	}
	return nil
}

// applyTransform applies a builtin transform function to a field value.
func applyTransform(transform string, val any) any {
	switch transform {
	case "lower":
		if s, ok := val.(string); ok {
			return strings.ToLower(s)
		}
		return strings.ToLower(fmt.Sprintf("%v", val))
	case "upper":
		if s, ok := val.(string); ok {
			return strings.ToUpper(s)
		}
		return strings.ToUpper(fmt.Sprintf("%v", val))
	case "len":
		switch v := val.(type) {
		case string:
			return len(v)
		case []any:
			return len(v)
		case []string:
			return len(v)
		case nil:
			return 0
		default:
			return 0
		}
	}
	return val
}

// regexCache caches compiled regular expressions for performance.
var regexCache = make(map[string]*regexp.Regexp)

// regexMatch matches a string against a regular expression pattern.
// Invalid patterns return false (no panic).
func regexMatch(pattern, s string) bool {
	re, ok := regexCache[pattern]
	if !ok {
		var err error
		re, err = regexp.Compile(pattern)
		if err != nil {
			return false
		}
		regexCache[pattern] = re
	}
	return re.MatchString(s)
}

// globMatch implements simple glob matching (* matches any sequence).
func globMatch(pattern, s string) bool {
	if pattern == "*" {
		return true
	}
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(s, prefix)
	}
	if strings.HasPrefix(pattern, "*") {
		suffix := strings.TrimPrefix(pattern, "*")
		return strings.HasSuffix(s, suffix)
	}
	if idx := strings.Index(pattern, "*"); idx >= 0 {
		prefix := pattern[:idx]
		suffix := pattern[idx+1:]
		return strings.HasPrefix(s, prefix) && strings.HasSuffix(s, suffix)
	}
	return pattern == s
}

// interpolateMessage replaces {expr} placeholders by resolving paths against the document.
var interpolateRe = regexp.MustCompile(`\{([^}]+)\}`)

func interpolateMessage(msg string, doc map[string]any) string {
	if msg == "" {
		return "policy violation"
	}

	return interpolateRe.ReplaceAllStringFunc(msg, func(match string) string {
		expr := match[1 : len(match)-1] // strip { }

		// Handle count() expressions
		if strings.HasPrefix(expr, "count(") && strings.HasSuffix(expr, ")") {
			target := expr[6 : len(expr)-1]
			val := ResolveField(target, doc)
			switch v := val.(type) {
			case []any:
				return fmt.Sprintf("%d", len(v))
			case float64:
				return fmt.Sprintf("%d", int(v))
			case int:
				return fmt.Sprintf("%d", v)
			default:
				return match
			}
		}

		// Resolve field path
		val := ResolveField(expr, doc)
		if val == nil {
			return match // leave unresolved placeholders as-is
		}

		return fmt.Sprintf("%v", val)
	})
}

// FormatResults produces human-readable output.
func FormatResults(results []types.Result) (string, bool) {
	allPassed := true
	var sb strings.Builder

	for _, r := range results {
		if r.Passed {
			continue
		}
		prefix := "DENY"
		if r.Kind == "warn" {
			prefix = "WARN"
		} else {
			allPassed = false
		}

		line := fmt.Sprintf("%s: %s (%s)", prefix, r.Message, r.Rule)

		var meta []string
		if r.Owner != "" {
			meta = append(meta, "owner: "+r.Owner)
		}
		if r.Link != "" {
			meta = append(meta, "link: "+r.Link)
		}
		if len(meta) > 0 {
			line += " [" + strings.Join(meta, ", ") + "]"
		}

		sb.WriteString(line + "\n")
	}

	if allPassed {
		passed := 0
		for _, r := range results {
			if r.Passed {
				passed++
			}
		}
		sb.WriteString(fmt.Sprintf("PASS: %d rules evaluated, all passed\n", passed))
	}

	return sb.String(), allPassed
}
