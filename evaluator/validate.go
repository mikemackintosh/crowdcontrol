package evaluator

import (
	"fmt"
	"strings"

	"github.com/mikemackintosh/crowdcontrol/types"
)

// ValidatePolicy checks all field references in the given policies against
// a schema. Returns warnings for unknown fields and type mismatches.
// This is a static analysis pass — no document is needed.
func ValidatePolicy(policies []*types.Policy, schema *types.Schema) []types.SchemaWarning {
	if schema == nil || len(schema.Fields) == 0 {
		return nil
	}

	var warnings []types.SchemaWarning

	for _, policy := range policies {
		for _, rule := range policy.Rules {
			warnings = append(warnings, validateRule(rule, schema)...)
		}
	}

	return warnings
}

func validateRule(rule types.Rule, schema *types.Schema) []types.SchemaWarning {
	var warnings []types.SchemaWarning

	for _, cond := range rule.Conditions {
		warnings = append(warnings, validateCondition(rule.Name, cond, schema)...)
	}
	for _, unless := range rule.Unlesses {
		warnings = append(warnings, validateCondition(rule.Name, unless, schema)...)
	}

	// Check message interpolation references
	warnings = append(warnings, validateMessage(rule.Name, rule.Message, schema)...)

	return warnings
}

func validateCondition(ruleName string, cond types.Condition, schema *types.Schema) []types.SchemaWarning {
	var warnings []types.SchemaWarning

	switch cond.Type {
	case types.CondField:
		if cond.Field != "" {
			warnings = append(warnings, checkField(ruleName, cond.Field, cond.Op, schema)...)
		}

	case types.CondAggregate:
		if cond.AggregateTarget != "" {
			w := checkFieldExists(ruleName, cond.AggregateTarget, schema)
			if w != nil {
				warnings = append(warnings, *w)
			} else {
				// count() target should be a list or number
				if ft, ok := schema.Fields[cond.AggregateTarget]; ok {
					if ft != types.FieldList && ft != types.FieldNumber && ft != types.FieldAny {
						warnings = append(warnings, types.SchemaWarning{
							Rule:    ruleName,
							Field:   cond.AggregateTarget,
							Message: fmt.Sprintf("count(%s) expects a list or number, schema says %s", cond.AggregateTarget, ft),
						})
					}
				}
			}
		}

	case types.CondHas:
		// has checks existence — warn if the field isn't in schema at all
		// (but this is intentional for has, so only warn if the prefix is unknown)
		if cond.Field != "" {
			checkFieldPrefix(ruleName, cond.Field, schema, &warnings)
		}

	case types.CondOr:
		for _, sub := range cond.OrGroup {
			warnings = append(warnings, validateCondition(ruleName, sub, schema)...)
		}

	case types.CondAny, types.CondAll:
		if cond.ListField != "" {
			w := checkFieldExists(ruleName, cond.ListField, schema)
			if w != nil {
				warnings = append(warnings, *w)
			} else if ft, ok := schema.Fields[cond.ListField]; ok {
				if ft != types.FieldList && ft != types.FieldAny {
					warnings = append(warnings, types.SchemaWarning{
						Rule:    ruleName,
						Field:   cond.ListField,
						Message: fmt.Sprintf("%s %s expects a list, schema says %s", cond.Quantifier, cond.ListField, ft),
					})
				}
			}
		}

	case types.CondExpr:
		if cond.LeftExpr != nil {
			warnings = append(warnings, validateExpr(ruleName, cond.LeftExpr, schema)...)
		}
		if cond.RightExpr != nil {
			warnings = append(warnings, validateExpr(ruleName, cond.RightExpr, schema)...)
		}
	}

	return warnings
}

func validateExpr(ruleName string, expr *types.Expr, schema *types.Schema) []types.SchemaWarning {
	var warnings []types.SchemaWarning

	switch expr.Kind {
	case types.ExprField:
		w := checkFieldExists(ruleName, expr.Field, schema)
		if w != nil {
			warnings = append(warnings, *w)
		} else if ft, ok := schema.Fields[expr.Field]; ok {
			if ft != types.FieldNumber && ft != types.FieldAny {
				warnings = append(warnings, types.SchemaWarning{
					Rule:    ruleName,
					Field:   expr.Field,
					Message: fmt.Sprintf("%s used in arithmetic but schema says %s", expr.Field, ft),
				})
			}
		}

	case types.ExprCount:
		w := checkFieldExists(ruleName, expr.AggTarget, schema)
		if w != nil {
			warnings = append(warnings, *w)
		}

	case types.ExprLen:
		w := checkFieldExists(ruleName, expr.Field, schema)
		if w != nil {
			warnings = append(warnings, *w)
		}

	case types.ExprBinary:
		if expr.Left != nil {
			warnings = append(warnings, validateExpr(ruleName, expr.Left, schema)...)
		}
		if expr.Right != nil {
			warnings = append(warnings, validateExpr(ruleName, expr.Right, schema)...)
		}
	}

	return warnings
}

// checkField checks if a field exists in the schema and validates type compatibility
// with the operator being used.
func checkField(ruleName, field, op string, schema *types.Schema) []types.SchemaWarning {
	var warnings []types.SchemaWarning

	w := checkFieldExists(ruleName, field, schema)
	if w != nil {
		warnings = append(warnings, *w)
		return warnings
	}

	ft, ok := schema.Fields[field]
	if !ok || ft == types.FieldAny {
		return nil
	}

	// Type-operator compatibility checks
	switch op {
	case "<", ">", "<=", ">=":
		if ft != types.FieldNumber {
			warnings = append(warnings, types.SchemaWarning{
				Rule:    ruleName,
				Field:   field,
				Message: fmt.Sprintf("%s %s used with numeric operator, schema says %s", field, op, ft),
			})
		}
	case "contains":
		if ft != types.FieldList && ft != types.FieldString {
			warnings = append(warnings, types.SchemaWarning{
				Rule:    ruleName,
				Field:   field,
				Message: fmt.Sprintf("%s contains expects list or string, schema says %s", field, ft),
			})
		}
	case "intersects", "is_subset":
		if ft != types.FieldList {
			warnings = append(warnings, types.SchemaWarning{
				Rule:    ruleName,
				Field:   field,
				Message: fmt.Sprintf("%s %s expects a list, schema says %s", field, op, ft),
			})
		}
	case "matches", "matches_regex":
		if ft != types.FieldString {
			warnings = append(warnings, types.SchemaWarning{
				Rule:    ruleName,
				Field:   field,
				Message: fmt.Sprintf("%s %s expects a string, schema says %s", field, op, ft),
			})
		}
	}

	return warnings
}

// checkFieldExists returns a warning if the field is not in the schema.
// Returns nil if the field is known or if any prefix of it is known as a map.
func checkFieldExists(ruleName, field string, schema *types.Schema) *types.SchemaWarning {
	// Direct match
	if _, ok := schema.Fields[field]; ok {
		return nil
	}

	// Check if any prefix is a map type (allowing nested access beyond the schema)
	parts := strings.Split(field, ".")
	for i := len(parts) - 1; i >= 1; i-- {
		prefix := strings.Join(parts[:i], ".")
		if ft, ok := schema.Fields[prefix]; ok {
			if ft == types.FieldMap || ft == types.FieldAny {
				return nil // parent is a map, nested access is fine
			}
			// Parent exists but isn't a map — can't traverse further
			return &types.SchemaWarning{
				Rule:    ruleName,
				Field:   field,
				Message: fmt.Sprintf("unknown field %q (parent %q is %s, not a map)", field, prefix, ft),
			}
		}
	}

	// No match at all — unknown field
	return &types.SchemaWarning{
		Rule:    ruleName,
		Field:   field,
		Message: fmt.Sprintf("unknown field %q — not in schema (typo?)", field),
	}
}

// checkFieldPrefix warns if the top-level segment of a field doesn't appear anywhere in the schema.
func checkFieldPrefix(ruleName, field string, schema *types.Schema, warnings *[]types.SchemaWarning) {
	topLevel := strings.Split(field, ".")[0]
	for k := range schema.Fields {
		if strings.Split(k, ".")[0] == topLevel {
			return // top-level namespace exists
		}
	}
	*warnings = append(*warnings, types.SchemaWarning{
		Rule:    ruleName,
		Field:   field,
		Message: fmt.Sprintf("unknown field %q — namespace %q not in schema (typo?)", field, topLevel),
	})
}

// validateMessage checks {interpolation} references in message templates.
func validateMessage(ruleName, msg string, schema *types.Schema) []types.SchemaWarning {
	if msg == "" {
		return nil
	}

	var warnings []types.SchemaWarning

	matches := interpolateRe.FindAllStringSubmatch(msg, -1)
	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		expr := m[1]

		// Skip count() expressions
		if strings.HasPrefix(expr, "count(") && strings.HasSuffix(expr, ")") {
			target := expr[6 : len(expr)-1]
			w := checkFieldExists(ruleName, target, schema)
			if w != nil {
				w.Message = fmt.Sprintf("message interpolation: %s", w.Message)
				warnings = append(warnings, *w)
			}
			continue
		}

		// Regular field reference
		w := checkFieldExists(ruleName, expr, schema)
		if w != nil {
			w.Message = fmt.Sprintf("message interpolation: %s", w.Message)
			warnings = append(warnings, *w)
		}
	}

	return warnings
}

// FormatWarnings produces human-readable output for schema warnings.
func FormatWarnings(warnings []types.SchemaWarning) string {
	if len(warnings) == 0 {
		return ""
	}

	var sb strings.Builder
	for _, w := range warnings {
		sb.WriteString(fmt.Sprintf("  WARN [%s]: %s\n", w.Rule, w.Message))
	}
	return sb.String()
}
