/*
 * Static schema validation for CrowdControl policies.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/evaluator/validate.go to
 * Kotlin. Produces non-fatal warnings for typos, type mismatches, and other
 * issues. Validation never fails — it only reports.
 */
package io.github.mikemackintosh.crowdcontrol

/** Run schema validation across every loaded policy. */
fun validatePolicies(policies: List<Policy>, schema: Schema): List<SchemaWarning> {
    val warnings = mutableListOf<SchemaWarning>()
    for (policy in policies) {
        for (rule in policy.rules) {
            for (cond in rule.conditions) {
                validateCondition(cond, schema, rule.name, warnings)
            }
            for (u in rule.unlesses) {
                validateCondition(u, schema, rule.name, warnings)
            }
            if (rule.message.isNotEmpty()) {
                validateInterpolations(rule.message, schema, rule.name, warnings)
            }
        }
    }
    return warnings
}

private fun validateCondition(
    cond: Condition,
    schema: Schema,
    ruleName: String,
    out: MutableList<SchemaWarning>,
) {
    when (cond.type) {
        ConditionType.FIELD -> if (cond.field.isNotEmpty()) checkField(cond.field, schema, ruleName, cond, out)
        ConditionType.HAS -> if (cond.field.isNotEmpty()) checkFieldExists(cond.field, schema, ruleName, out)
        ConditionType.AGGREGATE -> if (cond.aggregateTarget.isNotEmpty()) checkAggregateField(cond.aggregateTarget, schema, ruleName, out)
        ConditionType.ANY, ConditionType.ALL -> {
            if (cond.listField.isNotEmpty()) checkListField(cond.listField, schema, ruleName, out)
            cond.predicate?.let { validateCondition(it, schema, ruleName, out) }
        }
        ConditionType.OR -> {
            for (sub in cond.orGroup) validateCondition(sub, schema, ruleName, out)
        }
        ConditionType.EXPR -> {
            cond.leftExpr?.let { checkExprFields(it, schema, ruleName, out) }
            cond.rightExpr?.let { checkExprFields(it, schema, ruleName, out) }
        }
    }
}

private fun checkField(
    field: String,
    schema: Schema,
    ruleName: String,
    cond: Condition,
    out: MutableList<SchemaWarning>,
) {
    val expected = lookupField(schema, field)
    if (expected == null) {
        out.add(SchemaWarning(rule = ruleName, field = field, message = "field \"$field\" not found in schema"))
        return
    }

    val op = cond.op
    when (op) {
        "<", ">", "<=", ">=" -> {
            if (expected != FieldType.NUMBER && expected != FieldType.ANY) {
                out.add(SchemaWarning(rule = ruleName, field = field, message = "operator $op used on field \"$field\" of type $expected"))
            }
        }
        "contains", "intersects", "is_subset" -> {
            if (expected != FieldType.LIST && expected != FieldType.STRING && expected != FieldType.ANY) {
                out.add(SchemaWarning(rule = ruleName, field = field, message = "operator $op used on field \"$field\" of type $expected"))
            }
        }
        "in" -> {
            if (expected != FieldType.STRING && expected != FieldType.ANY) {
                out.add(SchemaWarning(rule = ruleName, field = field, message = "operator 'in' used on field \"$field\" of type $expected"))
            }
        }
    }
}

private fun checkFieldExists(
    field: String,
    schema: Schema,
    ruleName: String,
    out: MutableList<SchemaWarning>,
) {
    if (lookupField(schema, field) == null) {
        out.add(SchemaWarning(rule = ruleName, field = field, message = "field \"$field\" not found in schema (used with 'has')"))
    }
}

private fun checkAggregateField(
    field: String,
    schema: Schema,
    ruleName: String,
    out: MutableList<SchemaWarning>,
) {
    val expected = lookupField(schema, field)
    if (expected == null) {
        out.add(SchemaWarning(rule = ruleName, field = field, message = "field \"$field\" not found in schema (used with 'count')"))
        return
    }
    if (expected != FieldType.LIST && expected != FieldType.NUMBER && expected != FieldType.ANY) {
        out.add(SchemaWarning(rule = ruleName, field = field, message = "count() used on field \"$field\" of type $expected, expected list or number"))
    }
}

private fun checkListField(
    field: String,
    schema: Schema,
    ruleName: String,
    out: MutableList<SchemaWarning>,
) {
    val expected = lookupField(schema, field)
    if (expected == null) {
        out.add(SchemaWarning(rule = ruleName, field = field, message = "field \"$field\" not found in schema (used with quantifier)"))
        return
    }
    if (expected != FieldType.LIST && expected != FieldType.ANY) {
        out.add(SchemaWarning(rule = ruleName, field = field, message = "quantifier used on field \"$field\" of type $expected, expected list"))
    }
}

private fun checkExprFields(
    expr: Expr,
    schema: Schema,
    ruleName: String,
    out: MutableList<SchemaWarning>,
) {
    when (expr.kind) {
        ExprKind.FIELD -> if (expr.field.isNotEmpty()) {
            val expected = lookupField(schema, expr.field)
            if (expected == null) {
                out.add(SchemaWarning(rule = ruleName, field = expr.field, message = "field \"${expr.field}\" not found in schema (used in arithmetic)"))
            } else if (expected != FieldType.NUMBER && expected != FieldType.ANY) {
                out.add(SchemaWarning(rule = ruleName, field = expr.field, message = "arithmetic used on field \"${expr.field}\" of type $expected, expected number"))
            }
        }
        ExprKind.COUNT -> if (expr.aggTarget.isNotEmpty()) {
            checkAggregateField(expr.aggTarget, schema, ruleName, out)
        }
        ExprKind.LEN -> if (expr.field.isNotEmpty()) {
            if (lookupField(schema, expr.field) == null) {
                out.add(SchemaWarning(rule = ruleName, field = expr.field, message = "field \"${expr.field}\" not found in schema (used with len)"))
            }
        }
        ExprKind.BINARY -> {
            expr.left?.let { checkExprFields(it, schema, ruleName, out) }
            expr.right?.let { checkExprFields(it, schema, ruleName, out) }
        }
        ExprKind.LITERAL -> Unit
    }
}

private val INTERP_RE = Regex("\\{([^}]+)\\}")

private fun validateInterpolations(
    msg: String,
    schema: Schema,
    ruleName: String,
    out: MutableList<SchemaWarning>,
) {
    for (match in INTERP_RE.findAll(msg)) {
        val expr = match.groupValues[1]
        if (expr.startsWith("count(") && expr.endsWith(")")) continue
        if (lookupField(schema, expr) == null) {
            out.add(SchemaWarning(rule = ruleName, field = expr, message = "message interpolation references unknown field \"$expr\""))
        }
    }
}

private fun lookupField(schema: Schema, field: String): String? {
    schema.fields[field]?.let { return it }
    val parts = field.split(".")
    for (i in parts.size - 1 downTo 1) {
        val prefix = parts.subList(0, i).joinToString(".")
        val t = schema.fields[prefix]
        if (t == FieldType.MAP) return FieldType.ANY
    }
    return null
}

/** Render warnings as a newline-terminated plain-text block (empty if none). */
fun formatWarnings(warnings: List<SchemaWarning>): String {
    if (warnings.isEmpty()) return ""
    return warnings.joinToString("\n") { "  ${it.rule}: ${it.message}" } + "\n"
}
