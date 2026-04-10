/*
 * Evaluator for CrowdControl policies.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/evaluator/evaluator.go to
 * Kotlin. Pure stdlib — java.util.regex for regex matching.
 */
package io.github.mikemackintosh.crowdcontrol

import java.io.File
import java.util.regex.Pattern
import java.util.regex.PatternSyntaxException

/** File extension for policy files loaded from directories. */
const val POLICY_EXT: String = ".cc"

/**
 * Engine loads and runs CrowdControl policies against JSON-like documents.
 *
 * The name "Engine" is used in the public API for idiomatic Kotlin; the
 * underlying class also exposes static-like factory methods for Java interop.
 */
class Engine @JvmOverloads constructor(
    private val _policies: List<Policy> = emptyList(),
    private val defaultEffect: DefaultEffect = DefaultEffect.ALLOW,
    private val explain: Boolean = false,
) {
    /** Loaded policies, in the order they were added. */
    val policies: List<Policy> get() = _policies

    /**
     * Evaluate every rule against [doc], returning one [Result] per rule
     * (plus an optional synthetic `(default-deny)` result when
     * [DefaultEffect.DENY] is in effect and nothing matched).
     */
    fun evaluate(doc: Map<String, Any?>): List<Result> {
        val results = mutableListOf<Result>()
        var permitFired = false
        var forbidFired = false

        for (policy in _policies) {
            for (rule in policy.rules) {
                val r = evalRule(rule, doc)
                results.add(r)
                if (r.kind == "permit" && r.message.isNotEmpty()) {
                    permitFired = true
                }
                if (r.kind == "forbid" && !r.passed) {
                    forbidFired = true
                }
            }
        }

        if (defaultEffect == DefaultEffect.DENY && !permitFired && !forbidFired) {
            results.add(
                Result(
                    rule = "(default-deny)",
                    kind = "forbid",
                    passed = false,
                    message = "no permit rule matched — denied by default",
                )
            )
        }

        return results
    }

    /** Run schema validation across every loaded policy. */
    fun validate(schema: Schema): List<SchemaWarning> = validatePolicies(_policies, schema)

    // ----- rule evaluation -------------------------------------------------

    private fun evalRule(rule: Rule, doc: Map<String, Any?>): Result {
        val trace: RuleTrace? = if (explain) RuleTrace() else null

        var allMatch = true
        for (cond in rule.conditions) {
            val matched = evalCondition(cond, doc)
            if (trace != null) {
                trace.conditions.add(traceCondition(cond, doc, matched))
            }
            if (!matched) {
                allMatch = false
                if (trace == null) break
            }
        }
        trace?.allConditionsMatched = allMatch

        if (!allMatch) {
            return Result(
                rule = rule.name,
                kind = rule.kind,
                passed = true,
                description = rule.description,
                owner = rule.owner,
                link = rule.link,
                trace = trace,
            )
        }

        var saved = false
        for (u in rule.unlesses) {
            val matched = evalCondition(u, doc)
            if (trace != null) {
                trace.unlesses.add(traceCondition(u, doc, matched))
            }
            if (matched) {
                saved = true
                if (trace == null) break
            }
        }
        trace?.savedByUnless = saved

        if (saved) {
            return Result(
                rule = rule.name,
                kind = rule.kind,
                passed = true,
                description = rule.description,
                owner = rule.owner,
                link = rule.link,
                trace = trace,
            )
        }

        // Rule fires.
        val passed = rule.kind == "permit"
        return Result(
            rule = rule.name,
            kind = rule.kind,
            passed = passed,
            message = interpolateMessage(rule.message, doc),
            description = rule.description,
            owner = rule.owner,
            link = rule.link,
            trace = trace,
        )
    }

    companion object {
        /** Create an Engine from in-memory policy source strings. */
        @JvmStatic
        @JvmOverloads
        fun fromSource(
            sources: List<String>,
            defaultEffect: DefaultEffect = DefaultEffect.ALLOW,
            explain: Boolean = false,
        ): Engine {
            val policies = sources.map { parse(it) }
            return Engine(policies, defaultEffect, explain)
        }

        /** Load every `*.cc` file from each of the given directories. */
        @JvmStatic
        @JvmOverloads
        fun fromDirectory(
            policyDirs: List<String>,
            defaultEffect: DefaultEffect = DefaultEffect.ALLOW,
            explain: Boolean = false,
        ): Engine {
            val policies = mutableListOf<Policy>()
            for (d in policyDirs) {
                val dir = File(d)
                if (!dir.isDirectory) continue
                val entries = dir.listFiles() ?: continue
                entries.sortBy { it.name }
                for (f in entries) {
                    if (!f.isFile) continue
                    if (!f.name.endsWith(POLICY_EXT)) continue
                    policies.add(parse(f.readText(Charsets.UTF_8)))
                }
            }
            return Engine(policies, defaultEffect, explain)
        }
    }
}

// ===========================================================================
// Condition evaluation
// ===========================================================================

/** Evaluate a single condition against a document. Public for testing. */
fun evalCondition(cond: Condition, doc: Map<String, Any?>): Boolean {
    val r = evalConditionInner(cond, doc)
    return if (cond.negated) !r else r
}

private fun evalConditionInner(cond: Condition, doc: Map<String, Any?>): Boolean {
    return when (cond.type) {
        ConditionType.AGGREGATE -> evalAggregate(cond, doc)
        ConditionType.FIELD -> evalFieldCondition(cond, doc)
        ConditionType.OR -> cond.orGroup.any { evalCondition(it, doc) }
        ConditionType.ANY -> evalQuantifier(cond, doc, requireAll = false)
        ConditionType.ALL -> evalQuantifier(cond, doc, requireAll = true)
        ConditionType.HAS -> resolveField(cond.field, doc) != null
        ConditionType.EXPR -> evalExprCondition(cond, doc)
    }
}

private fun evalQuantifier(cond: Condition, doc: Map<String, Any?>, requireAll: Boolean): Boolean {
    val raw = resolveField(cond.listField, doc)
    val items = toList(raw) ?: return requireAll
    if (items.isEmpty()) return requireAll
    val pred = cond.predicate ?: return false
    for (item in items) {
        val matched = evalElementPredicate(pred, item)
        if (requireAll && !matched) return false
        if (!requireAll && matched) return true
    }
    return requireAll
}

private fun evalElementPredicate(pred: Condition, element: Any?): Boolean {
    val elemStr = fmtV(element)
    if (pred.type != ConditionType.FIELD) return false
    val op = pred.op
    return when (op) {
        "==" -> elemStr == fmtV(pred.value)
        "!=" -> elemStr != fmtV(pred.value)
        "in" -> {
            val lst = pred.value as? List<*> ?: return false
            lst.any { elemStr == it }
        }
        "matches" -> {
            val pattern = pred.value as? String ?: return false
            globMatch(pattern, elemStr)
        }
        "matches_regex" -> {
            val pattern = pred.value as? String ?: return false
            regexMatch(pattern, elemStr)
        }
        "contains" -> evalContains(element, pred.value)
        else -> compareValues(element, op, pred.value)
    }
}

private fun evalExprCondition(cond: Condition, doc: Map<String, Any?>): Boolean {
    val le = cond.leftExpr ?: return false
    val re = cond.rightExpr ?: return false
    val (l, lok) = evalExpr(le, doc)
    val (r, rok) = evalExpr(re, doc)
    if (!lok || !rok) return false
    return compareFloats(l, cond.op, r)
}

private fun evalExpr(expr: Expr, doc: Map<String, Any?>): Pair<Double, Boolean> {
    return when (expr.kind) {
        ExprKind.LITERAL -> expr.value to true
        ExprKind.FIELD -> {
            val v = resolveField(expr.field, doc)
            val f = toFloat(v) ?: return 0.0 to false
            f to true
        }
        ExprKind.COUNT -> {
            val v = resolveField(expr.aggTarget, doc)
            when {
                v is List<*> -> v.size.toDouble() to true
                isNumber(v) -> (v as Number).toDouble() to true
                else -> 0.0 to false
            }
        }
        ExprKind.LEN -> {
            val v = resolveField(expr.field, doc)
            when {
                v is String -> v.length.toDouble() to true
                v is List<*> -> v.size.toDouble() to true
                v == null -> 0.0 to true
                else -> 0.0 to false
            }
        }
        ExprKind.BINARY -> {
            val l = expr.left ?: return 0.0 to false
            val r = expr.right ?: return 0.0 to false
            val (lv, lok) = evalExpr(l, doc)
            val (rv, rok) = evalExpr(r, doc)
            if (!lok || !rok) return 0.0 to false
            when (expr.op) {
                "+" -> (lv + rv) to true
                "-" -> (lv - rv) to true
                "*" -> (lv * rv) to true
                "/" -> if (rv == 0.0) 0.0 to false else (lv / rv) to true
                else -> 0.0 to false
            }
        }
    }
}

private fun evalAggregate(cond: Condition, doc: Map<String, Any?>): Boolean {
    val v = resolveField(cond.aggregateTarget, doc)
    val count: Int = when {
        v is List<*> -> v.size
        isNumber(v) -> (v as Number).toInt()
        else -> return false
    }
    val target = cond.value as? Int ?: return false
    return compareFloats(count.toDouble(), cond.op, target.toDouble())
}

private fun evalFieldCondition(cond: Condition, doc: Map<String, Any?>): Boolean {
    var v: Any? = resolveField(cond.field, doc)
    if (cond.transform.isNotEmpty()) {
        v = applyTransform(cond.transform, v)
    }

    return when (val op = cond.op) {
        "==" -> fmtV(v) == fmtV(cond.value)
        "!=" -> fmtV(v) != fmtV(cond.value)
        "<", ">", "<=", ">=" -> compareValues(v, op, cond.value)
        "in" -> {
            val lst = cond.value as? List<*> ?: return false
            val s = fmtV(v)
            lst.any { s == it }
        }
        "matches" -> {
            val pat = cond.value as? String ?: return false
            globMatch(pat, fmtV(v))
        }
        "matches_regex" -> {
            val pat = cond.value as? String ?: return false
            regexMatch(pat, fmtV(v))
        }
        "contains" -> evalContains(v, cond.value)
        "intersects" -> evalIntersects(v, cond.value)
        "is_subset" -> evalIsSubset(v, cond.value)
        else -> false
    }
}

private fun evalContains(v: Any?, target: Any?): Boolean {
    val targetStr = fmtV(target)
    if (v is List<*>) {
        return v.any { fmtV(it) == targetStr }
    }
    if (v is String) return v.contains(targetStr)
    return false
}

private fun evalIntersects(v: Any?, target: Any?): Boolean {
    if (target !is List<*>) return false
    val rhsSet = HashSet<String>()
    for (x in target) rhsSet.add(fmtV(x))
    if (v is List<*>) {
        return v.any { fmtV(it) in rhsSet }
    }
    return false
}

private fun evalIsSubset(v: Any?, target: Any?): Boolean {
    if (target !is List<*>) return false
    val rhsSet = HashSet<String>()
    for (x in target) rhsSet.add(fmtV(x))
    if (v is List<*>) {
        if (v.isEmpty()) return true
        return v.all { fmtV(it) in rhsSet }
    }
    return false
}

// ===========================================================================
// Trace / explain
// ===========================================================================

internal fun traceCondition(cond: Condition, doc: Map<String, Any?>, result: Boolean): ConditionTrace {
    val ct = ConditionTrace(
        expr = conditionExpr(cond),
        result = result,
        actual = resolveActual(cond, doc),
    )
    if (cond.type == ConditionType.OR) {
        for (sub in cond.orGroup) {
            val subResult = evalCondition(sub, doc)
            ct.children.add(traceCondition(sub, doc, subResult))
        }
    }
    return ct
}

private fun conditionExpr(cond: Condition): String {
    val prefix = if (cond.negated) "not " else ""
    return when (cond.type) {
        ConditionType.FIELD -> {
            val field = if (cond.transform.isNotEmpty()) "${cond.transform}(${cond.field})" else cond.field
            "$prefix$field ${cond.op} ${formatValue(cond.value)}"
        }
        ConditionType.AGGREGATE -> "${prefix}count(${cond.aggregateTarget}) ${cond.op} ${cond.value}"
        ConditionType.HAS -> "${prefix}has ${cond.field}"
        ConditionType.ANY -> {
            val p = cond.predicate
            if (p != null) "${prefix}any ${cond.listField} ${p.op} ${formatValue(p.value)}"
            else "${prefix}any ${cond.listField} <predicate>"
        }
        ConditionType.ALL -> {
            val p = cond.predicate
            if (p != null) "${prefix}all ${cond.listField} ${p.op} ${formatValue(p.value)}"
            else "${prefix}all ${cond.listField} <predicate>"
        }
        ConditionType.OR -> prefix + cond.orGroup.joinToString(" or ") { conditionExpr(it) }
        ConditionType.EXPR -> "$prefix${exprString(cond.leftExpr)} ${cond.op} ${exprString(cond.rightExpr)}"
    }
}

private fun exprString(expr: Expr?): String {
    if (expr == null) return "<nil>"
    return when (expr.kind) {
        ExprKind.FIELD -> expr.field
        ExprKind.LITERAL -> {
            val v = expr.value
            if (v == v.toLong().toDouble()) v.toLong().toString() else v.toString()
        }
        ExprKind.COUNT -> "count(${expr.aggTarget})"
        ExprKind.LEN -> "len(${expr.field})"
        ExprKind.BINARY -> "${exprString(expr.left)} ${expr.op} ${exprString(expr.right)}"
    }
}

private fun resolveActual(cond: Condition, doc: Map<String, Any?>): String {
    return when (cond.type) {
        ConditionType.FIELD -> formatActual(resolveField(cond.field, doc))
        ConditionType.AGGREGATE -> {
            val v = resolveField(cond.aggregateTarget, doc)
            when {
                v is List<*> -> v.size.toString()
                isNumber(v) -> (v as Number).toInt().toString()
                else -> "<nil>"
            }
        }
        ConditionType.HAS -> {
            val v = resolveField(cond.field, doc)
            if (v != null) "exists" else "<nil>"
        }
        ConditionType.ANY, ConditionType.ALL -> {
            val v = resolveField(cond.listField, doc)
            val items = toList(v) ?: return "<nil>"
            "[${items.size} items]"
        }
        ConditionType.EXPR -> {
            val le = cond.leftExpr
            val re = cond.rightExpr
            if (le != null && re != null) {
                val (lv, lok) = evalExpr(le, doc)
                val (rv, rok) = evalExpr(re, doc)
                if (lok && rok) "$lv vs $rv" else ""
            } else ""
        }
        ConditionType.OR -> ""
    }
}

private fun formatValue(v: Any?): String {
    if (v is String) return "\"$v\""
    if (v is List<*> && v.all { it is String }) {
        return "[" + v.joinToString(", ") { "\"$it\"" } + "]"
    }
    return fmtV(v)
}

private fun formatActual(v: Any?): String {
    if (v == null) return "<nil>"
    if (v is List<*>) {
        return if (v.size <= 5) "[" + v.joinToString(", ") { fmtV(it) } + "]"
        else "[${v.size} items]"
    }
    if (v is String) return "\"$v\""
    return fmtV(v)
}

// ===========================================================================
// Helpers
// ===========================================================================

private val regexCache: MutableMap<String, Pattern?> = HashMap()

private fun regexMatch(pattern: String, s: String): Boolean {
    val compiled = regexCache.getOrPut(pattern) {
        try {
            Pattern.compile(pattern)
        } catch (_: PatternSyntaxException) {
            null
        }
    } ?: return false
    return compiled.matcher(s).find()
}

private fun globMatch(pattern: String, s: String): Boolean {
    if (pattern == "*") return true
    val endsStar = pattern.endsWith("*")
    val startsStar = pattern.startsWith("*")
    if (endsStar && !startsStar) return s.startsWith(pattern.substring(0, pattern.length - 1))
    if (startsStar && !endsStar) return s.endsWith(pattern.substring(1))
    val star = pattern.indexOf('*')
    if (star >= 0) {
        val prefix = pattern.substring(0, star)
        val suffix = pattern.substring(star + 1)
        return s.startsWith(prefix) && s.endsWith(suffix)
    }
    return pattern == s
}

/** Resolve a dotted path against a document. Returns `null` if missing. */
fun resolveField(path: String, doc: Any?): Any? {
    if (doc == null) return null
    var current: Any? = doc
    for (part in path.split(".")) {
        if (current is Map<*, *>) {
            @Suppress("UNCHECKED_CAST")
            current = (current as Map<Any?, Any?>)[part]
        } else {
            return null
        }
    }
    return current
}

private fun toList(v: Any?): List<Any?>? {
    if (v is List<*>) {
        @Suppress("UNCHECKED_CAST")
        return v as List<Any?>
    }
    return null
}

private fun isNumber(v: Any?): Boolean {
    return v is Number && v !is Boolean // Boolean does not extend Number in Kotlin, but be explicit.
}

private fun toFloat(v: Any?): Double? {
    if (v is Boolean) return null
    if (v is Number) return v.toDouble()
    return null
}

private fun compareValues(a: Any?, op: String, b: Any?): Boolean {
    val af = toFloat(a) ?: return false
    val bf = toFloat(b) ?: return false
    return compareFloats(af, op, bf)
}

private fun compareFloats(a: Double, op: String, b: Double): Boolean {
    return when (op) {
        "<" -> a < b
        ">" -> a > b
        "<=" -> a <= b
        ">=" -> a >= b
        "==" -> a == b
        "!=" -> a != b
        else -> false
    }
}

private fun applyTransform(transform: String, v: Any?): Any? {
    return when (transform) {
        "lower" -> if (v is String) v.lowercase() else fmtV(v).lowercase()
        "upper" -> if (v is String) v.uppercase() else fmtV(v).uppercase()
        "len" -> when (v) {
            is String -> v.length
            is List<*> -> v.size
            null -> 0
            else -> 0
        }
        else -> v
    }
}

/**
 * Format a value the way Go's `fmt.Sprintf("%v", v)` would — lowercase
 * booleans, integers without a decimal point, and `<nil>` for null.
 */
fun fmtV(v: Any?): String {
    if (v == null) return "<nil>"
    if (v is Boolean) return if (v) "true" else "false"
    if (v is Double) {
        if (!v.isFinite()) return v.toString()
        val asLong = v.toLong()
        if (asLong.toDouble() == v) return asLong.toString()
        return v.toString()
    }
    if (v is Float) {
        val d = v.toDouble()
        val asLong = d.toLong()
        if (asLong.toDouble() == d) return asLong.toString()
        return d.toString()
    }
    if (v is Number) return v.toString() // Int, Long, etc. render as-is.
    if (v is String) return v
    if (v is List<*>) return "[" + v.joinToString(" ") { fmtV(it) } + "]"
    return v.toString()
}

// ===========================================================================
// Message interpolation
// ===========================================================================

private val INTERP_RE = Regex("\\{([^}]+)\\}")

/** Replace `{field.path}` and `{count(field.path)}` placeholders in a message. */
fun interpolateMessage(msg: String, doc: Map<String, Any?>): String {
    if (msg.isEmpty()) return "policy violation"
    return INTERP_RE.replace(msg) { match ->
        val expr = match.groupValues[1]
        if (expr.startsWith("count(") && expr.endsWith(")")) {
            val target = expr.substring(6, expr.length - 1)
            val v = resolveField(target, doc)
            when {
                v is List<*> -> v.size.toString()
                v is Number && v !is Boolean -> v.toLong().toString()
                else -> match.value
            }
        } else {
            val v = resolveField(expr, doc)
            if (v == null) match.value else fmtV(v)
        }
    }
}

// ===========================================================================
// Output formatting
// ===========================================================================

/** Plain-text rendering of a batch of results, paired with a pass/fail flag. */
data class FormattedResults(val text: String, val allPassed: Boolean)

/** Render [results] as a plain-text summary suitable for CLI output. */
fun formatResults(results: List<Result>): FormattedResults {
    var allPassed = true
    val lines = mutableListOf<String>()
    for (r in results) {
        if (r.passed) continue
        val prefix = if (r.kind == "warn") "WARN" else {
            allPassed = false
            "DENY"
        }
        var line = "$prefix: ${r.message} (${r.rule})"
        val meta = mutableListOf<String>()
        if (r.owner.isNotEmpty()) meta.add("owner: ${r.owner}")
        if (r.link.isNotEmpty()) meta.add("link: ${r.link}")
        if (meta.isNotEmpty()) line += " [" + meta.joinToString(", ") + "]"
        lines.add(line)
    }
    if (allPassed) {
        val passedCount = results.count { it.passed }
        lines.add("PASS: $passedCount rules evaluated, all passed")
    }
    val text = if (lines.isNotEmpty()) lines.joinToString("\n") + "\n" else ""
    return FormattedResults(text, allPassed)
}
