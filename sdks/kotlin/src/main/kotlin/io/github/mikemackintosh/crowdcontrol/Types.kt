/*
 * AST, Schema, and Result types for CrowdControl.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/types/types.go.
 *
 * The AST intentionally uses mutable data classes (not sealed classes) to
 * mirror the Go reference struct exactly, so that the parser can build a
 * Condition incrementally (field, op, value, transform, ...). Sealed types
 * would force redundant copying at every step and would diverge from the
 * other ports for no readability gain.
 */
package io.github.mikemackintosh.crowdcontrol

/** ConditionType identifies the kind of condition. */
enum class ConditionType {
    FIELD,
    AGGREGATE,
    OR,
    ANY,
    ALL,
    HAS,
    EXPR,
}

/** ExprKind identifies the type of arithmetic expression node. */
enum class ExprKind {
    FIELD,
    LITERAL,
    COUNT,
    LEN,
    BINARY,
}

/** DefaultEffect controls what happens when no rule matches a document. */
enum class DefaultEffect(val wire: String) {
    ALLOW("allow"),
    DENY("deny");

    companion object {
        @JvmStatic
        fun fromString(s: String): DefaultEffect = when (s.lowercase()) {
            "allow" -> ALLOW
            "deny" -> DENY
            else -> throw IllegalArgumentException("unknown default_effect: $s")
        }
    }
}

/** Expr represents a numeric expression (field, count, literal, or binary op). */
class Expr(
    @JvmField var kind: ExprKind = ExprKind.LITERAL,
    @JvmField var field: String = "",
    @JvmField var value: Double = 0.0,
    @JvmField var aggTarget: String = "",
    @JvmField var transform: String = "",
    @JvmField var op: String = "",
    @JvmField var left: Expr? = null,
    @JvmField var right: Expr? = null,
)

/**
 * Condition is a single evaluable clause. Mutable, built up by the parser.
 *
 * Field usage depends on [type]:
 * - FIELD: [field], [op], [value], optional [transform]
 * - AGGREGATE: [aggregateFunc]="count", [aggregateTarget], [op], [value] (Int)
 * - OR: [orGroup]
 * - ANY / ALL: [quantifier], [listField], [predicate]
 * - HAS: [field]
 * - EXPR: [leftExpr], [op], [rightExpr]
 */
class Condition(
    @JvmField var type: ConditionType = ConditionType.FIELD,
    @JvmField var negated: Boolean = false,
    @JvmField var field: String = "",
    @JvmField var op: String = "",
    @JvmField var value: Any? = null,
    @JvmField var transform: String = "",
    @JvmField var aggregateFunc: String = "",
    @JvmField var aggregateTarget: String = "",
    @JvmField var orGroup: MutableList<Condition> = mutableListOf(),
    @JvmField var quantifier: String = "",
    @JvmField var listField: String = "",
    @JvmField var predicate: Condition? = null,
    @JvmField var leftExpr: Expr? = null,
    @JvmField var rightExpr: Expr? = null,
)

/** Rule is a single forbid, warn, or permit block. */
class Rule(
    @JvmField var kind: String = "",
    @JvmField var name: String = "",
    @JvmField val conditions: MutableList<Condition> = mutableListOf(),
    @JvmField val unlesses: MutableList<Condition> = mutableListOf(),
    @JvmField var message: String = "",
    @JvmField var description: String = "",
    @JvmField var owner: String = "",
    @JvmField var link: String = "",
)

/** Policy represents a parsed CrowdControl policy file containing multiple rules. */
class Policy(
    @JvmField val rules: MutableList<Rule> = mutableListOf(),
)

/** ConditionTrace records the evaluation of a single condition. */
class ConditionTrace(
    @JvmField var expr: String = "",
    @JvmField var result: Boolean = false,
    @JvmField var actual: String = "",
    @JvmField val children: MutableList<ConditionTrace> = mutableListOf(),
)

/** RuleTrace captures the evaluation trace for a single rule. */
class RuleTrace(
    @JvmField val conditions: MutableList<ConditionTrace> = mutableListOf(),
    @JvmField val unlesses: MutableList<ConditionTrace> = mutableListOf(),
    @JvmField var allConditionsMatched: Boolean = false,
    @JvmField var savedByUnless: Boolean = false,
)

/** Result is the outcome of evaluating a single rule against a document. */
data class Result(
    val rule: String = "",
    val kind: String = "",
    val passed: Boolean = true,
    val message: String = "",
    val description: String = "",
    val owner: String = "",
    val link: String = "",
    val trace: RuleTrace? = null,
)

// ---- Schema ---------------------------------------------------------------

/** FieldType describes the expected type of a field in a schema. */
object FieldType {
    const val STRING = "string"
    const val NUMBER = "number"
    const val BOOL = "bool"
    const val LIST = "list"
    const val MAP = "map"
    const val ANY = "any"
}

/** Schema defines the expected shape of an input document for static validation. */
data class Schema(
    val fields: Map<String, String> = emptyMap(),
)

/** SchemaWarning is a non-fatal issue found during schema validation. */
data class SchemaWarning(
    val rule: String = "",
    val field: String = "",
    val message: String = "",
)
