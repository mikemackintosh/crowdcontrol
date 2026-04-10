package io.github.mikemackintosh.crowdcontrol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

class ParserTest {

    @Test
    fun parsesSimpleForbidRule() {
        val policy = parse(
            """
            forbid "no-public" {
                resource.acl == "public-read"
                message "bucket is public"
            }
            """.trimIndent()
        )
        assertEquals(1, policy.rules.size)
        val rule = policy.rules[0]
        assertEquals("forbid", rule.kind)
        assertEquals("no-public", rule.name)
        assertEquals(1, rule.conditions.size)
        assertEquals("bucket is public", rule.message)
        val cond = rule.conditions[0]
        assertEquals(ConditionType.FIELD, cond.type)
        assertEquals("resource.acl", cond.field)
        assertEquals("==", cond.op)
        assertEquals("public-read", cond.value)
    }

    @Test
    fun parsesMetadataClauses() {
        val policy = parse(
            """
            forbid "rule" {
                description "a rule"
                owner "platform"
                link "https://example.com"
                user.role == "intern"
            }
            """.trimIndent()
        )
        val rule = policy.rules[0]
        assertEquals("a rule", rule.description)
        assertEquals("platform", rule.owner)
        assertEquals("https://example.com", rule.link)
    }

    @Test
    fun parsesUnlessClause() {
        val policy = parse(
            """
            forbid "rule" {
                user.role == "intern"
                unless user.approved == true
            }
            """.trimIndent()
        )
        val rule = policy.rules[0]
        assertEquals(1, rule.unlesses.size)
        assertEquals("user.approved", rule.unlesses[0].field)
    }

    @Test
    fun parsesCountAggregate() {
        val policy = parse(
            """
            forbid "rule" {
                count(plan.deletes) > 5
            }
            """.trimIndent()
        )
        val cond = policy.rules[0].conditions[0]
        assertEquals(ConditionType.AGGREGATE, cond.type)
        assertEquals("count", cond.aggregateFunc)
        assertEquals("plan.deletes", cond.aggregateTarget)
        assertEquals(">", cond.op)
        assertEquals(5, cond.value)
    }

    @Test
    fun parsesQuantifiers() {
        val policy = parse(
            """
            forbid "rule" {
                any plan.resources matches "prod-*"
            }
            """.trimIndent()
        )
        val cond = policy.rules[0].conditions[0]
        assertEquals(ConditionType.ANY, cond.type)
        assertEquals("plan.resources", cond.listField)
        val pred = cond.predicate
        assertNotNull(pred)
        assertEquals("matches", pred.op)
        assertEquals("prod-*", pred.value)
    }

    @Test
    fun parsesOrGroup() {
        val policy = parse(
            """
            forbid "rule" {
                user.role == "intern" or user.role == "contractor"
            }
            """.trimIndent()
        )
        val cond = policy.rules[0].conditions[0]
        assertEquals(ConditionType.OR, cond.type)
        assertEquals(2, cond.orGroup.size)
    }

    @Test
    fun parsesNegation() {
        val policy = parse(
            """
            forbid "rule" {
                not user.approved == true
            }
            """.trimIndent()
        )
        val cond = policy.rules[0].conditions[0]
        assertTrue(cond.negated)
    }

    @Test
    fun parsesArithmeticExpressions() {
        val policy = parse(
            """
            forbid "rule" {
                used + requested > capacity
            }
            """.trimIndent()
        )
        val cond = policy.rules[0].conditions[0]
        assertEquals(ConditionType.EXPR, cond.type)
        assertNotNull(cond.leftExpr)
        assertNotNull(cond.rightExpr)
    }

    @Test
    fun parsesInListOperator() {
        val policy = parse(
            """
            forbid "rule" {
                user.role in ["intern", "contractor"]
            }
            """.trimIndent()
        )
        val cond = policy.rules[0].conditions[0]
        assertEquals("in", cond.op)
        assertEquals(listOf("intern", "contractor"), cond.value)
    }

    @Test
    fun parsesHasCondition() {
        val policy = parse("""forbid "rule" { has user.email }""")
        val cond = policy.rules[0].conditions[0]
        assertEquals(ConditionType.HAS, cond.type)
        assertEquals("user.email", cond.field)
    }

    @Test
    fun parsesTransformCondition() {
        val policy = parse(
            """
            forbid "rule" {
                lower(user.name) == "root"
            }
            """.trimIndent()
        )
        val cond = policy.rules[0].conditions[0]
        assertEquals("lower", cond.transform)
        assertEquals("user.name", cond.field)
    }

    @Test
    fun rejectsMalformedRule() {
        assertFailsWith<ParseError> { parse("forbid { }") }
    }
}
