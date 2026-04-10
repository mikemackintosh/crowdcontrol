package io.github.mikemackintosh.crowdcontrol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class EvaluatorTest {

    @Test
    fun forbidFiresWhenConditionMatches() {
        val eng = fromSource(
            listOf(
                """
                forbid "no-public" {
                    resource.acl == "public-read"
                    message "bucket is public"
                }
                """.trimIndent()
            )
        )
        val results = eng.evaluate(mapOf("resource" to mapOf("acl" to "public-read")))
        assertEquals(1, results.size)
        assertEquals("no-public", results[0].rule)
        assertFalse(results[0].passed)
        assertTrue(results[0].message.contains("bucket is public"))
    }

    @Test
    fun forbidDoesNotFireWhenMismatch() {
        val eng = fromSource(
            listOf(
                """
                forbid "no-public" {
                    resource.acl == "public-read"
                    message "bucket is public"
                }
                """.trimIndent()
            )
        )
        val results = eng.evaluate(mapOf("resource" to mapOf("acl" to "private")))
        assertTrue(results[0].passed)
    }

    @Test
    fun permitFires() {
        val eng = fromSource(
            listOf(
                """
                permit "admin-ok" {
                    user.role == "admin"
                    message "approved"
                }
                """.trimIndent()
            )
        )
        val results = eng.evaluate(mapOf("user" to mapOf("role" to "admin")))
        assertTrue(results[0].passed)
        assertEquals("approved", results[0].message)
    }

    @Test
    fun unlessSavesRule() {
        val eng = fromSource(
            listOf(
                """
                forbid "rule" {
                    user.role == "intern"
                    unless user.approved == true
                    message "intern"
                }
                """.trimIndent()
            )
        )
        val results = eng.evaluate(mapOf("user" to mapOf("role" to "intern", "approved" to true)))
        assertTrue(results[0].passed)
    }

    @Test
    fun numericComparisonsOnlyWorkOnNumbers() {
        val eng = fromSource(listOf("""forbid "r" { user.age < 18 }"""))
        val r1 = eng.evaluate(mapOf("user" to mapOf("age" to 16)))
        assertFalse(r1[0].passed)
        val r2 = eng.evaluate(mapOf("user" to mapOf("age" to 21)))
        assertTrue(r2[0].passed)
        // String values should not coerce: "16" < 18 is false.
        val r3 = eng.evaluate(mapOf("user" to mapOf("age" to "16")))
        assertTrue(r3[0].passed)
    }

    @Test
    fun containsOnListAndString() {
        val eng = fromSource(
            listOf(
                """
                forbid "r" {
                    labels contains "danger"
                }
                """.trimIndent()
            )
        )
        val hit = eng.evaluate(mapOf("labels" to listOf("ok", "danger", "more")))
        assertFalse(hit[0].passed)
        val miss = eng.evaluate(mapOf("labels" to listOf("ok")))
        assertTrue(miss[0].passed)
    }

    @Test
    fun anyQuantifier() {
        val eng = fromSource(
            listOf(
                """
                forbid "r" {
                    any resources matches "prod-*"
                }
                """.trimIndent()
            )
        )
        val hit = eng.evaluate(mapOf("resources" to listOf("dev-db", "prod-api")))
        assertFalse(hit[0].passed)
        val miss = eng.evaluate(mapOf("resources" to listOf("dev-db")))
        assertTrue(miss[0].passed)
    }

    @Test
    fun allQuantifierEmptyListIsTrue() {
        val eng = fromSource(
            listOf(
                """
                forbid "r" {
                    all items == "bad"
                }
                """.trimIndent()
            )
        )
        val results = eng.evaluate(mapOf("items" to emptyList<String>()))
        assertFalse(results[0].passed) // all vacuously true -> rule fires
    }

    @Test
    fun countAggregate() {
        val eng = fromSource(listOf("""forbid "r" { count(items) > 2 }"""))
        val hit = eng.evaluate(mapOf("items" to listOf(1, 2, 3, 4)))
        assertFalse(hit[0].passed)
        val miss = eng.evaluate(mapOf("items" to listOf(1)))
        assertTrue(miss[0].passed)
    }

    @Test
    fun arithmeticExpr() {
        val eng = fromSource(listOf("""forbid "r" { used + requested > capacity }"""))
        val hit = eng.evaluate(mapOf("used" to 80, "requested" to 30, "capacity" to 100))
        assertFalse(hit[0].passed)
        val miss = eng.evaluate(mapOf("used" to 10, "requested" to 10, "capacity" to 100))
        assertTrue(miss[0].passed)
    }

    @Test
    fun messageInterpolation() {
        val eng = fromSource(
            listOf(
                """
                forbid "r" {
                    user.role == "intern"
                    message "user {user.name} is an intern"
                }
                """.trimIndent()
            )
        )
        val results = eng.evaluate(mapOf("user" to mapOf("name" to "alex", "role" to "intern")))
        assertEquals("user alex is an intern", results[0].message)
    }

    @Test
    fun defaultDenyAppendsImplicitResult() {
        val eng = fromSource(
            listOf(
                """
                permit "specific" {
                    user.role == "admin"
                    message "approved"
                }
                """.trimIndent()
            ),
            defaultEffect = DefaultEffect.DENY,
        )
        val results = eng.evaluate(mapOf("user" to mapOf("role" to "developer")))
        assertEquals(2, results.size)
        assertEquals("(default-deny)", results[1].rule)
        assertFalse(results[1].passed)
    }

    @Test
    fun negation() {
        val eng = fromSource(listOf("""forbid "r" { not user.approved == true }"""))
        val denied = eng.evaluate(mapOf("user" to mapOf("approved" to false)))
        assertFalse(denied[0].passed)
        val ok = eng.evaluate(mapOf("user" to mapOf("approved" to true)))
        assertTrue(ok[0].passed)
    }

    @Test
    fun orGroup() {
        val eng = fromSource(
            listOf(
                """
                forbid "r" {
                    user.role == "intern" or user.role == "contractor"
                }
                """.trimIndent()
            )
        )
        val a = eng.evaluate(mapOf("user" to mapOf("role" to "intern")))
        assertFalse(a[0].passed)
        val b = eng.evaluate(mapOf("user" to mapOf("role" to "contractor")))
        assertFalse(b[0].passed)
        val c = eng.evaluate(mapOf("user" to mapOf("role" to "admin")))
        assertTrue(c[0].passed)
    }

    @Test
    fun lowerTransform() {
        val eng = fromSource(listOf("""forbid "r" { lower(user.name) == "root" }"""))
        val hit = eng.evaluate(mapOf("user" to mapOf("name" to "ROOT")))
        assertFalse(hit[0].passed)
    }

    @Test
    fun resolveFieldReturnsNullOnMissing() {
        val doc = mapOf<String, Any?>("a" to mapOf("b" to 1))
        assertEquals(1, resolveField("a.b", doc))
        assertEquals(null, resolveField("a.c", doc))
        assertEquals(null, resolveField("x.y", doc))
    }

    @Test
    fun fmtVMatchesGoSemantics() {
        assertEquals("<nil>", fmtV(null))
        assertEquals("true", fmtV(true))
        assertEquals("false", fmtV(false))
        assertEquals("42", fmtV(42))
        assertEquals("42", fmtV(42.0))
        assertEquals("3.14", fmtV(3.14))
        assertEquals("hello", fmtV("hello"))
    }
}
