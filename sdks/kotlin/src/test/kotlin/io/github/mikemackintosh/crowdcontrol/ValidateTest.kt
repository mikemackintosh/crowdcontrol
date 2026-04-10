package io.github.mikemackintosh.crowdcontrol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ValidateTest {

    @Test
    fun flagsUnknownField() {
        val p = parse("""forbid "r" { user.unknown == "x" }""")
        val schema = Schema(mapOf("user.name" to FieldType.STRING))
        val warnings = validatePolicies(listOf(p), schema)
        assertEquals(1, warnings.size)
        assertTrue(warnings[0].message.contains("not found"))
    }

    @Test
    fun allowsKnownField() {
        val p = parse("""forbid "r" { user.name == "alex" }""")
        val schema = Schema(mapOf("user.name" to FieldType.STRING))
        val warnings = validatePolicies(listOf(p), schema)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun flagsNumericOpOnString() {
        val p = parse("""forbid "r" { user.name < 5 }""")
        val schema = Schema(mapOf("user.name" to FieldType.STRING))
        val warnings = validatePolicies(listOf(p), schema)
        assertEquals(1, warnings.size)
        assertTrue(warnings[0].message.contains("<"))
    }

    @Test
    fun flagsQuantifierOnNonList() {
        val p = parse("""forbid "r" { any user.name == "x" }""")
        val schema = Schema(mapOf("user.name" to FieldType.STRING))
        val warnings = validatePolicies(listOf(p), schema)
        assertTrue(warnings.any { it.message.contains("expected list") })
    }

    @Test
    fun flagsCountOnWrongType() {
        val p = parse("""forbid "r" { count(user.name) > 1 }""")
        val schema = Schema(mapOf("user.name" to FieldType.STRING))
        val warnings = validatePolicies(listOf(p), schema)
        assertTrue(warnings.any { it.message.contains("expected list or number") })
    }

    @Test
    fun flagsUnknownInterpolation() {
        val p = parse(
            """
            forbid "r" {
                user.role == "intern"
                message "bad: {user.nope}"
            }
            """.trimIndent()
        )
        val schema = Schema(mapOf("user.role" to FieldType.STRING))
        val warnings = validatePolicies(listOf(p), schema)
        assertTrue(warnings.any { it.field == "user.nope" })
    }

    @Test
    fun mapTypeAllowsAnySubpath() {
        val p = parse("""forbid "r" { user.profile.country == "US" }""")
        val schema = Schema(mapOf("user.profile" to FieldType.MAP))
        val warnings = validatePolicies(listOf(p), schema)
        assertTrue(warnings.isEmpty())
    }

    @Test
    fun formatWarningsRendersEachOnALine() {
        val warnings = listOf(
            SchemaWarning(rule = "r1", field = "x", message = "bad x"),
            SchemaWarning(rule = "r2", field = "y", message = "bad y"),
        )
        val text = formatWarnings(warnings)
        assertTrue(text.contains("r1: bad x"))
        assertTrue(text.contains("r2: bad y"))
    }
}
