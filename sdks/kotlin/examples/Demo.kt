/*
 * Runnable CrowdControl demo.
 *
 * Builds a small Engine from an in-memory policy and evaluates it
 * against two documents — one that should be denied, one that should
 * pass. Intended as a sanity check and as documentation by example.
 */
@file:JvmName("Demo")

package io.github.mikemackintosh.crowdcontrol

fun main() {
    val policySrc = """
        forbid "no-interns-in-prod" {
            description "interns should never touch production"
            owner "platform-security"
            user.role == "intern"
            resource.environment == "production"
            message "{user.name} cannot touch production"
        }

        warn "large-deletes" {
            count(plan.deletes) > 5
            message "large deletes: {count(plan.deletes)} resources"
        }

        permit "admin-override" {
            user.role == "admin"
            message "admin approved"
        }
    """.trimIndent()

    val engine = fromSource(listOf(policySrc))

    println("=== Denied case ===")
    val denied = engine.evaluate(
        mapOf(
            "user" to mapOf("name" to "alex", "role" to "intern"),
            "resource" to mapOf("environment" to "production"),
            "plan" to mapOf("deletes" to listOf("a", "b", "c", "d", "e", "f", "g")),
        )
    )
    print(formatResults(denied).text)

    println()
    println("=== Permitted case ===")
    val permitted = engine.evaluate(
        mapOf(
            "user" to mapOf("name" to "sam", "role" to "admin"),
            "resource" to mapOf("environment" to "production"),
            "plan" to mapOf("deletes" to emptyList<String>()),
        )
    )
    print(formatResults(permitted).text)
}
