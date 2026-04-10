/*
 * Top-level public API for the CrowdControl Kotlin SDK.
 *
 * Example (Kotlin):
 *
 *   val eng = fromSource(listOf("""
 *       forbid "no-interns-in-prod" {
 *           user.role == "intern"
 *           resource.environment == "production"
 *           message "{user.name} cannot touch production"
 *       }
 *   """))
 *   val results = eng.evaluate(mapOf(
 *       "user" to mapOf("name" to "alex", "role" to "intern"),
 *       "resource" to mapOf("environment" to "production"),
 *   ))
 *
 * Example (Java):
 *
 *   Engine eng = Engine.fromSource(List.of(policySource));
 *   List<Result> results = eng.evaluate(input);
 */
@file:JvmName("CrowdControl")

package io.github.mikemackintosh.crowdcontrol

/** Package version. */
const val VERSION: String = "0.1.0"

/** Create an Engine from in-memory policy source strings. */
@JvmOverloads
fun fromSource(
    sources: List<String>,
    defaultEffect: DefaultEffect = DefaultEffect.ALLOW,
    explain: Boolean = false,
): Engine = Engine.fromSource(sources, defaultEffect, explain)

/** Load every `*.cc` file from each of the given directories. */
@JvmOverloads
fun fromDirectory(
    dirs: List<String>,
    defaultEffect: DefaultEffect = DefaultEffect.ALLOW,
    explain: Boolean = false,
): Engine = Engine.fromDirectory(dirs, defaultEffect, explain)
