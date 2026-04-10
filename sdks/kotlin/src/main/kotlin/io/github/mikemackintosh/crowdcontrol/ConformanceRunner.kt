// Kotlin SDK conformance runner.
//
// Reads every case file in the shared conformance suite
// (../../conformance/suite/ *.json relative to this SDK) and runs it
// through the Kotlin implementation, verifying that results match the
// expected decisions. Exits 0 on full pass, 1 on any failure, 2 on
// argument / IO errors.
@file:JvmName("ConformanceRunner")

package io.github.mikemackintosh.crowdcontrol

import java.io.File
import kotlin.system.exitProcess

private data class ExpectedDecision(
    val rule: String,
    val kind: String,
    val passed: Boolean,
    val messageExact: String?,
    val messageContains: String?,
)

private data class ConformanceCase(
    val name: String?,
    val description: String?,
    val policy: String,
    val input: Map<String, Any?>,
    val defaultEffect: String,
    val expected: List<ExpectedDecision>,
)

private fun loadCase(path: File): ConformanceCase {
    val raw = path.readText(Charsets.UTF_8)
    val parsed = parseJson(raw)
        ?: throw JsonParseError("case file is null")
    @Suppress("UNCHECKED_CAST")
    val root = parsed as? Map<String, Any?>
        ?: throw JsonParseError("case root is not an object")

    val policy = root["policy"] as? String
        ?: throw JsonParseError("case missing 'policy'")
    @Suppress("UNCHECKED_CAST")
    val input = (root["input"] as? Map<String, Any?>) ?: emptyMap()
    val defaultEffect = (root["default_effect"] as? String) ?: "allow"

    val expect = root["expect"] as? Map<*, *>
    val decisions = expect?.get("decisions") as? List<*> ?: emptyList<Any?>()
    val expected = decisions.map { d ->
        @Suppress("UNCHECKED_CAST")
        val m = d as Map<String, Any?>
        ExpectedDecision(
            rule = m["rule"] as? String ?: "",
            kind = m["kind"] as? String ?: "",
            passed = m["passed"] as? Boolean ?: true,
            messageExact = m["message_exact"] as? String,
            messageContains = m["message_contains"] as? String,
        )
    }

    return ConformanceCase(
        name = root["name"] as? String,
        description = root["description"] as? String,
        policy = policy,
        input = input,
        defaultEffect = defaultEffect,
        expected = expected,
    )
}

private data class CaseOutcome(val ok: Boolean, val msg: String)

private fun runCase(cse: ConformanceCase): CaseOutcome {
    val effect = try {
        DefaultEffect.fromString(cse.defaultEffect)
    } catch (e: IllegalArgumentException) {
        return CaseOutcome(false, "unknown default_effect \"${cse.defaultEffect}\"")
    }

    val results: List<Result> = try {
        val eng = fromSource(listOf(cse.policy), defaultEffect = effect)
        eng.evaluate(cse.input)
    } catch (e: ParseError) {
        return CaseOutcome(false, "parse error: ${e.message}")
    }

    val expected = cse.expected
    if (results.size != expected.size) {
        val summary = results.joinToString(" ") { "[${it.rule}/${it.kind} passed=${it.passed}]" }
        return CaseOutcome(false, "expected ${expected.size} decisions, got ${results.size} (results: $summary)")
    }

    for (i in expected.indices) {
        val want = expected[i]
        val got = results[i]
        if (got.rule != want.rule) {
            return CaseOutcome(false, "decision[$i]: rule = \"${got.rule}\", want \"${want.rule}\"")
        }
        if (got.kind != want.kind) {
            return CaseOutcome(false, "decision[$i] (${got.rule}): kind = \"${got.kind}\", want \"${want.kind}\"")
        }
        if (got.passed != want.passed) {
            return CaseOutcome(false, "decision[$i] (${got.rule}): passed = ${got.passed}, want ${want.passed}")
        }
        val exact = want.messageExact
        if (!exact.isNullOrEmpty() && got.message != exact) {
            return CaseOutcome(false, "decision[$i] (${got.rule}): message = \"${got.message}\", want exact \"$exact\"")
        }
        val contains = want.messageContains
        if (!contains.isNullOrEmpty() && !got.message.contains(contains)) {
            return CaseOutcome(false, "decision[$i] (${got.rule}): message = \"${got.message}\", want contains \"$contains\"")
        }
    }

    return CaseOutcome(true, "")
}

private fun defaultSuiteDir(): File {
    // src/main/kotlin/io/github/mikemackintosh/crowdcontrol/ConformanceRunner.kt lives
    // inside sdks/kotlin. The suite is at ../../conformance/suite (from sdks/kotlin).
    // At runtime we are launched with cwd = sdks/kotlin (typical gradle/bash script
    // invocation), so relative path is fine. Also fall back to walking up.
    val cwd = File(".").absoluteFile.canonicalFile
    val candidates = listOf(
        File(cwd, "../../conformance/suite"),
        File(cwd, "../conformance/suite"),
        File(cwd, "conformance/suite"),
    )
    for (c in candidates) {
        if (c.isDirectory) return c.canonicalFile
    }
    return candidates[0].canonicalFile
}

fun main(args: Array<String>) {
    var suiteDir: File? = null
    var verbose = false
    var filter = ""

    var i = 0
    while (i < args.size) {
        val a = args[i]
        when (a) {
            "-v", "--verbose" -> verbose = true
            "-f", "--filter" -> {
                i += 1
                if (i < args.size) filter = args[i]
            }
            else -> suiteDir = File(a)
        }
        i += 1
    }

    val suite = suiteDir ?: defaultSuiteDir()

    if (!suite.isDirectory) {
        System.err.println("suite dir not found: ${suite.path}")
        exitProcess(2)
    }

    val files = (suite.listFiles() ?: emptyArray())
        .filter { it.isFile && it.name.endsWith(".json") }
        .sortedBy { it.name }

    if (files.isEmpty()) {
        System.err.println("no conformance cases in ${suite.path}")
        exitProcess(2)
    }

    var passed = 0
    var failed = 0

    for (f in files) {
        val cse: ConformanceCase = try {
            loadCase(f)
        } catch (e: Exception) {
            println("FAIL: ${f.name} — load error: ${e.message}")
            failed += 1
            continue
        }

        val caseName = cse.name ?: f.nameWithoutExtension
        if (filter.isNotEmpty() && !caseName.contains(filter)) continue

        val outcome = runCase(cse)
        if (outcome.ok) {
            passed += 1
            if (verbose) println("PASS: $caseName")
        } else {
            failed += 1
            println("FAIL: $caseName — ${outcome.msg}")
        }
    }

    println()
    println("$passed passed, $failed failed")
    exitProcess(if (failed > 0) 1 else 0)
}
