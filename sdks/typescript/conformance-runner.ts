#!/usr/bin/env node
/**
 * TypeScript SDK conformance runner.
 *
 * Reads every case file in the shared conformance suite
 * (`../../conformance/suite/*.json`), runs it through the TypeScript
 * implementation, and verifies that the results match the expected
 * decisions. Exits 0 on full pass, 1 on any failure.
 */

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";

import { ParseError, fromSource } from "./src/index.js";
import type { DefaultEffect, Result } from "./src/index.js";

interface ExpectedDecision {
  rule: string;
  kind: string;
  passed: boolean;
  message_exact?: string;
  message_contains?: string;
}

interface ConformanceCase {
  name?: string;
  description?: string;
  policy: string;
  input?: Record<string, unknown>;
  default_effect?: string;
  expect?: {
    decisions?: ExpectedDecision[];
  };
}

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// dist/conformance-runner.js lives in dist/, so ../.. takes us to sdks/typescript/,
// and then ../../conformance/suite is the shared suite.
const DEFAULT_SUITE = path.resolve(__dirname, "..", "..", "..", "conformance", "suite");

function loadCase(p: string): ConformanceCase {
  const raw = fs.readFileSync(p, "utf-8");
  return JSON.parse(raw) as ConformanceCase;
}

function runCase(cse: ConformanceCase): { ok: boolean; msg: string } {
  const defaultEffect = (cse.default_effect || "allow") as string;
  if (defaultEffect !== "allow" && defaultEffect !== "deny") {
    return { ok: false, msg: `unknown default_effect ${JSON.stringify(defaultEffect)}` };
  }

  let results: Result[];
  try {
    const eng = fromSource([cse.policy], { defaultEffect: defaultEffect as DefaultEffect });
    results = eng.evaluate(cse.input ?? {});
  } catch (e) {
    if (e instanceof ParseError) return { ok: false, msg: `parse error: ${e.message}` };
    throw e;
  }

  const expected = cse.expect?.decisions ?? [];
  if (results.length !== expected.length) {
    const summary = results
      .map((r) => `[${r.rule}/${r.kind} passed=${r.passed}]`)
      .join(" ");
    return {
      ok: false,
      msg: `expected ${expected.length} decisions, got ${results.length} (results: ${summary})`,
    };
  }

  for (let i = 0; i < expected.length; i++) {
    const want = expected[i]!;
    const got = results[i]!;
    if (got.rule !== want.rule) {
      return {
        ok: false,
        msg: `decision[${i}]: rule = ${JSON.stringify(got.rule)}, want ${JSON.stringify(want.rule)}`,
      };
    }
    if (got.kind !== want.kind) {
      return {
        ok: false,
        msg: `decision[${i}] (${got.rule}): kind = ${JSON.stringify(got.kind)}, want ${JSON.stringify(want.kind)}`,
      };
    }
    if (got.passed !== want.passed) {
      return {
        ok: false,
        msg: `decision[${i}] (${got.rule}): passed = ${got.passed}, want ${want.passed}`,
      };
    }
    if (want.message_exact !== undefined && want.message_exact !== "" && got.message !== want.message_exact) {
      return {
        ok: false,
        msg: `decision[${i}] (${got.rule}): message = ${JSON.stringify(got.message)}, want exact ${JSON.stringify(want.message_exact)}`,
      };
    }
    if (
      want.message_contains !== undefined &&
      want.message_contains !== "" &&
      !got.message.includes(want.message_contains)
    ) {
      return {
        ok: false,
        msg: `decision[${i}] (${got.rule}): message = ${JSON.stringify(got.message)}, want contains ${JSON.stringify(want.message_contains)}`,
      };
    }
  }

  return { ok: true, msg: "" };
}

function main(): number {
  const args = process.argv.slice(2);
  let suite = DEFAULT_SUITE;
  let verbose = false;
  let filter = "";

  for (let i = 0; i < args.length; i++) {
    const a = args[i]!;
    if (a === "-v" || a === "--verbose") {
      verbose = true;
    } else if (a === "-f" || a === "--filter") {
      filter = args[++i] ?? "";
    } else {
      suite = a;
    }
  }

  if (!fs.existsSync(suite) || !fs.statSync(suite).isDirectory()) {
    process.stderr.write(`suite dir not found: ${suite}\n`);
    return 2;
  }

  const files = fs
    .readdirSync(suite)
    .filter((f) => f.endsWith(".json"))
    .sort()
    .map((f) => path.join(suite, f));

  if (files.length === 0) {
    process.stderr.write(`no conformance cases in ${suite}\n`);
    return 2;
  }

  let passed = 0;
  let failed = 0;

  for (const p of files) {
    let cse: ConformanceCase;
    try {
      cse = loadCase(p);
    } catch (e) {
      const err = e instanceof Error ? e.message : String(e);
      process.stdout.write(`FAIL: ${path.basename(p)} — load error: ${err}\n`);
      failed++;
      continue;
    }

    const name = cse.name ?? path.basename(p, ".json");
    if (filter && !name.includes(filter)) continue;

    const { ok, msg } = runCase(cse);
    if (ok) {
      passed++;
      if (verbose) process.stdout.write(`PASS: ${name}\n`);
    } else {
      failed++;
      process.stdout.write(`FAIL: ${name} — ${msg}\n`);
    }
  }

  process.stdout.write("\n");
  process.stdout.write(`${passed} passed, ${failed} failed\n`);
  return failed > 0 ? 1 : 0;
}

process.exit(main());
