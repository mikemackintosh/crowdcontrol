/**
 * CrowdControl TypeScript SDK — runnable demo.
 *
 * Compile with `npx tsc`, then run with `node dist/examples/demo.js`.
 */

import {
  DEFAULT_DENY,
  fromSource,
  formatResults,
  validatePolicies,
  formatWarnings,
} from "../src/index.js";

const policy = `
permit "sre-can-deploy" {
  description "SRE team can always deploy to production"
  owner "security@example.com"
  user.team == "sre"
  resource.environment == "production"
  message "{user.name} is SRE — allowed"
}

forbid "no-interns-in-prod" {
  user.role == "intern"
  resource.environment == "production"
  message "{user.name} cannot touch production"
}

warn "large-blast-radius" {
  count(plan.deletes) > 5
  message "plan deletes {count(plan.deletes)} resources — consider splitting"
}
`;

const input = {
  user: { name: "ana", role: "intern", team: "backend" },
  resource: { environment: "production" },
  plan: { deletes: ["a", "b", "c", "d", "e", "f", "g"] },
};

const eng = fromSource([policy], { defaultEffect: DEFAULT_DENY });
const results = eng.evaluate(input);

process.stdout.write("Decisions:\n");
for (const r of results) {
  process.stdout.write(
    `  [${r.kind}] ${r.rule} passed=${r.passed}` +
      (r.message ? ` — ${r.message}` : "") +
      "\n",
  );
}

const { text } = formatResults(results);
process.stdout.write("\nSummary:\n" + text);

// Optional: schema validation demo.
const warnings = validatePolicies(eng.policies(), {
  fields: {
    "user.name": "string",
    "user.role": "string",
    "user.team": "string",
    "resource.environment": "string",
    "plan.deletes": "list",
  },
});
process.stdout.write("\nSchema warnings:\n" + (formatWarnings(warnings) || "  (none)\n"));
