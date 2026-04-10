/**
 * CrowdControl policy language — TypeScript / Node.js SDK.
 *
 * Zero runtime dependencies. Pure TypeScript port of the Go reference
 * implementation at https://github.com/mikemackintosh/crowdcontrol.
 *
 * Quick start:
 *
 * ```ts
 * import { fromSource } from "crowdcontrol";
 *
 * const eng = fromSource([`
 *   forbid "no-interns-in-prod" {
 *     user.role == "intern"
 *     resource.environment == "production"
 *     message "{user.name} cannot touch production"
 *   }
 * `]);
 *
 * const results = eng.evaluate({
 *   user: { name: "alex", role: "intern" },
 *   resource: { environment: "production" },
 * });
 *
 * for (const r of results) {
 *   console.log(r.rule, r.kind, r.passed, r.message);
 * }
 * ```
 */

export { parse, ParseError } from "./parser.js";
export {
  Evaluator,
  fromSource,
  fromDirectory,
  formatResults,
  resolveField,
  interpolateMessage,
  fmtV,
  POLICY_EXT,
} from "./evaluator.js";
export type { EvaluatorOptions, FormatOutput } from "./evaluator.js";
export { validatePolicies, formatWarnings } from "./validate.js";
export * from "./types.js";

export const VERSION = "0.1.0";
