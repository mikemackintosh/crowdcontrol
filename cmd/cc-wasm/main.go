// Command cc-wasm is the CrowdControl WASM shim. It exposes the
// parser and evaluator to JavaScript so the docs playground can run
// policies entirely client-side — no server round-trips, no sandboxing
// concerns, and the same engine the reference CLI uses.
//
// Build:
//
//	GOOS=js GOARCH=wasm go build -o docs/assets/wasm/cc.wasm ./cmd/cc-wasm
//
// Load from JavaScript (wasm_exec.js is shipped by Go and copied into
// docs/assets/wasm/):
//
//	const go = new Go();
//	const result = await WebAssembly.instantiateStreaming(
//	    fetch("assets/wasm/cc.wasm"), go.importObject);
//	go.run(result.instance);
//	// globals are now available:
//	const out = window.ccEvaluate(policySource, inputJSON, { explain: true });
//
// Exposed globals (attached to window / globalThis):
//
//	ccEvaluate(policy, inputJSON, options) -> { ok, decision, results, trace, elapsedUs, error }
//	ccParse(policy)                       -> { ok, ruleCount, rules, error }
//	ccVersion                             -> string
//
// All functions are synchronous and pure — no state persists across
// calls. Each invocation parses the policy fresh, which keeps the API
// simple and avoids lifetime bugs in a browser context.
//
//go:build js && wasm

package main

import (
	"encoding/json"
	"fmt"
	"syscall/js"
	"time"

	"github.com/mikemackintosh/crowdcontrol"
	"github.com/mikemackintosh/crowdcontrol/evaluator"
	"github.com/mikemackintosh/crowdcontrol/types"
)

func main() {
	js.Global().Set("ccVersion", crowdcontrol.Version)
	js.Global().Set("ccEvaluate", js.FuncOf(ccEvaluate))
	js.Global().Set("ccParse", js.FuncOf(ccParse))

	// Let the host know the module is ready. The playground awaits
	// this flag before enabling the Run button.
	js.Global().Set("ccReady", true)
	if cb := js.Global().Get("onCcReady"); cb.Type() == js.TypeFunction {
		cb.Invoke()
	}

	// Keep the Go runtime alive — syscall/js callbacks only work while
	// main is running.
	select {}
}

// ccEvaluate(policySource, inputJSON, options?) runs a single
// evaluation and returns a JS-friendly result object.
func ccEvaluate(this js.Value, args []js.Value) any {
	if len(args) < 2 {
		return jsError("ccEvaluate expects (policy, inputJSON, [options])")
	}
	policy := args[0].String()
	inputJSON := args[1].String()

	explain := false
	defaultEffect := types.DefaultAllow
	if len(args) >= 3 && args[2].Type() == js.TypeObject {
		if v := args[2].Get("explain"); v.Type() == js.TypeBoolean {
			explain = v.Bool()
		}
		if v := args[2].Get("defaultEffect"); v.Type() == js.TypeString {
			switch v.String() {
			case "deny":
				defaultEffect = types.DefaultDeny
			case "allow":
				defaultEffect = types.DefaultAllow
			}
		}
	}

	// Parse the input JSON.
	var input map[string]any
	if inputJSON != "" {
		if err := json.Unmarshal([]byte(inputJSON), &input); err != nil {
			return jsError("invalid input JSON: " + err.Error())
		}
	} else {
		input = map[string]any{}
	}

	// Build an engine from the source. We rebuild on every call —
	// the playground workload is single-digit evaluations per second
	// at most, and this keeps the API stateless.
	opts := []evaluator.Option{
		evaluator.WithDefaultEffect(defaultEffect),
	}
	if explain {
		opts = append(opts, evaluator.WithExplain(true))
	}

	eng, err := crowdcontrol.NewFromSource([]string{policy}, opts...)
	if err != nil {
		return jsError("parse error: " + err.Error())
	}

	start := time.Now()
	results := eng.Evaluate(input)
	elapsed := time.Since(start).Microseconds()

	// Collapse results to a single decision the same way cc serve does.
	decision := "allow"
	for _, r := range results {
		if !r.Passed {
			decision = "deny"
			break
		}
	}

	// Marshal results via our wire format so the browser gets
	// snake_case keys. Using json.Marshal + unmarshal into an
	// any keeps the type conversion minimal.
	payload := map[string]any{
		"ok":         true,
		"decision":   decision,
		"results":    resultsToAny(results),
		"elapsed_us": elapsed,
	}
	if explain {
		payload["trace"] = evaluator.FormatExplain(results)
	}
	return jsValueFromAny(payload)
}

// ccParse(policySource) returns rule metadata without evaluating.
// Useful for the playground to show "3 rules loaded" while the user
// is still typing.
func ccParse(this js.Value, args []js.Value) any {
	if len(args) < 1 {
		return jsError("ccParse expects (policy)")
	}
	source := args[0].String()
	policy, err := crowdcontrol.Parse(source)
	if err != nil {
		return jsError(err.Error())
	}

	rules := make([]any, 0, len(policy.Rules))
	for _, r := range policy.Rules {
		rules = append(rules, map[string]any{
			"name":        r.Name,
			"kind":        r.Kind,
			"description": r.Description,
			"owner":       r.Owner,
			"link":        r.Link,
		})
	}
	return jsValueFromAny(map[string]any{
		"ok":         true,
		"rule_count": len(policy.Rules),
		"rules":      rules,
	})
}

// ---------------------------------------------------------------------------
// JS-side marshaling helpers
// ---------------------------------------------------------------------------

func jsError(msg string) any {
	return jsValueFromAny(map[string]any{
		"ok":    false,
		"error": msg,
	})
}

// resultsToAny converts a []types.Result to a []map[string]any using
// the same snake_case wire shape cc serve uses. Kept deliberately
// duplicate-but-simple so this file doesn't depend on cmd/cc's
// internal types (which don't compile under js/wasm anyway because
// they import net/http).
func resultsToAny(results []types.Result) []any {
	out := make([]any, len(results))
	for i, r := range results {
		m := map[string]any{
			"rule":   r.Rule,
			"kind":   r.Kind,
			"passed": r.Passed,
		}
		if r.Message != "" {
			m["message"] = r.Message
		}
		if r.Description != "" {
			m["description"] = r.Description
		}
		if r.Owner != "" {
			m["owner"] = r.Owner
		}
		if r.Link != "" {
			m["link"] = r.Link
		}
		if r.Trace != nil {
			m["trace"] = traceToAny(r.Trace)
		}
		out[i] = m
	}
	return out
}

func traceToAny(t *types.RuleTrace) any {
	return map[string]any{
		"conditions":             conditionsToAny(t.Conditions),
		"unlesses":               conditionsToAny(t.Unlesses),
		"all_conditions_matched": t.AllConditionsMatched,
		"saved_by_unless":        t.SavedByUnless,
	}
}

func conditionsToAny(cs []types.ConditionTrace) []any {
	if len(cs) == 0 {
		return nil
	}
	out := make([]any, len(cs))
	for i, c := range cs {
		m := map[string]any{
			"expr":   c.Expr,
			"result": c.Result,
			"actual": c.Actual,
		}
		if len(c.Children) > 0 {
			m["children"] = conditionsToAny(c.Children)
		}
		out[i] = m
	}
	return out
}

// jsValueFromAny walks a Go value tree and produces a js.Value
// recursively. syscall/js's ValueOf handles scalars and one-level
// maps / slices but chokes on nested map[string]any, so we recurse.
func jsValueFromAny(v any) any {
	switch x := v.(type) {
	case nil:
		return js.Null()
	case bool, string, int, int64, float64:
		return x
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, vv := range x {
			out[k] = jsValueFromAny(vv)
		}
		return js.ValueOf(out)
	case []any:
		out := make([]any, len(x))
		for i, vv := range x {
			out[i] = jsValueFromAny(vv)
		}
		return js.ValueOf(out)
	default:
		// Unknown type — best effort via fmt. The playground should
		// never hit this path with the data we pass through.
		return fmt.Sprintf("%v", x)
	}
}
