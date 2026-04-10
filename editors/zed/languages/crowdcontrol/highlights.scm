; Zed-local copy of the CrowdControl highlight queries.
;
; Zed looks up highlights in the language directory first, so we
; keep this file in sync with the canonical version in the grammar
; repo at tree-sitter-crowdcontrol/queries/highlights.scm. They
; should be identical — this duplicate exists because Zed's
; extension loader needs it inside the language folder.

; --- rule kinds are the hero keyword: forbid / warn / permit ---
(rule_kind) @keyword.control

; --- control flow / condition operators ---
[
  "unless"
  "not"
  "or"
  "has"
  "any"
  "all"
  "in"
] @keyword.operator

; --- comparison and set operators ---
(cmp_op) @operator

[
  "matches"
  "matches_regex"
  "contains"
  "intersects"
  "is_subset"
] @keyword.operator

; --- metadata field names inside a rule body ---
(metadata_clause
  key: _ @property)
"message" @property

; --- built-in functions: count / len / lower / upper ---
(call_expression
  function: _ @function.builtin)

; --- quantifier heads (any / all) have their own highlight field ---
(quantifier_condition
  quantifier: _ @keyword.operator)

; --- literals ---
(string)  @string
(number)  @number
(boolean) @boolean

; --- comments ---
(comment) @comment

; --- field paths ---
(field_path
  (identifier) @variable)

; --- punctuation ---
[ "{" "}" "[" "]" "(" ")" ] @punctuation.bracket
[ "," "." ] @punctuation.delimiter

; --- arithmetic operators ---
[ "+" "-" "*" "/" ] @operator
