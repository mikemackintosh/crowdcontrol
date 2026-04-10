; Highlight query for the CrowdControl policy language.
;
; Captures here use the standard tree-sitter highlight capture names
; so any editor that ships with a default highlight theme (Zed,
; Neovim, Helix, Emacs) will pick up reasonable colors without extra
; configuration. The two-hue palette from the docs (mint keywords,
; amber strings, neutral identifiers) falls out naturally because
; that's what almost every dark theme does for these captures.

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

; --- comparison and set operators are also keyword-ish ---
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

; --- field paths: the first identifier is like a variable root,
; later segments are properties. Applied via field path matching. ---
(field_path
  (identifier) @variable)

; --- rule name strings and metadata values keep the generic @string
; capture above, which is what we want ---

; --- punctuation ---
[ "{" "}" "[" "]" "(" ")" ] @punctuation.bracket
[ "," "." ] @punctuation.delimiter

; --- arithmetic operators ---
[ "+" "-" "*" "/" ] @operator
