// cc-lsp is a Language Server Protocol server for .cc policy files.
// It provides diagnostics (parse errors), hover documentation, and completion.
//
// Usage:
//
//	cc-lsp --stdio
//
// The server communicates over stdin/stdout using the LSP JSON-RPC protocol.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"strings"
	"sync"

	"github.com/mikemackintosh/crowdcontrol/parser"
	"github.com/mikemackintosh/crowdcontrol/types"
)

// --- JSON-RPC types ---

type jsonrpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      any             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  any             `json:"result,omitempty"`
}

type position struct {
	Line      int `json:"line"`
	Character int `json:"character"`
}

type lspRange struct {
	Start position `json:"start"`
	End   position `json:"end"`
}

type diagnostic struct {
	Range    lspRange `json:"range"`
	Severity int      `json:"severity"` // 1=Error, 2=Warning, 3=Info, 4=Hint
	Source   string   `json:"source"`
	Message  string   `json:"message"`
}

type textDocumentIdentifier struct {
	URI string `json:"uri"`
}

type textDocumentItem struct {
	URI        string `json:"uri"`
	LanguageID string `json:"languageId"`
	Version    int    `json:"version"`
	Text       string `json:"text"`
}

type didOpenParams struct {
	TextDocument textDocumentItem `json:"textDocument"`
}

type didChangeParams struct {
	TextDocument   struct{ URI string }    `json:"textDocument"`
	ContentChanges []struct{ Text string } `json:"contentChanges"`
}

type didSaveParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Text         string                 `json:"text,omitempty"`
}

type didCloseParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
}

type hoverParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Position     position               `json:"position"`
}

type completionParams struct {
	TextDocument textDocumentIdentifier `json:"textDocument"`
	Position     position               `json:"position"`
}

type completionItem struct {
	Label         string `json:"label"`
	Kind          int    `json:"kind"` // 14=Keyword, 15=Snippet
	Detail        string `json:"detail,omitempty"`
	Documentation string `json:"documentation,omitempty"`
	InsertText    string `json:"insertText,omitempty"`
	InsertTextFmt int    `json:"insertTextFormat,omitempty"` // 1=PlainText, 2=Snippet
}

// --- Server ---

type server struct {
	mu    sync.Mutex
	docs  map[string]string // URI → content
	diags map[string][]diagnostic
}

func newServer() *server {
	return &server{
		docs:  make(map[string]string),
		diags: make(map[string][]diagnostic),
	}
}

func main() {
	log.SetOutput(os.Stderr)
	log.SetFlags(0)
	log.SetPrefix("cc-lsp: ")

	s := newServer()
	reader := bufio.NewReader(os.Stdin)
	writer := os.Stdout

	for {
		msg, err := readMessage(reader)
		if err != nil {
			if err == io.EOF {
				return
			}
			log.Printf("read error: %v", err)
			return
		}

		responses := s.handle(msg)
		for _, resp := range responses {
			if err := writeMessage(writer, resp); err != nil {
				log.Printf("write error: %v", err)
				return
			}
		}
	}
}

func (s *server) handle(msg jsonrpcMessage) []jsonrpcMessage {
	switch msg.Method {
	case "initialize":
		return []jsonrpcMessage{s.handleInitialize(msg)}
	case "initialized":
		return nil
	case "shutdown":
		return []jsonrpcMessage{{JSONRPC: "2.0", ID: msg.ID, Result: nil}}
	case "exit":
		os.Exit(0)
		return nil
	case "textDocument/didOpen":
		return s.handleDidOpen(msg)
	case "textDocument/didChange":
		return s.handleDidChange(msg)
	case "textDocument/didSave":
		return s.handleDidSave(msg)
	case "textDocument/didClose":
		return s.handleDidClose(msg)
	case "textDocument/hover":
		return []jsonrpcMessage{s.handleHover(msg)}
	case "textDocument/completion":
		return []jsonrpcMessage{s.handleCompletion(msg)}
	default:
		return nil
	}
}

func (s *server) handleInitialize(msg jsonrpcMessage) jsonrpcMessage {
	return jsonrpcMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result: map[string]any{
			"capabilities": map[string]any{
				"textDocumentSync": map[string]any{
					"openClose": true,
					"change":    1, // Full sync
					"save":      map[string]any{"includeText": true},
				},
				"hoverProvider":      true,
				"completionProvider": map[string]any{"triggerCharacters": []string{"."}},
			},
			"serverInfo": map[string]any{
				"name":    "cc-lsp",
				"version": "0.1.0",
			},
		},
	}
}

func (s *server) handleDidOpen(msg jsonrpcMessage) []jsonrpcMessage {
	var params didOpenParams
	json.Unmarshal(msg.Params, &params)

	s.mu.Lock()
	s.docs[params.TextDocument.URI] = params.TextDocument.Text
	s.mu.Unlock()

	return s.publishDiagnostics(params.TextDocument.URI, params.TextDocument.Text)
}

func (s *server) handleDidChange(msg jsonrpcMessage) []jsonrpcMessage {
	var params didChangeParams
	json.Unmarshal(msg.Params, &params)

	if len(params.ContentChanges) == 0 {
		return nil
	}
	text := params.ContentChanges[len(params.ContentChanges)-1].Text

	s.mu.Lock()
	s.docs[params.TextDocument.URI] = text
	s.mu.Unlock()

	return s.publishDiagnostics(params.TextDocument.URI, text)
}

func (s *server) handleDidSave(msg jsonrpcMessage) []jsonrpcMessage {
	var params didSaveParams
	json.Unmarshal(msg.Params, &params)

	s.mu.Lock()
	text := s.docs[params.TextDocument.URI]
	if params.Text != "" {
		text = params.Text
		s.docs[params.TextDocument.URI] = text
	}
	s.mu.Unlock()

	return s.publishDiagnostics(params.TextDocument.URI, text)
}

func (s *server) handleDidClose(msg jsonrpcMessage) []jsonrpcMessage {
	var params didCloseParams
	json.Unmarshal(msg.Params, &params)

	s.mu.Lock()
	delete(s.docs, params.TextDocument.URI)
	delete(s.diags, params.TextDocument.URI)
	s.mu.Unlock()

	// Clear diagnostics
	return []jsonrpcMessage{{
		JSONRPC: "2.0",
		Method:  "textDocument/publishDiagnostics",
		Params:  mustJSON(map[string]any{"uri": params.TextDocument.URI, "diagnostics": []any{}}),
	}}
}

func (s *server) publishDiagnostics(uri, text string) []jsonrpcMessage {
	diags := validate(text)

	s.mu.Lock()
	s.diags[uri] = diags
	s.mu.Unlock()

	return []jsonrpcMessage{{
		JSONRPC: "2.0",
		Method:  "textDocument/publishDiagnostics",
		Params:  mustJSON(map[string]any{"uri": uri, "diagnostics": diags}),
	}}
}

func validate(text string) []diagnostic {
	_, err := parser.Parse(text)
	if err == nil {
		return nil
	}

	// Try to extract line/col from error message: "line N col M: ..."
	msg := err.Error()
	line, col := 1, 1
	if _, scanErr := fmt.Sscanf(msg, "line %d col %d:", &line, &col); scanErr == nil {
		// Remove the "line N col M: " prefix from the message
		if idx := strings.Index(msg, ": "); idx >= 0 {
			msg = msg[idx+2:]
		}
	}

	return []diagnostic{{
		Range: lspRange{
			Start: position{Line: line - 1, Character: col - 1},
			End:   position{Line: line - 1, Character: col + 10},
		},
		Severity: 1, // Error
		Source:   "crowdcontrol",
		Message:  msg,
	}}
}

func (s *server) handleHover(msg jsonrpcMessage) jsonrpcMessage {
	var params hoverParams
	json.Unmarshal(msg.Params, &params)

	s.mu.Lock()
	text, ok := s.docs[params.TextDocument.URI]
	s.mu.Unlock()

	if !ok {
		return jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID, Result: nil}
	}

	word := wordAtPosition(text, params.Position)
	hover := hoverForWord(word)

	if hover == "" {
		return jsonrpcMessage{JSONRPC: "2.0", ID: msg.ID, Result: nil}
	}

	return jsonrpcMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result: map[string]any{
			"contents": map[string]any{
				"kind":  "markdown",
				"value": hover,
			},
		},
	}
}

func (s *server) handleCompletion(msg jsonrpcMessage) jsonrpcMessage {
	var params completionParams
	json.Unmarshal(msg.Params, &params)

	s.mu.Lock()
	text, ok := s.docs[params.TextDocument.URI]
	s.mu.Unlock()

	items := completionItems(text, params.Position)
	if !ok {
		items = completionItems("", params.Position)
	}

	return jsonrpcMessage{
		JSONRPC: "2.0",
		ID:      msg.ID,
		Result:  items,
	}
}

// --- Hover documentation ---

var hoverDocs = map[string]string{
	"forbid":      "**forbid** `\"name\"` { ... }\n\nDenies if all conditions match. Use `unless` for escape clauses.",
	"warn":        "**warn** `\"name\"` { ... }\n\nSame as forbid but non-blocking. Produces a warning.",
	"permit":      "**permit** `\"name\"` { ... }\n\nExplicitly allows. Overrides `forbid` for the same resource+action.",
	"unless":      "**unless** `<condition>`\n\nEscape clause — if any `unless` is true, the rule does not fire. Multiple unlesses are OR'd.",
	"message":     "**message** `\"template\"`\n\nDenial output. Supports `{field.path}` interpolation and `{count(list)}`.",
	"description": "**description** `\"text\"`\n\nHuman-readable explanation (appears in denial output).",
	"owner":       "**owner** `\"team-or-person\"`\n\nWho owns/maintains this policy (appears in output).",
	"link":        "**link** `\"url\"`\n\nLink to documentation or runbook (appears in output).",
	"author":      "**author** `in team \"slug\"` | `in [\"user1\", ...]`\n\nChecks PR author's team membership or against a user list.",
	"approved_by": "**approved_by** `team \"slug\"`\n\nChecks if at least one approving reviewer is on the specified team.",
	"label":       "**label** `\"name\"`\n\nChecks if the PR has the specified label.",
	"count":       "**count**(`path`) `op value`\n\nCounts elements in a list. E.g., `count(plan.destroys) > 5`",
	"not":         "**not** `<condition>`\n\nNegates a single condition.",
	"or":          "`<condition>` **or** `<condition>`\n\nOR within a single line. Lines are AND'd together.",
	"any":         "**any** `<list_field>` `<predicate>`\n\nTrue if any element matches. E.g., `any pr.changed_files matches \"infra/*\"`",
	"all":         "**all** `<list_field>` `<predicate>`\n\nTrue if all elements match. E.g., `all pr.commit_authors in team \"approved\"`",
	"matches":     "**matches** `\"pattern\"`\n\nGlob pattern matching. `*` matches any sequence. E.g., `matches \"aws_iam_*\"`",
	"in":          "**in** `[\"a\", \"b\"]` | **in** `team \"slug\"`\n\nSet membership check or team membership.",
	"true":        "**true** — boolean literal",
	"false":       "**false** — boolean literal",
}

func hoverForWord(word string) string {
	if doc, ok := hoverDocs[word]; ok {
		return doc
	}

	// Check for known field prefixes
	switch {
	case strings.HasPrefix(word, "resource."):
		return "**resource.** fields\n\n`type`, `name`, `address`, `action`, `change.before.*`, `change.after.*`"
	case strings.HasPrefix(word, "pr."):
		return "**pr.** fields\n\n`author`, `author_teams`, `draft`, `approvals`, `labels`, `branch`, `base_branch`, `head_commit`, `repo`, `changed_files`, `commit_authors`, `reviewers`, `reviewer_teams`"
	case strings.HasPrefix(word, "project."):
		return "**project.** fields\n\n`workspace`, `dir`"
	case strings.HasPrefix(word, "plan."):
		return "**plan.** fields\n\n`resource_changes`, `destroys`, `creates`, `updates`, `changes`, plus any Terraform plan field"
	}

	return ""
}

// --- Completion items ---

func completionItems(text string, pos position) []completionItem {
	// Determine context: are we at top level or inside a rule body?
	line := getLine(text, pos.Line)
	indent := strings.TrimRight(line[:min(pos.Character, len(line))], " \t")

	if indent == "" || isTopLevel(text, pos) {
		return topLevelCompletions()
	}
	return bodyCompletions()
}

func topLevelCompletions() []completionItem {
	return []completionItem{
		{Label: "forbid", Kind: 14, Detail: "Deny rule", InsertText: "forbid \"${1:rule-name}\" {\n  ${0}\n}", InsertTextFmt: 2},
		{Label: "warn", Kind: 14, Detail: "Warning rule", InsertText: "warn \"${1:rule-name}\" {\n  ${0}\n}", InsertTextFmt: 2},
		{Label: "permit", Kind: 14, Detail: "Permit rule", InsertText: "permit \"${1:rule-name}\" {\n  ${0}\n}", InsertTextFmt: 2},
	}
}

func bodyCompletions() []completionItem {
	return []completionItem{
		{Label: "resource.type", Kind: 6, Detail: "Resource type field"},
		{Label: "resource.name", Kind: 6, Detail: "Resource name field"},
		{Label: "resource.address", Kind: 6, Detail: "Full resource address"},
		{Label: "resource.action", Kind: 6, Detail: "Terraform action (create, update, delete)"},
		{Label: "resource.change.after", Kind: 6, Detail: "Planned resource state"},
		{Label: "pr.author", Kind: 6, Detail: "PR author login"},
		{Label: "pr.draft", Kind: 6, Detail: "Whether the PR is a draft"},
		{Label: "pr.approvals", Kind: 6, Detail: "Number of approvals"},
		{Label: "pr.branch", Kind: 6, Detail: "Head branch name"},
		{Label: "pr.base_branch", Kind: 6, Detail: "Base branch name"},
		{Label: "pr.repo", Kind: 6, Detail: "Repository (owner/name)"},
		{Label: "pr.changed_files", Kind: 6, Detail: "List of changed file paths"},
		{Label: "pr.commit_authors", Kind: 6, Detail: "List of commit author logins"},
		{Label: "project.workspace", Kind: 6, Detail: "Terraform workspace"},
		{Label: "project.dir", Kind: 6, Detail: "Project directory"},
		{Label: "author in team", Kind: 14, Detail: "Check author team membership", InsertText: "author in team \"${1:team-slug}\"", InsertTextFmt: 2},
		{Label: "author in [users]", Kind: 14, Detail: "Check author against user list", InsertText: "author in [\"${1:user}\"]", InsertTextFmt: 2},
		{Label: "approved_by team", Kind: 14, Detail: "Check reviewer team approval", InsertText: "approved_by team \"${1:team-slug}\"", InsertTextFmt: 2},
		{Label: "label", Kind: 14, Detail: "Check PR label", InsertText: "label \"${1:label-name}\"", InsertTextFmt: 2},
		{Label: "unless", Kind: 14, Detail: "Escape clause", InsertText: "unless ${0}", InsertTextFmt: 2},
		{Label: "message", Kind: 14, Detail: "Denial message template", InsertText: "message \"${1}\"", InsertTextFmt: 2},
		{Label: "description", Kind: 14, Detail: "Policy description", InsertText: "description \"${1}\"", InsertTextFmt: 2},
		{Label: "owner", Kind: 14, Detail: "Policy owner", InsertText: "owner \"${1}\"", InsertTextFmt: 2},
		{Label: "link", Kind: 14, Detail: "Documentation link", InsertText: "link \"${1}\"", InsertTextFmt: 2},
		{Label: "count()", Kind: 3, Detail: "Aggregate count", InsertText: "count(${1:plan.destroys}) ${2:>} ${3:5}", InsertTextFmt: 2},
		{Label: "not", Kind: 14, Detail: "Negate condition"},
		{Label: "any", Kind: 14, Detail: "Any element matches", InsertText: "any ${1:pr.changed_files} matches \"${2:pattern}\"", InsertTextFmt: 2},
		{Label: "all", Kind: 14, Detail: "All elements match", InsertText: "all ${1:pr.commit_authors} in team \"${2:team}\"", InsertTextFmt: 2},
		{Label: "matches", Kind: 14, Detail: "Glob pattern match"},
		{Label: "in", Kind: 14, Detail: "Set membership"},
	}
}

// --- Helpers ---

func wordAtPosition(text string, pos position) string {
	lines := strings.Split(text, "\n")
	if pos.Line >= len(lines) {
		return ""
	}
	line := lines[pos.Line]
	if pos.Character >= len(line) {
		return ""
	}

	// Find word boundaries
	start := pos.Character
	for start > 0 && isWordChar(line[start-1]) {
		start--
	}
	end := pos.Character
	for end < len(line) && isWordChar(line[end]) {
		end++
	}

	return line[start:end]
}

func isWordChar(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_' || c == '.'
}

func getLine(text string, line int) string {
	lines := strings.Split(text, "\n")
	if line >= len(lines) {
		return ""
	}
	return lines[line]
}

func isTopLevel(text string, pos position) bool {
	// Count open/close braces before this position to determine nesting
	lines := strings.Split(text, "\n")
	depth := 0
	for i := 0; i < pos.Line && i < len(lines); i++ {
		for _, c := range lines[i] {
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
			}
		}
	}
	// Check current line up to cursor
	if pos.Line < len(lines) {
		line := lines[pos.Line]
		end := pos.Character
		if end > len(line) {
			end = len(line)
		}
		for _, c := range line[:end] {
			if c == '{' {
				depth++
			} else if c == '}' {
				depth--
			}
		}
	}
	return depth <= 0
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// --- JSON-RPC transport ---

func readMessage(reader *bufio.Reader) (jsonrpcMessage, error) {
	// Read headers
	contentLength := 0
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			return jsonrpcMessage{}, err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "Content-Length:") {
			fmt.Sscanf(line, "Content-Length: %d", &contentLength)
		}
	}

	if contentLength == 0 {
		return jsonrpcMessage{}, fmt.Errorf("missing Content-Length header")
	}

	// Read body
	body := make([]byte, contentLength)
	if _, err := io.ReadFull(reader, body); err != nil {
		return jsonrpcMessage{}, err
	}

	var msg jsonrpcMessage
	if err := json.Unmarshal(body, &msg); err != nil {
		return jsonrpcMessage{}, err
	}

	return msg, nil
}

func writeMessage(writer io.Writer, msg jsonrpcMessage) error {
	body, err := json.Marshal(msg)
	if err != nil {
		return err
	}
	header := fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body))
	if _, err := io.WriteString(writer, header); err != nil {
		return err
	}
	_, err = writer.Write(body)
	return err
}

func mustJSON(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

// --- Policy analysis for enhanced diagnostics ---

// validatePolicy performs deeper semantic checks beyond parse errors.
func validatePolicy(text string) []diagnostic {
	policy, err := parser.Parse(text)
	if err != nil {
		return nil // parse error already reported
	}

	var diags []diagnostic
	for _, rule := range policy.Rules {
		diags = append(diags, validateRule(rule, text)...)
	}
	return diags
}

func validateRule(rule types.Rule, text string) []diagnostic {
	var diags []diagnostic

	// Warn if forbid/warn has no message
	if rule.Kind != "permit" && rule.Message == "" {
		diags = append(diags, diagnostic{
			Range:    findRuleRange(rule.Name, text),
			Severity: 2, // Warning
			Source:   "crowdcontrol",
			Message:  fmt.Sprintf("rule %q has no message — denial output will show \"policy violation\"", rule.Name),
		})
	}

	// Warn if rule has no conditions (always fires)
	if len(rule.Conditions) == 0 {
		diags = append(diags, diagnostic{
			Range:    findRuleRange(rule.Name, text),
			Severity: 2,
			Source:   "crowdcontrol",
			Message:  fmt.Sprintf("rule %q has no conditions — it will always fire", rule.Name),
		})
	}

	return diags
}

func findRuleRange(name, text string) lspRange {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		if strings.Contains(line, fmt.Sprintf("%q", name)) {
			return lspRange{
				Start: position{Line: i, Character: 0},
				End:   position{Line: i, Character: len(line)},
			}
		}
	}
	return lspRange{}
}
