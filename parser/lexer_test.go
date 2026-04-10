package parser

import (
	"testing"
)

func TestLexEmpty(t *testing.T) {
	tokens, err := Lex("")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || tokens[0].Type != TokenEOF {
		t.Fatalf("expected single EOF token, got %d tokens", len(tokens))
	}
}

func TestLexWhitespaceOnly(t *testing.T) {
	tokens, err := Lex("   \n\t\n  ")
	if err != nil {
		t.Fatal(err)
	}
	if len(tokens) != 1 || tokens[0].Type != TokenEOF {
		t.Fatalf("expected single EOF token, got %d tokens", len(tokens))
	}
}

func TestLexComments(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"hash comment", "# this is a comment\n"},
		{"slash comment", "// this is a comment\n"},
		{"comment then token", "# comment\nforbid"},
		{"inline slash comment", "// comment\nwarn"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Lex(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			// Should have at most one ident + EOF
			for _, tok := range tokens {
				if tok.Type == TokenEOF {
					break
				}
				if tok.Type != TokenIdent {
					t.Errorf("unexpected token type after comment: %v %q", tok.Type, tok.Val)
				}
			}
		})
	}
}

func TestLexStringLiterals(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		expect string
	}{
		{"simple", `"hello"`, "hello"},
		{"with spaces", `"hello world"`, "hello world"},
		{"escaped quote", `"say \"hello\""`, `say "hello"`},
		{"escaped backslash", `"path\\to"`, `path\to`},
		{"escaped newline", `"line\none"`, "line\none"},
		{"escaped tab", `"col\tone"`, "col\tone"},
		{"with braces", `"{author} cannot modify"`, "{author} cannot modify"},
		{"with dots", `"resource.type.name"`, "resource.type.name"},
		{"empty string", `""`, ""},
		{"glob pattern", `"okta_*"`, "okta_*"},
		{"with dashes", `"enterprise-security"`, "enterprise-security"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tokens, err := Lex(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if tokens[0].Type != TokenString {
				t.Fatalf("expected string token, got %v", tokens[0].Type)
			}
			if tokens[0].Val != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, tokens[0].Val)
			}
		})
	}
}

func TestLexUnterminatedString(t *testing.T) {
	_, err := Lex(`"unterminated`)
	if err == nil {
		t.Fatal("expected error for unterminated string")
	}
}

func TestLexNumbers(t *testing.T) {
	tests := []struct {
		input  string
		expect string
	}{
		{"0", "0"},
		{"5", "5"},
		{"123", "123"},
		{"99", "99"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tokens, err := Lex(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if tokens[0].Type != TokenNumber {
				t.Fatalf("expected number token, got %v", tokens[0].Type)
			}
			if tokens[0].Val != tt.expect {
				t.Errorf("expected %q, got %q", tt.expect, tokens[0].Val)
			}
		})
	}
}

func TestLexIdentifiers(t *testing.T) {
	tests := []string{
		"forbid", "warn", "permit", "unless", "message",
		"author", "approved_by", "label", "count",
		"resource", "pr", "project", "plan",
		"in", "team", "matches", "true", "false",
	}

	for _, ident := range tests {
		t.Run(ident, func(t *testing.T) {
			tokens, err := Lex(ident)
			if err != nil {
				t.Fatal(err)
			}
			if tokens[0].Type != TokenIdent {
				t.Fatalf("expected ident token, got %v", tokens[0].Type)
			}
			if tokens[0].Val != ident {
				t.Errorf("expected %q, got %q", ident, tokens[0].Val)
			}
		})
	}
}

func TestLexOperators(t *testing.T) {
	tests := []struct {
		input    string
		expected TokenType
	}{
		{"==", TokenEq},
		{"!=", TokenNeq},
		{"<=", TokenLte},
		{">=", TokenGte},
		{"<", TokenLt},
		{">", TokenGt},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			tokens, err := Lex(tt.input)
			if err != nil {
				t.Fatal(err)
			}
			if tokens[0].Type != tt.expected {
				t.Errorf("expected token type %v, got %v", tt.expected, tokens[0].Type)
			}
		})
	}
}

func TestLexBraces(t *testing.T) {
	tokens, err := Lex("{ } [ ] ( ) . ,")
	if err != nil {
		t.Fatal(err)
	}

	expected := []TokenType{
		TokenLBrace, TokenRBrace, TokenLBracket, TokenRBracket,
		TokenLParen, TokenRParen, TokenDot, TokenComma, TokenEOF,
	}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, tok := range tokens {
		if tok.Type != expected[i] {
			t.Errorf("token %d: expected %v, got %v (%q)", i, expected[i], tok.Type, tok.Val)
		}
	}
}

func TestLexLineTracking(t *testing.T) {
	input := "forbid\n\"test\"\n{"
	tokens, err := Lex(input)
	if err != nil {
		t.Fatal(err)
	}

	if tokens[0].Line != 1 {
		t.Errorf("forbid: expected line 1, got %d", tokens[0].Line)
	}
	if tokens[1].Line != 2 {
		t.Errorf("string: expected line 2, got %d", tokens[1].Line)
	}
	if tokens[2].Line != 3 {
		t.Errorf("lbrace: expected line 3, got %d", tokens[2].Line)
	}
}

func TestLexUnexpectedChar(t *testing.T) {
	_, err := Lex("@")
	if err == nil {
		t.Fatal("expected error for unexpected character")
	}
}

func TestLexFullRule(t *testing.T) {
	input := `forbid "test-rule" {
  resource.type == "aws_iam_role"
  unless author in team "security"
  message "{author} cannot modify {resource.type}"
}`
	tokens, err := Lex(input)
	if err != nil {
		t.Fatalf("lex error: %v", err)
	}

	// Just verify we got a reasonable number of tokens without errors
	if len(tokens) < 15 {
		t.Errorf("expected at least 15 tokens, got %d", len(tokens))
	}

	// First should be "forbid"
	if tokens[0].Val != "forbid" {
		t.Errorf("first token: expected 'forbid', got %q", tokens[0].Val)
	}

	// Last should be EOF
	if tokens[len(tokens)-1].Type != TokenEOF {
		t.Error("last token should be EOF")
	}
}

func TestLexStringList(t *testing.T) {
	input := `["aws_iam_role", "aws_kms_key", "aws_s3_bucket"]`
	tokens, err := Lex(input)
	if err != nil {
		t.Fatal(err)
	}

	expected := []TokenType{
		TokenLBracket, TokenString, TokenComma, TokenString,
		TokenComma, TokenString, TokenRBracket, TokenEOF,
	}

	if len(tokens) != len(expected) {
		t.Fatalf("expected %d tokens, got %d", len(expected), len(tokens))
	}

	for i, tok := range tokens {
		if tok.Type != expected[i] {
			t.Errorf("token %d: expected %v, got %v (%q)", i, expected[i], tok.Type, tok.Val)
		}
	}
}
