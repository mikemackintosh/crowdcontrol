package parser

import (
	"fmt"
	"strings"
	"unicode"
)

// TokenType identifies token kinds.
type TokenType int

const (
	TokenEOF      TokenType = iota
	TokenIdent              // keywords and identifiers: forbid, warn, permit, resource, etc.
	TokenString             // "quoted string"
	TokenNumber             // 123, 5.0
	TokenLBrace             // {
	TokenRBrace             // }
	TokenLBracket           // [
	TokenRBracket           // ]
	TokenLParen             // (
	TokenRParen             // )
	TokenDot                // .
	TokenComma              // ,
	TokenEq                 // ==
	TokenNeq                // !=
	TokenLt                 // <
	TokenGt                 // >
	TokenLte                // <=
	TokenGte                // >=
	TokenStar               // * (also used as multiply in arithmetic)
	TokenPlus               // +
	TokenMinus              // -
	TokenSlash              // /
)

// Token is a lexed token with position info.
type Token struct {
	Type TokenType
	Val  string
	Line int
	Col  int
}

func (t Token) String() string {
	if t.Type == TokenEOF {
		return "EOF"
	}
	return fmt.Sprintf("%q", t.Val)
}

// Lexer tokenizes CrowdControl policy source code.
type Lexer struct {
	input  []rune
	pos    int
	line   int
	col    int
	tokens []Token
}

// Lex tokenizes the input string.
func Lex(input string) ([]Token, error) {
	l := &Lexer{
		input: []rune(input),
		line:  1,
		col:   1,
	}
	if err := l.run(); err != nil {
		return nil, err
	}
	l.tokens = append(l.tokens, Token{Type: TokenEOF, Line: l.line, Col: l.col})
	return l.tokens, nil
}

func (l *Lexer) run() error {
	for l.pos < len(l.input) {
		ch := l.input[l.pos]

		// Skip whitespace
		if unicode.IsSpace(ch) {
			if ch == '\n' {
				l.line++
				l.col = 1
			} else {
				l.col++
			}
			l.pos++
			continue
		}

		// Skip comments
		if ch == '#' || (ch == '/' && l.pos+1 < len(l.input) && l.input[l.pos+1] == '/') {
			for l.pos < len(l.input) && l.input[l.pos] != '\n' {
				l.pos++
			}
			continue
		}

		// String literal
		if ch == '"' {
			tok, err := l.lexString()
			if err != nil {
				return err
			}
			l.tokens = append(l.tokens, tok)
			continue
		}

		// Number
		if unicode.IsDigit(ch) {
			l.tokens = append(l.tokens, l.lexNumber())
			continue
		}

		// Identifier or keyword
		if unicode.IsLetter(ch) || ch == '_' {
			l.tokens = append(l.tokens, l.lexIdent())
			continue
		}

		// Two-character operators
		if l.pos+1 < len(l.input) {
			two := string(l.input[l.pos : l.pos+2])
			switch two {
			case "==":
				l.tokens = append(l.tokens, Token{Type: TokenEq, Val: two, Line: l.line, Col: l.col})
				l.pos += 2
				l.col += 2
				continue
			case "!=":
				l.tokens = append(l.tokens, Token{Type: TokenNeq, Val: two, Line: l.line, Col: l.col})
				l.pos += 2
				l.col += 2
				continue
			case "<=":
				l.tokens = append(l.tokens, Token{Type: TokenLte, Val: two, Line: l.line, Col: l.col})
				l.pos += 2
				l.col += 2
				continue
			case ">=":
				l.tokens = append(l.tokens, Token{Type: TokenGte, Val: two, Line: l.line, Col: l.col})
				l.pos += 2
				l.col += 2
				continue
			}
		}

		// Single character tokens
		tok := Token{Line: l.line, Col: l.col, Val: string(ch)}
		switch ch {
		case '{':
			tok.Type = TokenLBrace
		case '}':
			tok.Type = TokenRBrace
		case '[':
			tok.Type = TokenLBracket
		case ']':
			tok.Type = TokenRBracket
		case '(':
			tok.Type = TokenLParen
		case ')':
			tok.Type = TokenRParen
		case '.':
			tok.Type = TokenDot
		case ',':
			tok.Type = TokenComma
		case '<':
			tok.Type = TokenLt
		case '>':
			tok.Type = TokenGt
		case '*':
			tok.Type = TokenStar
		case '+':
			tok.Type = TokenPlus
		case '-':
			tok.Type = TokenMinus
		case '/':
			// Check it's not a comment (// already handled above)
			tok.Type = TokenSlash
		default:
			return fmt.Errorf("line %d col %d: unexpected character: %c", l.line, l.col, ch)
		}
		l.tokens = append(l.tokens, tok)
		l.pos++
		l.col++
	}

	return nil
}

func (l *Lexer) lexString() (Token, error) {
	start := l.pos
	startCol := l.col
	l.pos++ // skip opening "
	l.col++

	var sb strings.Builder
	for l.pos < len(l.input) {
		ch := l.input[l.pos]
		if ch == '"' {
			l.pos++
			l.col++
			return Token{Type: TokenString, Val: sb.String(), Line: l.line, Col: startCol}, nil
		}
		if ch == '\\' && l.pos+1 < len(l.input) {
			l.pos++
			l.col++
			next := l.input[l.pos]
			switch next {
			case '"', '\\':
				sb.WriteRune(next)
			case 'n':
				sb.WriteRune('\n')
			case 't':
				sb.WriteRune('\t')
			default:
				sb.WriteRune('\\')
				sb.WriteRune(next)
			}
		} else {
			sb.WriteRune(ch)
		}
		l.pos++
		l.col++
	}

	return Token{}, fmt.Errorf("line %d col %d: unterminated string", l.line, start)
}

func (l *Lexer) lexNumber() Token {
	start := l.pos
	startCol := l.col
	for l.pos < len(l.input) && (unicode.IsDigit(l.input[l.pos]) || l.input[l.pos] == '.') {
		l.pos++
		l.col++
	}
	return Token{Type: TokenNumber, Val: string(l.input[start:l.pos]), Line: l.line, Col: startCol}
}

func (l *Lexer) lexIdent() Token {
	start := l.pos
	startCol := l.col
	for l.pos < len(l.input) && (unicode.IsLetter(l.input[l.pos]) || unicode.IsDigit(l.input[l.pos]) || l.input[l.pos] == '_') {
		l.pos++
		l.col++
	}
	return Token{Type: TokenIdent, Val: string(l.input[start:l.pos]), Line: l.line, Col: startCol}
}
