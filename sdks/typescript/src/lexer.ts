/**
 * Lexer for CrowdControl policy source.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/parser/lexer.go to TypeScript.
 * Pure stdlib; no regex needed for tokenization.
 */

export enum TokenType {
  EOF = 0,
  IDENT = 1,
  STRING = 2,
  NUMBER = 3,
  LBRACE = 4,
  RBRACE = 5,
  LBRACKET = 6,
  RBRACKET = 7,
  LPAREN = 8,
  RPAREN = 9,
  DOT = 10,
  COMMA = 11,
  EQ = 12,
  NEQ = 13,
  LT = 14,
  GT = 15,
  LTE = 16,
  GTE = 17,
  STAR = 18,
  PLUS = 19,
  MINUS = 20,
  SLASH = 21,
}

export interface Token {
  type: TokenType;
  val: string;
  line: number;
  col: number;
}

export function tokenName(t: TokenType): string {
  return TokenType[t];
}

export function tokenDisplay(tok: Token): string {
  if (tok.type === TokenType.EOF) return "EOF";
  return JSON.stringify(tok.val);
}

export class LexError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "LexError";
  }
}

/**
 * Mimic Go's unicode.IsLetter: Unicode letter categories.
 * We use a simple regex-based test that covers the general Letter category.
 */
const LETTER_RE = /\p{L}/u;

function isLetter(ch: string): boolean {
  return LETTER_RE.test(ch);
}

function isDigit(ch: string): boolean {
  return ch >= "0" && ch <= "9";
}

function isAlnum(ch: string): boolean {
  return isLetter(ch) || isDigit(ch);
}

function isSpace(ch: string): boolean {
  return ch === " " || ch === "\t" || ch === "\r" || ch === "\n";
}

/** Tokenize a CrowdControl source string into a list of tokens. */
export function lex(source: string): Token[] {
  const lx = new Lexer(source);
  return lx.run();
}

class Lexer {
  private input: string;
  private pos = 0;
  private line = 1;
  private col = 1;
  private tokens: Token[] = [];

  constructor(source: string) {
    this.input = source;
  }

  run(): Token[] {
    const n = this.input.length;
    while (this.pos < n) {
      const ch = this.input[this.pos]!;

      // Whitespace
      if (isSpace(ch)) {
        if (ch === "\n") {
          this.line++;
          this.col = 1;
        } else {
          this.col++;
        }
        this.pos++;
        continue;
      }

      // Comments: # or //
      if (ch === "#" || (ch === "/" && this.pos + 1 < n && this.input[this.pos + 1] === "/")) {
        while (this.pos < n && this.input[this.pos] !== "\n") {
          this.pos++;
        }
        continue;
      }

      // String literal
      if (ch === '"') {
        this.tokens.push(this.lexString());
        continue;
      }

      // Number
      if (isDigit(ch)) {
        this.tokens.push(this.lexNumber());
        continue;
      }

      // Identifier or keyword
      if (isLetter(ch) || ch === "_") {
        this.tokens.push(this.lexIdent());
        continue;
      }

      // Two-character operators
      if (this.pos + 1 < n) {
        const two = this.input.slice(this.pos, this.pos + 2);
        let tt: TokenType | null = null;
        if (two === "==") tt = TokenType.EQ;
        else if (two === "!=") tt = TokenType.NEQ;
        else if (two === "<=") tt = TokenType.LTE;
        else if (two === ">=") tt = TokenType.GTE;
        if (tt !== null) {
          this.tokens.push({ type: tt, val: two, line: this.line, col: this.col });
          this.pos += 2;
          this.col += 2;
          continue;
        }
      }

      // Single-character tokens
      const single: Record<string, TokenType> = {
        "{": TokenType.LBRACE,
        "}": TokenType.RBRACE,
        "[": TokenType.LBRACKET,
        "]": TokenType.RBRACKET,
        "(": TokenType.LPAREN,
        ")": TokenType.RPAREN,
        ".": TokenType.DOT,
        ",": TokenType.COMMA,
        "<": TokenType.LT,
        ">": TokenType.GT,
        "*": TokenType.STAR,
        "+": TokenType.PLUS,
        "-": TokenType.MINUS,
        "/": TokenType.SLASH,
      };
      if (ch in single) {
        this.tokens.push({ type: single[ch]!, val: ch, line: this.line, col: this.col });
        this.pos++;
        this.col++;
        continue;
      }

      throw new LexError(`line ${this.line} col ${this.col}: unexpected character: ${ch}`);
    }

    this.tokens.push({ type: TokenType.EOF, val: "", line: this.line, col: this.col });
    return this.tokens;
  }

  private lexString(): Token {
    const startCol = this.col;
    this.pos++; // skip opening "
    this.col++;
    const parts: string[] = [];
    const n = this.input.length;
    while (this.pos < n) {
      const ch = this.input[this.pos]!;
      if (ch === '"') {
        this.pos++;
        this.col++;
        return { type: TokenType.STRING, val: parts.join(""), line: this.line, col: startCol };
      }
      if (ch === "\\" && this.pos + 1 < n) {
        this.pos++;
        this.col++;
        const nxt = this.input[this.pos]!;
        if (nxt === '"' || nxt === "\\") {
          parts.push(nxt);
        } else if (nxt === "n") {
          parts.push("\n");
        } else if (nxt === "t") {
          parts.push("\t");
        } else {
          parts.push("\\");
          parts.push(nxt);
        }
      } else {
        parts.push(ch);
      }
      this.pos++;
      this.col++;
    }
    throw new LexError(`line ${this.line} col ${startCol}: unterminated string`);
  }

  private lexNumber(): Token {
    const start = this.pos;
    const startCol = this.col;
    const n = this.input.length;
    while (this.pos < n) {
      const ch = this.input[this.pos]!;
      if (isDigit(ch) || ch === ".") {
        this.pos++;
        this.col++;
      } else {
        break;
      }
    }
    return {
      type: TokenType.NUMBER,
      val: this.input.slice(start, this.pos),
      line: this.line,
      col: startCol,
    };
  }

  private lexIdent(): Token {
    const start = this.pos;
    const startCol = this.col;
    const n = this.input.length;
    while (this.pos < n) {
      const ch = this.input[this.pos]!;
      if (isAlnum(ch) || ch === "_") {
        this.pos++;
        this.col++;
      } else {
        break;
      }
    }
    return {
      type: TokenType.IDENT,
      val: this.input.slice(start, this.pos),
      line: this.line,
      col: startCol,
    };
  }
}
