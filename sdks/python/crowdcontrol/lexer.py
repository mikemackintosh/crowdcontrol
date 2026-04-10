"""Lexer for CrowdControl policy source.

Ports github.com/mikemackintosh/crowdcontrol/parser/lexer.go to Python.
Pure stdlib; no regex needed for tokenization.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import IntEnum


class TokenType(IntEnum):
    EOF = 0
    IDENT = 1
    STRING = 2
    NUMBER = 3
    LBRACE = 4
    RBRACE = 5
    LBRACKET = 6
    RBRACKET = 7
    LPAREN = 8
    RPAREN = 9
    DOT = 10
    COMMA = 11
    EQ = 12
    NEQ = 13
    LT = 14
    GT = 15
    LTE = 16
    GTE = 17
    STAR = 18
    PLUS = 19
    MINUS = 20
    SLASH = 21


@dataclass
class Token:
    type: TokenType
    val: str = ""
    line: int = 0
    col: int = 0

    def __str__(self) -> str:
        if self.type == TokenType.EOF:
            return "EOF"
        return repr(self.val)


class LexError(Exception):
    """Raised when the lexer encounters invalid input."""


def lex(source: str) -> list[Token]:
    """Tokenize a CrowdControl source string into a list of tokens.

    Always ends with a single ``TokenType.EOF`` token.
    """
    lx = _Lexer(source)
    return lx.run()


class _Lexer:
    def __init__(self, source: str) -> None:
        self.input = source
        self.pos = 0
        self.line = 1
        self.col = 1
        self.tokens: list[Token] = []

    def run(self) -> list[Token]:
        n = len(self.input)
        while self.pos < n:
            ch = self.input[self.pos]

            # Whitespace
            if ch.isspace():
                if ch == "\n":
                    self.line += 1
                    self.col = 1
                else:
                    self.col += 1
                self.pos += 1
                continue

            # Comments: # or //
            if ch == "#" or (ch == "/" and self.pos + 1 < n and self.input[self.pos + 1] == "/"):
                while self.pos < n and self.input[self.pos] != "\n":
                    self.pos += 1
                continue

            # String literal
            if ch == '"':
                self.tokens.append(self._lex_string())
                continue

            # Number
            if ch.isdigit():
                self.tokens.append(self._lex_number())
                continue

            # Identifier or keyword
            if ch.isalpha() or ch == "_":
                self.tokens.append(self._lex_ident())
                continue

            # Two-character operators
            if self.pos + 1 < n:
                two = self.input[self.pos : self.pos + 2]
                mapping = {
                    "==": TokenType.EQ,
                    "!=": TokenType.NEQ,
                    "<=": TokenType.LTE,
                    ">=": TokenType.GTE,
                }
                if two in mapping:
                    self.tokens.append(Token(mapping[two], two, self.line, self.col))
                    self.pos += 2
                    self.col += 2
                    continue

            # Single-character tokens
            single_map = {
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
            }
            if ch in single_map:
                self.tokens.append(Token(single_map[ch], ch, self.line, self.col))
                self.pos += 1
                self.col += 1
                continue

            raise LexError(f"line {self.line} col {self.col}: unexpected character: {ch}")

        self.tokens.append(Token(TokenType.EOF, "", self.line, self.col))
        return self.tokens

    def _lex_string(self) -> Token:
        start_col = self.col
        self.pos += 1  # skip opening "
        self.col += 1
        parts: list[str] = []
        n = len(self.input)
        while self.pos < n:
            ch = self.input[self.pos]
            if ch == '"':
                self.pos += 1
                self.col += 1
                return Token(TokenType.STRING, "".join(parts), self.line, start_col)
            if ch == "\\" and self.pos + 1 < n:
                self.pos += 1
                self.col += 1
                nxt = self.input[self.pos]
                if nxt == '"' or nxt == "\\":
                    parts.append(nxt)
                elif nxt == "n":
                    parts.append("\n")
                elif nxt == "t":
                    parts.append("\t")
                else:
                    parts.append("\\")
                    parts.append(nxt)
            else:
                parts.append(ch)
            self.pos += 1
            self.col += 1
        raise LexError(f"line {self.line} col {start_col}: unterminated string")

    def _lex_number(self) -> Token:
        start = self.pos
        start_col = self.col
        n = len(self.input)
        while self.pos < n and (self.input[self.pos].isdigit() or self.input[self.pos] == "."):
            self.pos += 1
            self.col += 1
        return Token(TokenType.NUMBER, self.input[start : self.pos], self.line, start_col)

    def _lex_ident(self) -> Token:
        start = self.pos
        start_col = self.col
        n = len(self.input)
        while self.pos < n:
            ch = self.input[self.pos]
            if ch.isalnum() or ch == "_":
                self.pos += 1
                self.col += 1
            else:
                break
        return Token(TokenType.IDENT, self.input[start : self.pos], self.line, start_col)
