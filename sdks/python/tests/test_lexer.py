"""Unit tests for the CrowdControl lexer."""

import os
import sys
import unittest

sys.path.insert(0, os.path.normpath(os.path.join(os.path.dirname(__file__), "..")))

from crowdcontrol.lexer import LexError, TokenType, lex  # noqa: E402


class TestLexer(unittest.TestCase):
    def _types(self, source):
        return [t.type for t in lex(source)[:-1]]  # drop EOF

    def test_empty(self):
        self.assertEqual(self._types(""), [])

    def test_keywords_are_idents(self):
        types = self._types("forbid warn permit unless")
        self.assertEqual(types, [TokenType.IDENT] * 4)
        self.assertEqual([t.val for t in lex("forbid warn permit unless")[:-1]],
                         ["forbid", "warn", "permit", "unless"])

    def test_string_with_escapes(self):
        tokens = lex(r'"hello\nworld\t\"done\""')
        self.assertEqual(tokens[0].type, TokenType.STRING)
        self.assertEqual(tokens[0].val, 'hello\nworld\t"done"')

    def test_numbers_int_and_float(self):
        tokens = lex("42 3.14")
        self.assertEqual(tokens[0].type, TokenType.NUMBER)
        self.assertEqual(tokens[0].val, "42")
        self.assertEqual(tokens[1].type, TokenType.NUMBER)
        self.assertEqual(tokens[1].val, "3.14")

    def test_dotted_path(self):
        tokens = lex("resource.type")
        self.assertEqual([t.type for t in tokens[:-1]],
                         [TokenType.IDENT, TokenType.DOT, TokenType.IDENT])

    def test_two_char_operators(self):
        tokens = lex("== != <= >=")
        kinds = [t.type for t in tokens[:-1]]
        self.assertEqual(kinds, [TokenType.EQ, TokenType.NEQ, TokenType.LTE, TokenType.GTE])

    def test_single_char_operators(self):
        tokens = lex("< > + - * /")
        kinds = [t.type for t in tokens[:-1]]
        self.assertEqual(kinds, [
            TokenType.LT, TokenType.GT, TokenType.PLUS, TokenType.MINUS,
            TokenType.STAR, TokenType.SLASH,
        ])

    def test_punctuation(self):
        tokens = lex("{ } [ ] ( ) , .")
        kinds = [t.type for t in tokens[:-1]]
        self.assertEqual(kinds, [
            TokenType.LBRACE, TokenType.RBRACE,
            TokenType.LBRACKET, TokenType.RBRACKET,
            TokenType.LPAREN, TokenType.RPAREN,
            TokenType.COMMA, TokenType.DOT,
        ])

    def test_hash_comment(self):
        tokens = lex("# this is a comment\nforbid")
        self.assertEqual(tokens[0].type, TokenType.IDENT)
        self.assertEqual(tokens[0].val, "forbid")

    def test_double_slash_comment(self):
        tokens = lex("// this is a comment\nforbid")
        self.assertEqual(tokens[0].type, TokenType.IDENT)
        self.assertEqual(tokens[0].val, "forbid")

    def test_line_col_tracking(self):
        tokens = lex("forbid\n  warn")
        self.assertEqual(tokens[0].line, 1)
        self.assertEqual(tokens[0].col, 1)
        self.assertEqual(tokens[1].line, 2)
        self.assertEqual(tokens[1].col, 3)

    def test_unterminated_string_error(self):
        with self.assertRaises(LexError):
            lex('"no closing quote')

    def test_unexpected_char_error(self):
        with self.assertRaises(LexError):
            lex("@")

    def test_ident_with_underscore_and_digits(self):
        tokens = lex("foo_bar_123")
        self.assertEqual(tokens[0].type, TokenType.IDENT)
        self.assertEqual(tokens[0].val, "foo_bar_123")


if __name__ == "__main__":
    unittest.main()
