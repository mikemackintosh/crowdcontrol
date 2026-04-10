"""Parser for CrowdControl policy source.

Ports github.com/mikemackintosh/crowdcontrol/parser/parser.go to Python.
"""

from __future__ import annotations

from .lexer import LexError, Token, TokenType, lex
from .types import (
    Condition,
    ConditionType,
    Expr,
    ExprKind,
    Policy,
    Rule,
)


class ParseError(Exception):
    """Raised when the parser encounters invalid syntax."""


def parse(source: str) -> Policy:
    """Parse CrowdControl source into a Policy AST."""
    try:
        tokens = lex(source)
    except LexError as e:
        raise ParseError(str(e)) from e
    p = _Parser(tokens)
    return p.parse_policy()


class _Parser:
    def __init__(self, tokens: list[Token]) -> None:
        self.tokens = tokens
        self.pos = 0

    # ----- top level -------------------------------------------------------

    def parse_policy(self) -> Policy:
        policy = Policy()
        while not self._at_end():
            policy.rules.append(self._parse_rule())
        return policy

    def _parse_rule(self) -> Rule:
        kind_tok = self._advance()
        if kind_tok.type != TokenType.IDENT:
            raise self._errorf(f"expected forbid, warn, or permit, got {kind_tok}")
        kind = kind_tok.val
        if kind not in ("forbid", "warn", "permit"):
            raise self._errorf(f"expected forbid, warn, or permit, got {kind!r}")

        name_tok = self._advance()
        if name_tok.type != TokenType.STRING:
            raise self._errorf(f"expected rule name string, got {name_tok}")

        self._expect(TokenType.LBRACE)

        rule = Rule(kind=kind, name=name_tok.val)

        while not self._check(TokenType.RBRACE) and not self._at_end():
            self._parse_clause(rule)

        self._expect(TokenType.RBRACE)
        return rule

    def _parse_clause(self, rule: Rule) -> None:
        tok = self._peek()
        val = tok.val

        if val == "unless":
            self._parse_unless(rule)
            return
        if val == "message":
            self._parse_message(rule)
            return
        if val in ("description", "owner", "link"):
            self._parse_metadata(rule, val)
            return
        if val == "not":
            cond = self._parse_negated_condition()
        elif val in ("any", "all"):
            cond = self._parse_quantifier()
        elif val == "has":
            cond = self._parse_has_condition()
        elif val == "count":
            cond = self._parse_aggregate_condition()
        elif val in ("lower", "upper", "len"):
            cond = self._parse_transform_condition()
        else:
            cond = self._parse_field_cond()

        rule.conditions.append(self._wrap_or(cond))

    # ----- or-chaining -----------------------------------------------------

    def _wrap_or(self, first: Condition) -> Condition:
        if not self._check_ident("or"):
            return first
        group = [first]
        while self._check_ident("or"):
            self._advance()  # consume "or"
            try:
                cond = self._parse_single_condition()
            except ParseError:
                break
            group.append(cond)
        return Condition(type=ConditionType.OR, or_group=group)

    def _parse_single_condition(self) -> Condition:
        val = self._peek().val
        if val == "not":
            return self._parse_negated_condition()
        if val in ("any", "all"):
            return self._parse_quantifier()
        if val == "has":
            return self._parse_has_condition()
        if val == "count":
            return self._parse_aggregate_condition()
        if val in ("lower", "upper", "len"):
            return self._parse_transform_condition()
        return self._parse_field_cond()

    # ----- individual conditions -------------------------------------------

    def _parse_negated_condition(self) -> Condition:
        self._advance()  # consume "not"
        cond = self._parse_single_condition()
        cond.negated = not cond.negated
        return cond

    def _parse_has_condition(self) -> Condition:
        self._advance()  # consume "has"
        field = self._parse_dotted_path()
        return Condition(type=ConditionType.HAS, field=field)

    def _parse_quantifier(self) -> Condition:
        quant_tok = self._advance()  # consume "any" or "all"
        list_field = self._parse_dotted_path()
        predicate = self._parse_element_predicate()
        cond_type = ConditionType.ALL if quant_tok.val == "all" else ConditionType.ANY
        return Condition(
            type=cond_type,
            quantifier=quant_tok.val,
            list_field=list_field,
            predicate=predicate,
        )

    def _parse_element_predicate(self) -> Condition:
        tok = self._peek()

        if tok.type == TokenType.IDENT and tok.val == "in":
            self._advance()
            nxt = self._peek()
            if nxt.type == TokenType.LBRACKET:
                vals = self._parse_string_list()
                return Condition(type=ConditionType.FIELD, op="in", value=vals)
            raise self._errorf(f"expected list after 'in', got {nxt}")

        if tok.type == TokenType.IDENT and tok.val in ("matches", "matches_regex"):
            op = tok.val
            self._advance()
            val_tok = self._advance()
            if val_tok.type != TokenType.STRING:
                raise self._errorf(f"{op} expects a string pattern, got {val_tok}")
            return Condition(type=ConditionType.FIELD, op=op, value=val_tok.val)

        if tok.type == TokenType.IDENT and tok.val == "contains":
            self._advance()
            val = self._parse_value()
            return Condition(type=ConditionType.FIELD, op="contains", value=val)

        op_tok = self._advance()
        if op_tok.type not in (
            TokenType.EQ,
            TokenType.NEQ,
            TokenType.LT,
            TokenType.GT,
            TokenType.LTE,
            TokenType.GTE,
        ):
            raise self._errorf(f"expected operator in quantifier predicate, got {op_tok}")
        val = self._parse_value()
        return Condition(type=ConditionType.FIELD, op=op_tok.val, value=val)

    def _parse_field_cond(self) -> Condition:
        field = self._parse_dotted_path()

        if self._is_arith_op():
            left = Expr(kind=ExprKind.FIELD, field=field)
            return self._parse_expr_condition_from_left(left)

        op_tok = self._advance()
        op = op_tok.val

        comparison_types = (
            TokenType.EQ,
            TokenType.NEQ,
            TokenType.LT,
            TokenType.GT,
            TokenType.LTE,
            TokenType.GTE,
        )
        if op_tok.type not in comparison_types:
            if op_tok.type == TokenType.IDENT and op_tok.val in (
                "in",
                "matches",
                "matches_regex",
                "contains",
                "intersects",
                "is_subset",
            ):
                op = op_tok.val
            else:
                raise self._errorf(f"expected operator, got {op_tok}")

        cond = Condition(type=ConditionType.FIELD, field=field, op=op)

        if op in ("in", "intersects", "is_subset"):
            cond.value = self._parse_string_list()
        elif op in ("matches", "matches_regex"):
            val_tok = self._advance()
            if val_tok.type != TokenType.STRING:
                raise self._errorf(f"{op} expects a string pattern, got {val_tok}")
            cond.value = val_tok.val
        else:
            cond.value = self._parse_value()

        return cond

    def _is_arith_op(self) -> bool:
        t = self._peek().type
        return t in (TokenType.PLUS, TokenType.MINUS, TokenType.STAR, TokenType.SLASH)

    def _parse_expr_condition_from_left(self, left: Expr) -> Condition:
        expr = self._parse_arith_expr_from(left)

        op_tok = self._advance()
        if op_tok.type not in (
            TokenType.EQ,
            TokenType.NEQ,
            TokenType.LT,
            TokenType.GT,
            TokenType.LTE,
            TokenType.GTE,
        ):
            raise self._errorf(f"expected comparison operator in expression, got {op_tok}")

        right = self._parse_arith_expr()
        return Condition(
            type=ConditionType.EXPR,
            op=op_tok.val,
            left_expr=expr,
            right_expr=right,
        )

    def _parse_arith_expr(self) -> Expr:
        left = self._parse_expr_term()
        return self._parse_arith_expr_from(left)

    def _parse_arith_expr_from(self, left: Expr) -> Expr:
        while self._is_arith_op():
            op_tok = self._advance()
            right = self._parse_expr_term()
            left = Expr(kind=ExprKind.BINARY, op=op_tok.val, left=left, right=right)
        return left

    def _parse_expr_term(self) -> Expr:
        tok = self._peek()

        if tok.type == TokenType.NUMBER:
            self._advance()
            try:
                return Expr(kind=ExprKind.LITERAL, value=float(tok.val))
            except ValueError as e:
                raise self._errorf(f"invalid number: {tok.val}") from e

        if tok.type == TokenType.IDENT and tok.val in ("count", "len"):
            func_name = tok.val
            self._advance()
            self._expect(TokenType.LPAREN)
            path = self._parse_dotted_path()
            self._expect(TokenType.RPAREN)
            if func_name == "count":
                return Expr(kind=ExprKind.COUNT, agg_target=path)
            return Expr(kind=ExprKind.LEN, field=path, transform="len")

        if tok.type == TokenType.IDENT:
            path = self._parse_dotted_path()
            return Expr(kind=ExprKind.FIELD, field=path)

        raise self._errorf(f"expected number, field, count(), or len() in expression, got {tok}")

    def _parse_unless(self, rule: Rule) -> None:
        self._advance()  # consume "unless"
        val = self._peek().val
        if val == "not":
            cond = self._parse_negated_condition()
        elif val in ("any", "all"):
            cond = self._parse_quantifier()
        elif val == "has":
            cond = self._parse_has_condition()
        elif val in ("lower", "upper", "len"):
            cond = self._parse_transform_condition()
        elif val == "count":
            cond = self._parse_aggregate_condition()
        else:
            cond = self._parse_field_cond()
        rule.unlesses.append(cond)

    def _parse_transform_condition(self) -> Condition:
        func_tok = self._advance()
        self._expect(TokenType.LPAREN)
        field = self._parse_dotted_path()
        self._expect(TokenType.RPAREN)

        if func_tok.val == "len" and self._is_arith_op():
            left = Expr(kind=ExprKind.LEN, field=field, transform="len")
            return self._parse_expr_condition_from_left(left)

        op_tok = self._advance()
        op = op_tok.val
        if op_tok.type not in (
            TokenType.EQ,
            TokenType.NEQ,
            TokenType.LT,
            TokenType.GT,
            TokenType.LTE,
            TokenType.GTE,
        ):
            if op_tok.type == TokenType.IDENT and op_tok.val in (
                "in",
                "matches",
                "matches_regex",
                "contains",
            ):
                op = op_tok.val
            else:
                raise self._errorf(f"expected operator after {func_tok.val}(), got {op_tok}")

        cond = Condition(type=ConditionType.FIELD, field=field, op=op, transform=func_tok.val)

        if op == "in":
            cond.value = self._parse_string_list()
        elif op in ("matches", "matches_regex"):
            val_tok = self._advance()
            if val_tok.type != TokenType.STRING:
                raise self._errorf(f"{op} expects a string pattern, got {val_tok}")
            cond.value = val_tok.val
        else:
            cond.value = self._parse_value()
        return cond

    def _parse_aggregate_condition(self) -> Condition:
        self._advance()  # consume "count"
        self._expect(TokenType.LPAREN)
        target = self._parse_dotted_path()
        self._expect(TokenType.RPAREN)

        if self._is_arith_op():
            left = Expr(kind=ExprKind.COUNT, agg_target=target)
            return self._parse_expr_condition_from_left(left)

        op_tok = self._advance()
        if op_tok.type not in (
            TokenType.LT,
            TokenType.GT,
            TokenType.LTE,
            TokenType.GTE,
            TokenType.EQ,
            TokenType.NEQ,
        ):
            raise self._errorf(f"expected comparison operator after count(), got {op_tok}")

        val_tok = self._advance()
        if val_tok.type != TokenType.NUMBER:
            raise self._errorf(f"expected number after operator, got {val_tok}")
        try:
            num = int(val_tok.val)
        except ValueError as e:
            raise self._errorf(f"invalid number: {val_tok.val}") from e

        return Condition(
            type=ConditionType.AGGREGATE,
            aggregate_func="count",
            aggregate_target=target,
            op=op_tok.val,
            value=num,
        )

    def _parse_message(self, rule: Rule) -> None:
        self._advance()
        msg_tok = self._advance()
        if msg_tok.type != TokenType.STRING:
            raise self._errorf(f"expected message string, got {msg_tok}")
        rule.message = msg_tok.val

    def _parse_metadata(self, rule: Rule, keyword: str) -> None:
        self._advance()
        val_tok = self._advance()
        if val_tok.type != TokenType.STRING:
            raise self._errorf(f"expected string after {keyword}, got {val_tok}")
        if keyword == "description":
            rule.description = val_tok.val
        elif keyword == "owner":
            rule.owner = val_tok.val
        elif keyword == "link":
            rule.link = val_tok.val

    # ----- helpers ---------------------------------------------------------

    def _parse_dotted_path(self) -> str:
        tok = self._advance()
        if tok.type != TokenType.IDENT:
            raise self._errorf(f"expected identifier, got {tok}")
        parts = [tok.val]
        while self._check(TokenType.DOT):
            self._advance()
            nxt = self._advance()
            if nxt.type != TokenType.IDENT:
                raise self._errorf(f"expected identifier after '.', got {nxt}")
            parts.append(nxt.val)
        return ".".join(parts)

    def _parse_string_list(self) -> list[str]:
        self._expect(TokenType.LBRACKET)
        vals: list[str] = []
        while not self._check(TokenType.RBRACKET) and not self._at_end():
            tok = self._advance()
            if tok.type != TokenType.STRING:
                raise self._errorf(f"expected string in list, got {tok}")
            vals.append(tok.val)
            if self._check(TokenType.COMMA):
                self._advance()
        self._expect(TokenType.RBRACKET)
        return vals

    def _parse_value(self):
        tok = self._advance()
        if tok.type == TokenType.STRING:
            return tok.val
        if tok.type == TokenType.NUMBER:
            try:
                return int(tok.val)
            except ValueError:
                try:
                    return float(tok.val)
                except ValueError as e:
                    raise self._errorf(f"invalid number: {tok.val}") from e
        if tok.type == TokenType.IDENT:
            if tok.val == "true":
                return True
            if tok.val == "false":
                return False
            raise self._errorf(f"unexpected identifier {tok.val!r} in value position")
        raise self._errorf(f"expected value, got {tok}")

    def _peek(self) -> Token:
        if self.pos >= len(self.tokens):
            return Token(TokenType.EOF)
        return self.tokens[self.pos]

    def _advance(self) -> Token:
        tok = self._peek()
        if tok.type != TokenType.EOF:
            self.pos += 1
        return tok

    def _check(self, t: TokenType) -> bool:
        return self._peek().type == t

    def _check_ident(self, val: str) -> bool:
        tok = self._peek()
        return tok.type == TokenType.IDENT and tok.val == val

    def _at_end(self) -> bool:
        return self._peek().type == TokenType.EOF

    def _expect(self, t: TokenType) -> Token:
        tok = self._advance()
        if tok.type != t:
            raise self._errorf(f"expected {t.name}, got {tok}")
        return tok

    def _errorf(self, msg: str) -> ParseError:
        tok = self._peek()
        return ParseError(f"line {tok.line} col {tok.col}: {msg}")
