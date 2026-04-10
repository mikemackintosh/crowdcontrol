<?php

declare(strict_types=1);

namespace MikeMackintosh\CrowdControl;

/**
 * Ports github.com/mikemackintosh/crowdcontrol/parser/parser.go to PHP.
 */

final class ParseException extends \RuntimeException
{
}

final class Parser
{
    /** @var list<Token> */
    private array $tokens;
    private int $pos = 0;

    /**
     * @param list<Token> $tokens
     */
    public function __construct(array $tokens)
    {
        $this->tokens = $tokens;
    }

    public static function parse(string $source): Policy
    {
        try {
            $tokens = Lexer::tokenize($source);
        } catch (LexException $e) {
            throw new ParseException($e->getMessage(), 0, $e);
        }
        return (new self($tokens))->parsePolicy();
    }

    public function parsePolicy(): Policy
    {
        $policy = new Policy();
        while (!$this->atEnd()) {
            $policy->rules[] = $this->parseRule();
        }
        return $policy;
    }

    private function parseRule(): Rule
    {
        $kindTok = $this->advance();
        if ($kindTok->type !== TokenType::Ident) {
            throw $this->errorf("expected forbid, warn, or permit, got {$kindTok}");
        }
        $kind = $kindTok->val;
        if (!in_array($kind, ['forbid', 'warn', 'permit'], true)) {
            throw $this->errorf("expected forbid, warn, or permit, got '{$kind}'");
        }

        $nameTok = $this->advance();
        if ($nameTok->type !== TokenType::StringT) {
            throw $this->errorf("expected rule name string, got {$nameTok}");
        }

        $this->expect(TokenType::LBrace);

        $rule = new Rule(kind: $kind, name: $nameTok->val);

        while (!$this->check(TokenType::RBrace) && !$this->atEnd()) {
            $this->parseClause($rule);
        }

        $this->expect(TokenType::RBrace);
        return $rule;
    }

    private function parseClause(Rule $rule): void
    {
        $tok = $this->peek();
        $val = $tok->val;

        if ($val === 'unless') {
            $this->parseUnless($rule);
            return;
        }
        if ($val === 'message') {
            $this->parseMessage($rule);
            return;
        }
        if (in_array($val, ['description', 'owner', 'link'], true)) {
            $this->parseMetadata($rule, $val);
            return;
        }

        $cond = match ($val) {
            'not' => $this->parseNegatedCondition(),
            'any', 'all' => $this->parseQuantifier(),
            'has' => $this->parseHasCondition(),
            'count' => $this->parseAggregateCondition(),
            'lower', 'upper', 'len' => $this->parseTransformCondition(),
            default => $this->parseFieldCond(),
        };

        $rule->conditions[] = $this->wrapOr($cond);
    }

    private function wrapOr(Condition $first): Condition
    {
        if (!$this->checkIdent('or')) {
            return $first;
        }
        $group = [$first];
        while ($this->checkIdent('or')) {
            $this->advance();
            try {
                $group[] = $this->parseSingleCondition();
            } catch (ParseException) {
                break;
            }
        }
        return new Condition(type: ConditionType::OrGroup, orGroup: $group);
    }

    private function parseSingleCondition(): Condition
    {
        $val = $this->peek()->val;
        return match ($val) {
            'not' => $this->parseNegatedCondition(),
            'any', 'all' => $this->parseQuantifier(),
            'has' => $this->parseHasCondition(),
            'count' => $this->parseAggregateCondition(),
            'lower', 'upper', 'len' => $this->parseTransformCondition(),
            default => $this->parseFieldCond(),
        };
    }

    private function parseNegatedCondition(): Condition
    {
        $this->advance(); // consume "not"
        $cond = $this->parseSingleCondition();
        $cond->negated = !$cond->negated;
        return $cond;
    }

    private function parseHasCondition(): Condition
    {
        $this->advance(); // consume "has"
        $field = $this->parseDottedPath();
        return new Condition(type: ConditionType::HasCheck, field: $field);
    }

    private function parseQuantifier(): Condition
    {
        $quantTok = $this->advance();
        $listField = $this->parseDottedPath();
        $predicate = $this->parseElementPredicate();
        $condType = $quantTok->val === 'all' ? ConditionType::AllQ : ConditionType::AnyQ;
        return new Condition(
            type: $condType,
            quantifier: $quantTok->val,
            listField: $listField,
            predicate: $predicate,
        );
    }

    private function parseElementPredicate(): Condition
    {
        $tok = $this->peek();

        if ($tok->type === TokenType::Ident && $tok->val === 'in') {
            $this->advance();
            $next = $this->peek();
            if ($next->type === TokenType::LBracket) {
                $vals = $this->parseStringList();
                return new Condition(type: ConditionType::Field, op: 'in', value: $vals);
            }
            throw $this->errorf("expected list after 'in', got {$next}");
        }

        if ($tok->type === TokenType::Ident && ($tok->val === 'matches' || $tok->val === 'matches_regex')) {
            $op = $tok->val;
            $this->advance();
            $valTok = $this->advance();
            if ($valTok->type !== TokenType::StringT) {
                throw $this->errorf("{$op} expects a string pattern, got {$valTok}");
            }
            return new Condition(type: ConditionType::Field, op: $op, value: $valTok->val);
        }

        if ($tok->type === TokenType::Ident && $tok->val === 'contains') {
            $this->advance();
            $val = $this->parseValue();
            return new Condition(type: ConditionType::Field, op: 'contains', value: $val);
        }

        $opTok = $this->advance();
        $cmp = [TokenType::Eq, TokenType::Neq, TokenType::Lt, TokenType::Gt, TokenType::Lte, TokenType::Gte];
        if (!in_array($opTok->type, $cmp, true)) {
            throw $this->errorf("expected operator in quantifier predicate, got {$opTok}");
        }
        $val = $this->parseValue();
        return new Condition(type: ConditionType::Field, op: $opTok->val, value: $val);
    }

    private function parseFieldCond(): Condition
    {
        $field = $this->parseDottedPath();

        if ($this->isArithOp()) {
            $left = new Expr(kind: ExprKind::Field, field: $field);
            return $this->parseExprConditionFromLeft($left);
        }

        $opTok = $this->advance();
        $op = $opTok->val;
        $cmp = [TokenType::Eq, TokenType::Neq, TokenType::Lt, TokenType::Gt, TokenType::Lte, TokenType::Gte];

        if (!in_array($opTok->type, $cmp, true)) {
            if ($opTok->type === TokenType::Ident && in_array($opTok->val, ['in', 'matches', 'matches_regex', 'contains', 'intersects', 'is_subset'], true)) {
                $op = $opTok->val;
            } else {
                throw $this->errorf("expected operator, got {$opTok}");
            }
        }

        $cond = new Condition(type: ConditionType::Field, field: $field, op: $op);

        if (in_array($op, ['in', 'intersects', 'is_subset'], true)) {
            $cond->value = $this->parseStringList();
        } elseif ($op === 'matches' || $op === 'matches_regex') {
            $valTok = $this->advance();
            if ($valTok->type !== TokenType::StringT) {
                throw $this->errorf("{$op} expects a string pattern, got {$valTok}");
            }
            $cond->value = $valTok->val;
        } else {
            $cond->value = $this->parseValue();
        }
        return $cond;
    }

    private function isArithOp(): bool
    {
        $t = $this->peek()->type;
        return $t === TokenType::Plus || $t === TokenType::Minus || $t === TokenType::Star || $t === TokenType::Slash;
    }

    private function parseExprConditionFromLeft(Expr $left): Condition
    {
        $expr = $this->parseArithExprFrom($left);

        $opTok = $this->advance();
        $cmp = [TokenType::Eq, TokenType::Neq, TokenType::Lt, TokenType::Gt, TokenType::Lte, TokenType::Gte];
        if (!in_array($opTok->type, $cmp, true)) {
            throw $this->errorf("expected comparison operator in expression, got {$opTok}");
        }

        $right = $this->parseArithExpr();
        return new Condition(
            type: ConditionType::ExprCheck,
            op: $opTok->val,
            leftExpr: $expr,
            rightExpr: $right,
        );
    }

    private function parseArithExpr(): Expr
    {
        $left = $this->parseExprTerm();
        return $this->parseArithExprFrom($left);
    }

    private function parseArithExprFrom(Expr $left): Expr
    {
        while ($this->isArithOp()) {
            $opTok = $this->advance();
            $right = $this->parseExprTerm();
            $left = new Expr(kind: ExprKind::Binary, op: $opTok->val, left: $left, right: $right);
        }
        return $left;
    }

    private function parseExprTerm(): Expr
    {
        $tok = $this->peek();

        if ($tok->type === TokenType::Number) {
            $this->advance();
            if (!is_numeric($tok->val)) {
                throw $this->errorf("invalid number: {$tok->val}");
            }
            return new Expr(kind: ExprKind::Literal, value: (float) $tok->val);
        }

        if ($tok->type === TokenType::Ident && ($tok->val === 'count' || $tok->val === 'len')) {
            $funcName = $tok->val;
            $this->advance();
            $this->expect(TokenType::LParen);
            $path = $this->parseDottedPath();
            $this->expect(TokenType::RParen);
            if ($funcName === 'count') {
                return new Expr(kind: ExprKind::Count, aggTarget: $path);
            }
            return new Expr(kind: ExprKind::Len, field: $path, transform: 'len');
        }

        if ($tok->type === TokenType::Ident) {
            $path = $this->parseDottedPath();
            return new Expr(kind: ExprKind::Field, field: $path);
        }

        throw $this->errorf("expected number, field, count(), or len() in expression, got {$tok}");
    }

    private function parseUnless(Rule $rule): void
    {
        $this->advance(); // consume "unless"
        $val = $this->peek()->val;
        $cond = match ($val) {
            'not' => $this->parseNegatedCondition(),
            'any', 'all' => $this->parseQuantifier(),
            'has' => $this->parseHasCondition(),
            'lower', 'upper', 'len' => $this->parseTransformCondition(),
            'count' => $this->parseAggregateCondition(),
            default => $this->parseFieldCond(),
        };
        $rule->unlesses[] = $cond;
    }

    private function parseTransformCondition(): Condition
    {
        $funcTok = $this->advance();
        $this->expect(TokenType::LParen);
        $field = $this->parseDottedPath();
        $this->expect(TokenType::RParen);

        if ($funcTok->val === 'len' && $this->isArithOp()) {
            $left = new Expr(kind: ExprKind::Len, field: $field, transform: 'len');
            return $this->parseExprConditionFromLeft($left);
        }

        $opTok = $this->advance();
        $op = $opTok->val;
        $cmp = [TokenType::Eq, TokenType::Neq, TokenType::Lt, TokenType::Gt, TokenType::Lte, TokenType::Gte];
        if (!in_array($opTok->type, $cmp, true)) {
            if ($opTok->type === TokenType::Ident && in_array($opTok->val, ['in', 'matches', 'matches_regex', 'contains'], true)) {
                $op = $opTok->val;
            } else {
                throw $this->errorf("expected operator after {$funcTok->val}(), got {$opTok}");
            }
        }

        $cond = new Condition(type: ConditionType::Field, field: $field, op: $op, transform: $funcTok->val);

        if ($op === 'in') {
            $cond->value = $this->parseStringList();
        } elseif ($op === 'matches' || $op === 'matches_regex') {
            $valTok = $this->advance();
            if ($valTok->type !== TokenType::StringT) {
                throw $this->errorf("{$op} expects a string pattern, got {$valTok}");
            }
            $cond->value = $valTok->val;
        } else {
            $cond->value = $this->parseValue();
        }
        return $cond;
    }

    private function parseAggregateCondition(): Condition
    {
        $this->advance(); // consume "count"
        $this->expect(TokenType::LParen);
        $target = $this->parseDottedPath();
        $this->expect(TokenType::RParen);

        if ($this->isArithOp()) {
            $left = new Expr(kind: ExprKind::Count, aggTarget: $target);
            return $this->parseExprConditionFromLeft($left);
        }

        $opTok = $this->advance();
        $cmp = [TokenType::Lt, TokenType::Gt, TokenType::Lte, TokenType::Gte, TokenType::Eq, TokenType::Neq];
        if (!in_array($opTok->type, $cmp, true)) {
            throw $this->errorf("expected comparison operator after count(), got {$opTok}");
        }

        $valTok = $this->advance();
        if ($valTok->type !== TokenType::Number) {
            throw $this->errorf("expected number after operator, got {$valTok}");
        }
        if (!is_numeric($valTok->val)) {
            throw $this->errorf("invalid number: {$valTok->val}");
        }
        $num = (int) $valTok->val;

        return new Condition(
            type: ConditionType::Aggregate,
            aggregateFunc: 'count',
            aggregateTarget: $target,
            op: $opTok->val,
            value: $num,
        );
    }

    private function parseMessage(Rule $rule): void
    {
        $this->advance();
        $msgTok = $this->advance();
        if ($msgTok->type !== TokenType::StringT) {
            throw $this->errorf("expected message string, got {$msgTok}");
        }
        $rule->message = $msgTok->val;
    }

    private function parseMetadata(Rule $rule, string $keyword): void
    {
        $this->advance();
        $valTok = $this->advance();
        if ($valTok->type !== TokenType::StringT) {
            throw $this->errorf("expected string after {$keyword}, got {$valTok}");
        }
        match ($keyword) {
            'description' => $rule->description = $valTok->val,
            'owner' => $rule->owner = $valTok->val,
            'link' => $rule->link = $valTok->val,
            default => null,
        };
    }

    // ----- helpers ---------------------------------------------------------

    private function parseDottedPath(): string
    {
        $tok = $this->advance();
        if ($tok->type !== TokenType::Ident) {
            throw $this->errorf("expected identifier, got {$tok}");
        }
        $parts = [$tok->val];
        while ($this->check(TokenType::Dot)) {
            $this->advance();
            $next = $this->advance();
            if ($next->type !== TokenType::Ident) {
                throw $this->errorf("expected identifier after '.', got {$next}");
            }
            $parts[] = $next->val;
        }
        return implode('.', $parts);
    }

    /**
     * @return list<string>
     */
    private function parseStringList(): array
    {
        $this->expect(TokenType::LBracket);
        $vals = [];
        while (!$this->check(TokenType::RBracket) && !$this->atEnd()) {
            $tok = $this->advance();
            if ($tok->type !== TokenType::StringT) {
                throw $this->errorf("expected string in list, got {$tok}");
            }
            $vals[] = $tok->val;
            if ($this->check(TokenType::Comma)) {
                $this->advance();
            }
        }
        $this->expect(TokenType::RBracket);
        return $vals;
    }

    private function parseValue(): mixed
    {
        $tok = $this->advance();
        return match ($tok->type) {
            TokenType::StringT => $tok->val,
            TokenType::Number => str_contains($tok->val, '.')
                ? (float) $tok->val
                : (int) $tok->val,
            TokenType::Ident => match ($tok->val) {
                'true' => true,
                'false' => false,
                default => throw $this->errorf("unexpected identifier '{$tok->val}' in value position"),
            },
            default => throw $this->errorf("expected value, got {$tok}"),
        };
    }

    private function peek(): Token
    {
        if ($this->pos >= count($this->tokens)) {
            return new Token(TokenType::Eof);
        }
        return $this->tokens[$this->pos];
    }

    private function advance(): Token
    {
        $tok = $this->peek();
        if ($tok->type !== TokenType::Eof) {
            $this->pos++;
        }
        return $tok;
    }

    private function check(TokenType $t): bool
    {
        return $this->peek()->type === $t;
    }

    private function checkIdent(string $val): bool
    {
        $tok = $this->peek();
        return $tok->type === TokenType::Ident && $tok->val === $val;
    }

    private function atEnd(): bool
    {
        return $this->peek()->type === TokenType::Eof;
    }

    private function expect(TokenType $t): Token
    {
        $tok = $this->advance();
        if ($tok->type !== $t) {
            throw $this->errorf("expected {$t->name}, got {$tok}");
        }
        return $tok;
    }

    private function errorf(string $msg): ParseException
    {
        $tok = $this->peek();
        return new ParseException("line {$tok->line} col {$tok->col}: {$msg}");
    }
}
