<?php

declare(strict_types=1);

namespace MikeMackintosh\CrowdControl;

/**
 * Ports github.com/mikemackintosh/crowdcontrol/evaluator/evaluator.go to PHP.
 */

final class Engine
{
    /** @var list<Policy> */
    private array $policies;
    private DefaultEffect $defaultEffect;
    private bool $explain;

    /**
     * @param list<Policy> $policies
     */
    public function __construct(array $policies = [], DefaultEffect $defaultEffect = DefaultEffect::Allow, bool $explain = false)
    {
        $this->policies = $policies;
        $this->defaultEffect = $defaultEffect;
        $this->explain = $explain;
    }

    /**
     * @return list<Policy>
     */
    public function policies(): array
    {
        return $this->policies;
    }

    /**
     * @param array<string, mixed> $doc
     * @return list<Result>
     */
    public function evaluate(array $doc): array
    {
        $results = [];
        $permitFired = false;
        $forbidFired = false;

        foreach ($this->policies as $policy) {
            foreach ($policy->rules as $rule) {
                $r = $this->evalRule($rule, $doc);
                $results[] = $r;
                if ($r->kind === 'permit' && $r->message !== '') {
                    $permitFired = true;
                }
                if ($r->kind === 'forbid' && !$r->passed) {
                    $forbidFired = true;
                }
            }
        }

        if ($this->defaultEffect === DefaultEffect::Deny && !$permitFired && !$forbidFired) {
            $results[] = new Result(
                rule: '(default-deny)',
                kind: 'forbid',
                passed: false,
                message: 'no permit rule matched — denied by default',
            );
        }

        return $results;
    }

    /**
     * @param array<string, mixed> $doc
     */
    private function evalRule(Rule $rule, array $doc): Result
    {
        $result = new Result(
            rule: $rule->name,
            kind: $rule->kind,
            passed: true,
            description: $rule->description,
            owner: $rule->owner,
            link: $rule->link,
        );

        $trace = $this->explain ? new RuleTrace() : null;

        $allMatch = true;
        foreach ($rule->conditions as $cond) {
            $matched = Evaluator::evalCondition($cond, $doc);
            if ($trace !== null) {
                $trace->conditions[] = Evaluator::traceCondition($cond, $doc, $matched);
            }
            if (!$matched) {
                $allMatch = false;
                if ($trace === null) {
                    break;
                }
            }
        }

        if ($trace !== null) {
            $trace->allConditionsMatched = $allMatch;
        }

        if (!$allMatch) {
            if ($trace !== null) {
                $result->trace = $trace;
            }
            return $result;
        }

        $saved = false;
        foreach ($rule->unlesses as $u) {
            $matched = Evaluator::evalCondition($u, $doc);
            if ($trace !== null) {
                $trace->unlesses[] = Evaluator::traceCondition($u, $doc, $matched);
            }
            if ($matched) {
                $saved = true;
                if ($trace === null) {
                    break;
                }
            }
        }

        if ($trace !== null) {
            $trace->savedByUnless = $saved;
        }

        if ($saved) {
            if ($trace !== null) {
                $result->trace = $trace;
            }
            return $result;
        }

        if ($rule->kind === 'permit') {
            $result->passed = true;
            $result->message = Evaluator::interpolateMessage($rule->message, $doc);
        } else {
            $result->passed = false;
            $result->message = Evaluator::interpolateMessage($rule->message, $doc);
        }

        if ($trace !== null) {
            $result->trace = $trace;
        }
        return $result;
    }

    /**
     * @return list<SchemaWarning>
     */
    public function validate(Schema $schema): array
    {
        return Validate::validatePolicies($this->policies, $schema);
    }
}

final class Evaluator
{
    public const POLICY_EXT = '.cc';

    /**
     * @param array<string, mixed> $doc
     */
    public static function evalCondition(Condition $cond, array $doc): bool
    {
        $result = self::evalConditionInner($cond, $doc);
        return $cond->negated ? !$result : $result;
    }

    /**
     * @param array<string, mixed> $doc
     */
    private static function evalConditionInner(Condition $cond, array $doc): bool
    {
        return match ($cond->type) {
            ConditionType::Aggregate => self::evalAggregate($cond, $doc),
            ConditionType::Field => self::evalFieldCondition($cond, $doc),
            ConditionType::OrGroup => (function () use ($cond, $doc) {
                foreach ($cond->orGroup as $sub) {
                    if (self::evalCondition($sub, $doc)) {
                        return true;
                    }
                }
                return false;
            })(),
            ConditionType::AnyQ => self::evalQuantifier($cond, $doc, false),
            ConditionType::AllQ => self::evalQuantifier($cond, $doc, true),
            ConditionType::HasCheck => self::resolveField($cond->field, $doc) !== null,
            ConditionType::ExprCheck => self::evalExprCondition($cond, $doc),
        };
    }

    /**
     * @param array<string, mixed> $doc
     */
    private static function evalQuantifier(Condition $cond, array $doc, bool $requireAll): bool
    {
        $val = self::resolveField($cond->listField, $doc);
        $items = self::toList($val);
        if ($items === null) {
            return $requireAll;
        }
        if (count($items) === 0) {
            return $requireAll;
        }
        if ($cond->predicate === null) {
            return false;
        }
        foreach ($items as $item) {
            $matched = self::evalElementPredicate($cond->predicate, $doc, $item);
            if ($requireAll && !$matched) {
                return false;
            }
            if (!$requireAll && $matched) {
                return true;
            }
        }
        return $requireAll;
    }

    /**
     * @param array<string, mixed> $doc
     */
    private static function evalElementPredicate(Condition $pred, array $doc, mixed $element): bool
    {
        $elemStr = self::fmtV($element);

        if ($pred->type !== ConditionType::Field) {
            return false;
        }

        switch ($pred->op) {
            case '==':
                return $elemStr === self::fmtV($pred->value);
            case '!=':
                return $elemStr !== self::fmtV($pred->value);
            case 'in':
                if (!is_array($pred->value)) {
                    return false;
                }
                return in_array($elemStr, $pred->value, true);
            case 'matches':
                if (!is_string($pred->value)) {
                    return false;
                }
                return self::globMatch($pred->value, $elemStr);
            case 'matches_regex':
                if (!is_string($pred->value)) {
                    return false;
                }
                return self::regexMatch($pred->value, $elemStr);
            case 'contains':
                return self::evalContains($element, $pred->value);
            default:
                return self::compareValues($element, $pred->op, $pred->value);
        }
    }

    /**
     * @param array<string, mixed> $doc
     */
    private static function evalExprCondition(Condition $cond, array $doc): bool
    {
        if ($cond->leftExpr === null || $cond->rightExpr === null) {
            return false;
        }
        [$left, $lok] = self::evalExpr($cond->leftExpr, $doc);
        [$right, $rok] = self::evalExpr($cond->rightExpr, $doc);
        if (!$lok || !$rok) {
            return false;
        }
        return self::compareFloats($left, $cond->op, $right);
    }

    /**
     * @param array<string, mixed> $doc
     * @return array{float, bool}
     */
    private static function evalExpr(Expr $expr, array $doc): array
    {
        switch ($expr->kind) {
            case ExprKind::Literal:
                return [$expr->value, true];
            case ExprKind::Field:
                $val = self::resolveField($expr->field, $doc);
                $f = self::toFloat($val);
                if ($f === null) {
                    return [0.0, false];
                }
                return [$f, true];
            case ExprKind::Count:
                $val = self::resolveField($expr->aggTarget, $doc);
                if (is_array($val) && array_is_list($val)) {
                    return [(float) count($val), true];
                }
                if (is_int($val) || is_float($val)) {
                    return [(float) $val, true];
                }
                return [0.0, false];
            case ExprKind::Len:
                $val = self::resolveField($expr->field, $doc);
                if (is_string($val)) {
                    return [(float) strlen($val), true];
                }
                if (is_array($val)) {
                    return [(float) count($val), true];
                }
                if ($val === null) {
                    return [0.0, true];
                }
                return [0.0, false];
            case ExprKind::Binary:
                if ($expr->left === null || $expr->right === null) {
                    return [0.0, false];
                }
                [$l, $lok] = self::evalExpr($expr->left, $doc);
                [$r, $rok] = self::evalExpr($expr->right, $doc);
                if (!$lok || !$rok) {
                    return [0.0, false];
                }
                switch ($expr->op) {
                    case '+': return [$l + $r, true];
                    case '-': return [$l - $r, true];
                    case '*': return [$l * $r, true];
                    case '/':
                        if ($r === 0.0) {
                            return [0.0, false];
                        }
                        return [$l / $r, true];
                }
        }
        return [0.0, false];
    }

    /**
     * @param array<string, mixed> $doc
     */
    private static function evalAggregate(Condition $cond, array $doc): bool
    {
        $val = self::resolveField($cond->aggregateTarget, $doc);
        if (is_array($val) && array_is_list($val)) {
            $count = count($val);
        } elseif (is_int($val) || is_float($val)) {
            $count = (int) $val;
        } else {
            return false;
        }
        if (!is_int($cond->value)) {
            return false;
        }
        return self::compareInts($count, $cond->op, $cond->value);
    }

    /**
     * @param array<string, mixed> $doc
     */
    private static function evalFieldCondition(Condition $cond, array $doc): bool
    {
        $val = self::resolveField($cond->field, $doc);
        if ($cond->transform !== '') {
            $val = self::applyTransform($cond->transform, $val);
        }

        switch ($cond->op) {
            case '==':
                return self::fmtV($val) === self::fmtV($cond->value);
            case '!=':
                return self::fmtV($val) !== self::fmtV($cond->value);
            case '<':
            case '>':
            case '<=':
            case '>=':
                return self::compareValues($val, $cond->op, $cond->value);
            case 'in':
                if (!is_array($cond->value)) {
                    return false;
                }
                $s = self::fmtV($val);
                return in_array($s, $cond->value, true);
            case 'matches':
                if (!is_string($cond->value)) {
                    return false;
                }
                return self::globMatch($cond->value, self::fmtV($val));
            case 'matches_regex':
                if (!is_string($cond->value)) {
                    return false;
                }
                return self::regexMatch($cond->value, self::fmtV($val));
            case 'contains':
                return self::evalContains($val, $cond->value);
            case 'intersects':
                return self::evalIntersects($val, $cond->value);
            case 'is_subset':
                return self::evalIsSubset($val, $cond->value);
        }
        return false;
    }

    private static function evalContains(mixed $val, mixed $target): bool
    {
        $targetStr = self::fmtV($target);
        if (is_array($val) && array_is_list($val)) {
            foreach ($val as $item) {
                if (self::fmtV($item) === $targetStr) {
                    return true;
                }
            }
            return false;
        }
        if (is_string($val)) {
            return str_contains($val, $targetStr);
        }
        return false;
    }

    private static function evalIntersects(mixed $val, mixed $target): bool
    {
        if (!is_array($target)) {
            return false;
        }
        if (!is_array($val) || !array_is_list($val)) {
            return false;
        }
        foreach ($val as $item) {
            if (in_array(self::fmtV($item), $target, true)) {
                return true;
            }
        }
        return false;
    }

    private static function evalIsSubset(mixed $val, mixed $target): bool
    {
        if (!is_array($target)) {
            return false;
        }
        if (!is_array($val) || !array_is_list($val)) {
            return false;
        }
        if (count($val) === 0) {
            return true;
        }
        foreach ($val as $item) {
            if (!in_array(self::fmtV($item), $target, true)) {
                return false;
            }
        }
        return true;
    }

    /**
     * @param array<string, mixed> $doc
     */
    public static function resolveField(string $path, array $doc): mixed
    {
        $current = $doc;
        foreach (explode('.', $path) as $part) {
            if (is_array($current) && !array_is_list($current) && array_key_exists($part, $current)) {
                $current = $current[$part];
            } elseif (is_array($current) && count($current) === 0) {
                return null;
            } else {
                return null;
            }
        }
        return $current;
    }

    /**
     * @return list<mixed>|null
     */
    private static function toList(mixed $v): ?array
    {
        if (is_array($v) && array_is_list($v)) {
            return $v;
        }
        return null;
    }

    private static function toFloat(mixed $v): ?float
    {
        if (is_bool($v)) {
            return null;
        }
        if (is_int($v) || is_float($v)) {
            return (float) $v;
        }
        return null;
    }

    private static function compareInts(int $a, string $op, int $b): bool
    {
        return self::compareFloats((float) $a, $op, (float) $b);
    }

    private static function compareValues(mixed $a, string $op, mixed $b): bool
    {
        $af = self::toFloat($a);
        $bf = self::toFloat($b);
        if ($af !== null && $bf !== null) {
            return self::compareFloats($af, $op, $bf);
        }
        return false;
    }

    private static function compareFloats(float $a, string $op, float $b): bool
    {
        return match ($op) {
            '<' => $a < $b,
            '>' => $a > $b,
            '<=' => $a <= $b,
            '>=' => $a >= $b,
            '==' => $a === $b,
            '!=' => $a !== $b,
            default => false,
        };
    }

    private static function applyTransform(string $transform, mixed $val): mixed
    {
        switch ($transform) {
            case 'lower':
                if (is_string($val)) {
                    return strtolower($val);
                }
                return strtolower(self::fmtV($val));
            case 'upper':
                if (is_string($val)) {
                    return strtoupper($val);
                }
                return strtoupper(self::fmtV($val));
            case 'len':
                if (is_string($val)) {
                    return strlen($val);
                }
                if (is_array($val)) {
                    return count($val);
                }
                if ($val === null) {
                    return 0;
                }
                return 0;
        }
        return $val;
    }

    private static function globMatch(string $pattern, string $s): bool
    {
        if ($pattern === '*') {
            return true;
        }
        $startsWithStar = str_starts_with($pattern, '*');
        $endsWithStar = str_ends_with($pattern, '*');
        if ($endsWithStar && !$startsWithStar) {
            $prefix = substr($pattern, 0, -1);
            return str_starts_with($s, $prefix);
        }
        if ($startsWithStar && !$endsWithStar) {
            $suffix = substr($pattern, 1);
            return str_ends_with($s, $suffix);
        }
        $star = strpos($pattern, '*');
        if ($star !== false) {
            $prefix = substr($pattern, 0, $star);
            $suffix = substr($pattern, $star + 1);
            return str_starts_with($s, $prefix) && str_ends_with($s, $suffix);
        }
        return $pattern === $s;
    }

    /** @var array<string, string|null> */
    private static array $regexCache = [];

    private static function regexMatch(string $pattern, string $s): bool
    {
        if (!array_key_exists($pattern, self::$regexCache)) {
            // Use # as delimiter and escape any literal # in the pattern.
            $escaped = str_replace('#', '\\#', $pattern);
            $delim = '#' . $escaped . '#';
            // Test-compile so invalid patterns become null (match false).
            $ok = @preg_match($delim, '');
            self::$regexCache[$pattern] = $ok !== false ? $delim : null;
        }
        $delim = self::$regexCache[$pattern];
        if ($delim === null) {
            return false;
        }
        return (bool) @preg_match($delim, $s);
    }

    /**
     * Go-style %v formatting. Must match the Python/TypeScript ports so that
     * conformance stays identical.
     */
    public static function fmtV(mixed $v): string
    {
        if ($v === null) {
            return '<nil>';
        }
        if (is_bool($v)) {
            return $v ? 'true' : 'false';
        }
        if (is_float($v)) {
            if ($v === floor($v) && !is_infinite($v) && $v >= PHP_INT_MIN && $v <= PHP_INT_MAX) {
                return (string) (int) $v;
            }
            return (string) $v;
        }
        if (is_int($v)) {
            return (string) $v;
        }
        if (is_string($v)) {
            return $v;
        }
        if (is_array($v)) {
            return implode(' ', array_map(fn($x) => self::fmtV($x), $v));
        }
        return (string) $v;
    }

    /**
     * @param array<string, mixed> $doc
     */
    public static function interpolateMessage(string $msg, array $doc): string
    {
        if ($msg === '') {
            return 'policy violation';
        }
        $result = preg_replace_callback('/\{([^}]+)\}/', function ($match) use ($doc) {
            $expr = $match[1];
            if (str_starts_with($expr, 'count(') && str_ends_with($expr, ')')) {
                $target = substr($expr, 6, -1);
                $val = self::resolveField($target, $doc);
                if (is_array($val) && array_is_list($val)) {
                    return (string) count($val);
                }
                if (is_int($val) || is_float($val)) {
                    return (string) (int) $val;
                }
                return $match[0];
            }
            $val = self::resolveField($expr, $doc);
            if ($val === null) {
                return $match[0];
            }
            return self::fmtV($val);
        }, $msg);
        return $result ?? $msg;
    }

    public static function traceCondition(Condition $cond, array $doc, bool $result): ConditionTrace
    {
        $ct = new ConditionTrace(
            expr: self::conditionExpr($cond),
            result: $result,
            actual: self::resolveActual($cond, $doc),
        );
        if ($cond->type === ConditionType::OrGroup) {
            foreach ($cond->orGroup as $sub) {
                $sr = self::evalCondition($sub, $doc);
                $ct->children[] = self::traceCondition($sub, $doc, $sr);
            }
        }
        return $ct;
    }

    private static function conditionExpr(Condition $cond): string
    {
        $prefix = $cond->negated ? 'not ' : '';
        return match ($cond->type) {
            ConditionType::Field => (function () use ($cond, $prefix) {
                $field = $cond->field;
                if ($cond->transform !== '') {
                    $field = "{$cond->transform}({$cond->field})";
                }
                return "{$prefix}{$field} {$cond->op} " . self::formatValue($cond->value);
            })(),
            ConditionType::Aggregate => "{$prefix}count({$cond->aggregateTarget}) {$cond->op} " . self::fmtV($cond->value),
            ConditionType::HasCheck => "{$prefix}has {$cond->field}",
            ConditionType::AnyQ => $cond->predicate !== null
                ? "{$prefix}any {$cond->listField} {$cond->predicate->op} " . self::formatValue($cond->predicate->value)
                : "{$prefix}any {$cond->listField} <predicate>",
            ConditionType::AllQ => $cond->predicate !== null
                ? "{$prefix}all {$cond->listField} {$cond->predicate->op} " . self::formatValue($cond->predicate->value)
                : "{$prefix}all {$cond->listField} <predicate>",
            ConditionType::OrGroup => $prefix . implode(' or ', array_map([self::class, 'conditionExpr'], $cond->orGroup)),
            ConditionType::ExprCheck => (function () use ($cond, $prefix) {
                return "{$prefix}" . self::exprString($cond->leftExpr) . " {$cond->op} " . self::exprString($cond->rightExpr);
            })(),
        };
    }

    private static function exprString(?Expr $expr): string
    {
        if ($expr === null) {
            return '<nil>';
        }
        return match ($expr->kind) {
            ExprKind::Field => $expr->field,
            ExprKind::Literal => $expr->value == (int) $expr->value
                ? (string) (int) $expr->value
                : (string) $expr->value,
            ExprKind::Count => "count({$expr->aggTarget})",
            ExprKind::Len => "len({$expr->field})",
            ExprKind::Binary => self::exprString($expr->left) . " {$expr->op} " . self::exprString($expr->right),
        };
    }

    private static function resolveActual(Condition $cond, array $doc): string
    {
        return match ($cond->type) {
            ConditionType::Field => self::formatActual(self::resolveField($cond->field, $doc)),
            ConditionType::Aggregate => (function () use ($cond, $doc) {
                $val = self::resolveField($cond->aggregateTarget, $doc);
                if (is_array($val) && array_is_list($val)) {
                    return (string) count($val);
                }
                if (is_int($val) || is_float($val)) {
                    return (string) (int) $val;
                }
                return '<nil>';
            })(),
            ConditionType::HasCheck => self::resolveField($cond->field, $doc) !== null ? 'exists' : '<nil>',
            ConditionType::AnyQ, ConditionType::AllQ => (function () use ($cond, $doc) {
                $val = self::resolveField($cond->listField, $doc);
                if (!is_array($val) || !array_is_list($val)) {
                    return '<nil>';
                }
                return '[' . count($val) . ' items]';
            })(),
            ConditionType::ExprCheck => '',
            ConditionType::OrGroup => '',
        };
    }

    private static function formatValue(mixed $v): string
    {
        if (is_string($v)) {
            return '"' . $v . '"';
        }
        if (is_array($v)) {
            $parts = array_map(fn($x) => is_string($x) ? '"' . $x . '"' : self::fmtV($x), $v);
            return '[' . implode(', ', $parts) . ']';
        }
        return self::fmtV($v);
    }

    private static function formatActual(mixed $v): string
    {
        if ($v === null) {
            return '<nil>';
        }
        if (is_array($v) && array_is_list($v)) {
            if (count($v) <= 5) {
                return '[' . implode(', ', array_map([self::class, 'fmtV'], $v)) . ']';
            }
            return '[' . count($v) . ' items]';
        }
        if (is_string($v)) {
            return '"' . $v . '"';
        }
        return self::fmtV($v);
    }

    /**
     * @param list<Result> $results
     * @return array{string, bool}
     */
    public static function formatResults(array $results): array
    {
        $allPassed = true;
        $lines = [];
        foreach ($results as $r) {
            if ($r->passed) {
                continue;
            }
            $prefix = 'DENY';
            if ($r->kind === 'warn') {
                $prefix = 'WARN';
            } else {
                $allPassed = false;
            }
            $line = "{$prefix}: {$r->message} ({$r->rule})";
            $meta = [];
            if ($r->owner !== '') {
                $meta[] = "owner: {$r->owner}";
            }
            if ($r->link !== '') {
                $meta[] = "link: {$r->link}";
            }
            if (!empty($meta)) {
                $line .= ' [' . implode(', ', $meta) . ']';
            }
            $lines[] = $line;
        }
        if ($allPassed) {
            $passed = 0;
            foreach ($results as $r) {
                if ($r->passed) {
                    $passed++;
                }
            }
            $lines[] = "PASS: {$passed} rules evaluated, all passed";
        }
        return [implode("\n", $lines) . (empty($lines) ? '' : "\n"), $allPassed];
    }
}
