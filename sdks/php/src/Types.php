<?php

declare(strict_types=1);

namespace MikeMackintosh\CrowdControl;

/**
 * AST, Schema, and Result types for CrowdControl.
 *
 * Mirrors the shape of github.com/mikemackintosh/crowdcontrol/types so that
 * the PHP port produces decisions identical to the Go reference.
 */

enum ConditionType: int
{
    case Field = 0;
    case Aggregate = 1;
    case OrGroup = 2;
    case AnyQ = 3;
    case AllQ = 4;
    case HasCheck = 5;
    case ExprCheck = 6;
}

enum ExprKind: int
{
    case Field = 0;
    case Literal = 1;
    case Count = 2;
    case Len = 3;
    case Binary = 4;
}

enum DefaultEffect: string
{
    case Allow = 'allow';
    case Deny = 'deny';
}

enum FieldType: string
{
    case String = 'string';
    case Number = 'number';
    case Bool = 'bool';
    case ListT = 'list';
    case MapT = 'map';
    case AnyT = 'any';
}

final class Expr
{
    public function __construct(
        public ExprKind $kind = ExprKind::Literal,
        public string $field = '',
        public float $value = 0.0,
        public string $aggTarget = '',
        public string $transform = '',
        public string $op = '',
        public ?Expr $left = null,
        public ?Expr $right = null,
    ) {
    }
}

final class Condition
{
    /**
     * @param list<Condition> $orGroup
     */
    public function __construct(
        public ConditionType $type = ConditionType::Field,
        public bool $negated = false,
        public string $field = '',
        public string $op = '',
        public mixed $value = null,
        public string $transform = '',
        public string $aggregateFunc = '',
        public string $aggregateTarget = '',
        public array $orGroup = [],
        public string $quantifier = '',
        public string $listField = '',
        public ?Condition $predicate = null,
        public ?Expr $leftExpr = null,
        public ?Expr $rightExpr = null,
    ) {
    }
}

final class Rule
{
    /**
     * @param list<Condition> $conditions
     * @param list<Condition> $unlesses
     */
    public function __construct(
        public string $kind = '',
        public string $name = '',
        public array $conditions = [],
        public array $unlesses = [],
        public string $message = '',
        public string $description = '',
        public string $owner = '',
        public string $link = '',
    ) {
    }
}

final class Policy
{
    /**
     * @param list<Rule> $rules
     */
    public function __construct(public array $rules = [])
    {
    }
}

final class ConditionTrace
{
    /**
     * @param list<ConditionTrace> $children
     */
    public function __construct(
        public string $expr = '',
        public bool $result = false,
        public string $actual = '',
        public array $children = [],
    ) {
    }
}

final class RuleTrace
{
    /**
     * @param list<ConditionTrace> $conditions
     * @param list<ConditionTrace> $unlesses
     */
    public function __construct(
        public array $conditions = [],
        public array $unlesses = [],
        public bool $allConditionsMatched = false,
        public bool $savedByUnless = false,
    ) {
    }
}

final class Result
{
    public function __construct(
        public string $rule = '',
        public string $kind = '',
        public bool $passed = true,
        public string $message = '',
        public string $description = '',
        public string $owner = '',
        public string $link = '',
        public ?RuleTrace $trace = null,
    ) {
    }
}

final class Schema
{
    /**
     * @param array<string, string> $fields
     */
    public function __construct(public array $fields = [])
    {
    }
}

final class SchemaWarning
{
    public function __construct(
        public string $rule = '',
        public string $field = '',
        public string $message = '',
    ) {
    }
}
