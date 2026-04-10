<?php

declare(strict_types=1);

use MikeMackintosh\CrowdControl\ConditionType;
use MikeMackintosh\CrowdControl\CrowdControl;
use MikeMackintosh\CrowdControl\ExprKind;
use MikeMackintosh\CrowdControl\ParseException;

function test_parser_empty_policy(): void
{
    $p = CrowdControl::parse('');
    assert_count(0, $p->rules);
}

function test_parser_simple_forbid(): void
{
    $p = CrowdControl::parse('forbid "r" { x.y == "z" message "m" }');
    assert_count(1, $p->rules);
    $r = $p->rules[0];
    assert_eq('forbid', $r->kind);
    assert_eq('r', $r->name);
    assert_eq('m', $r->message);
    assert_count(1, $r->conditions);
    $c = $r->conditions[0];
    assert_eq(ConditionType::Field, $c->type);
    assert_eq('x.y', $c->field);
    assert_eq('==', $c->op);
    assert_eq('z', $c->value);
}

function test_parser_warn_and_permit(): void
{
    $p = CrowdControl::parse('warn "w" { a == 1 } permit "p" { b == 2 }');
    assert_count(2, $p->rules);
    assert_eq('warn', $p->rules[0]->kind);
    assert_eq('permit', $p->rules[1]->kind);
}

function test_parser_metadata(): void
{
    $p = CrowdControl::parse('forbid "r" { description "d" owner "o" link "l" x == "y" }');
    assert_eq('d', $p->rules[0]->description);
    assert_eq('o', $p->rules[0]->owner);
    assert_eq('l', $p->rules[0]->link);
}

function test_parser_unless(): void
{
    $p = CrowdControl::parse('forbid "r" { x == "a" unless y == "b" }');
    assert_count(1, $p->rules[0]->conditions);
    assert_count(1, $p->rules[0]->unlesses);
}

function test_parser_has(): void
{
    $p = CrowdControl::parse('forbid "r" { has foo.bar }');
    $c = $p->rules[0]->conditions[0];
    assert_eq(ConditionType::HasCheck, $c->type);
    assert_eq('foo.bar', $c->field);
}

function test_parser_not_negation(): void
{
    $p = CrowdControl::parse('forbid "r" { not x == "y" }');
    $c = $p->rules[0]->conditions[0];
    assert_true($c->negated);
}

function test_parser_any_quantifier(): void
{
    $p = CrowdControl::parse('forbid "r" { any tags == "prod" }');
    $c = $p->rules[0]->conditions[0];
    assert_eq(ConditionType::AnyQ, $c->type);
    assert_eq('tags', $c->listField);
    assert_not_null($c->predicate);
}

function test_parser_all_quantifier(): void
{
    $p = CrowdControl::parse('forbid "r" { all ports < 1024 }');
    $c = $p->rules[0]->conditions[0];
    assert_eq(ConditionType::AllQ, $c->type);
}

function test_parser_count_aggregate(): void
{
    $p = CrowdControl::parse('forbid "r" { count(items) > 5 }');
    $c = $p->rules[0]->conditions[0];
    assert_eq(ConditionType::Aggregate, $c->type);
    assert_eq('items', $c->aggregateTarget);
    assert_eq('>', $c->op);
    assert_eq(5, $c->value);
}

function test_parser_in_list(): void
{
    $p = CrowdControl::parse('forbid "r" { x in ["a", "b", "c"] }');
    $c = $p->rules[0]->conditions[0];
    assert_eq('in', $c->op);
    assert_eq(['a', 'b', 'c'], $c->value);
}

function test_parser_matches(): void
{
    $p = CrowdControl::parse('forbid "r" { name matches "foo-*" }');
    assert_eq('matches', $p->rules[0]->conditions[0]->op);
}

function test_parser_matches_regex(): void
{
    $p = CrowdControl::parse('forbid "r" { name matches_regex "^v[0-9]+$" }');
    assert_eq('matches_regex', $p->rules[0]->conditions[0]->op);
}

function test_parser_transforms(): void
{
    foreach (['lower', 'upper', 'len'] as $tr) {
        $p = CrowdControl::parse("forbid \"r\" { {$tr}(x.y) == \"z\" }");
        assert_eq($tr, $p->rules[0]->conditions[0]->transform);
    }
}

function test_parser_arithmetic(): void
{
    $p = CrowdControl::parse('forbid "r" { a + b > c }');
    $c = $p->rules[0]->conditions[0];
    assert_eq(ConditionType::ExprCheck, $c->type);
    assert_eq('>', $c->op);
    assert_not_null($c->leftExpr);
    assert_eq(ExprKind::Binary, $c->leftExpr->kind);
}

function test_parser_or_group(): void
{
    $p = CrowdControl::parse('forbid "r" { a == 1 or b == 2 or c == 3 }');
    $c = $p->rules[0]->conditions[0];
    assert_eq(ConditionType::OrGroup, $c->type);
    assert_count(3, $c->orGroup);
}

function test_parser_error_missing_brace(): void
{
    assert_throws(static fn() => CrowdControl::parse('forbid "r" x == "y"'), ParseException::class);
}

function test_parser_error_bad_kind(): void
{
    assert_throws(static fn() => CrowdControl::parse('deny "r" { x == "y" }'), ParseException::class);
}

function test_parser_booleans(): void
{
    $p = CrowdControl::parse('forbid "r" { x == true }');
    assert_true($p->rules[0]->conditions[0]->value);
}

function test_parser_numeric_value(): void
{
    $p = CrowdControl::parse('forbid "r" { x == 42 }');
    assert_eq(42, $p->rules[0]->conditions[0]->value);
}

function test_parser_contains(): void
{
    $p = CrowdControl::parse('forbid "r" { tags contains "prod" }');
    assert_eq('contains', $p->rules[0]->conditions[0]->op);
    assert_eq('prod', $p->rules[0]->conditions[0]->value);
}

function test_parser_intersects(): void
{
    $p = CrowdControl::parse('forbid "r" { tags intersects ["a", "b"] }');
    assert_eq('intersects', $p->rules[0]->conditions[0]->op);
    assert_eq(['a', 'b'], $p->rules[0]->conditions[0]->value);
}
