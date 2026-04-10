<?php

declare(strict_types=1);

use MikeMackintosh\CrowdControl\CrowdControl;

function eval_policy(string $src, array $doc, string $default = 'allow'): array
{
    $eng = CrowdControl::fromSource([$src], $default);
    return $eng->evaluate($doc);
}

function test_eval_forbid_fires(): void
{
    $r = eval_policy('forbid "r" { x == "y" message "m" }', ['x' => 'y']);
    assert_count(1, $r);
    assert_false($r[0]->passed);
    assert_eq('m', $r[0]->message);
}

function test_eval_forbid_no_fire(): void
{
    $r = eval_policy('forbid "r" { x == "y" message "m" }', ['x' => 'z']);
    assert_true($r[0]->passed);
    assert_eq('', $r[0]->message);
}

function test_eval_unless_saves(): void
{
    $src = 'forbid "r" { x == "a" unless y == "b" message "blocked" }';
    assert_true(eval_policy($src, ['x' => 'a', 'y' => 'b'])[0]->passed);
    assert_false(eval_policy($src, ['x' => 'a', 'y' => 'c'])[0]->passed);
}

function test_eval_has(): void
{
    $r = eval_policy('forbid "r" { has x.y message "m" }', ['x' => ['y' => 1]]);
    assert_false($r[0]->passed);
    $r2 = eval_policy('forbid "r" { has x.y message "m" }', ['x' => []]);
    assert_true($r2[0]->passed);
}

function test_eval_numeric_comparison(): void
{
    $src = 'forbid "r" { size > 100 message "big" }';
    assert_false(eval_policy($src, ['size' => 200])[0]->passed);
    assert_true(eval_policy($src, ['size' => 50])[0]->passed);
}

function test_eval_in_list(): void
{
    $src = 'forbid "r" { t in ["a", "b", "c"] message "x" }';
    assert_false(eval_policy($src, ['t' => 'b'])[0]->passed);
    assert_true(eval_policy($src, ['t' => 'd'])[0]->passed);
}

function test_eval_matches_glob(): void
{
    $src = 'forbid "r" { name matches "prod-*" message "x" }';
    assert_false(eval_policy($src, ['name' => 'prod-api'])[0]->passed);
    assert_true(eval_policy($src, ['name' => 'stg-api'])[0]->passed);
}

function test_eval_matches_regex(): void
{
    $src = 'forbid "r" { v matches_regex "^v[0-9]+$" message "x" }';
    assert_false(eval_policy($src, ['v' => 'v42'])[0]->passed);
    assert_true(eval_policy($src, ['v' => 'release'])[0]->passed);
}

function test_eval_contains_list(): void
{
    $src = 'forbid "r" { tags contains "prod" message "x" }';
    assert_false(eval_policy($src, ['tags' => ['dev', 'prod']])[0]->passed);
    assert_true(eval_policy($src, ['tags' => ['dev']])[0]->passed);
}

function test_eval_intersects(): void
{
    $src = 'forbid "r" { tags intersects ["a", "b"] message "x" }';
    assert_false(eval_policy($src, ['tags' => ['x', 'a']])[0]->passed);
    assert_true(eval_policy($src, ['tags' => ['x', 'y']])[0]->passed);
}

function test_eval_is_subset(): void
{
    $src = 'forbid "r" { not actions is_subset ["read"] message "x" }';
    assert_false(eval_policy($src, ['actions' => ['read', 'write']])[0]->passed);
    assert_true(eval_policy($src, ['actions' => ['read']])[0]->passed);
}

function test_eval_any_quantifier(): void
{
    $src = 'forbid "r" { any ports == 22 message "x" }';
    assert_false(eval_policy($src, ['ports' => [80, 22, 443]])[0]->passed);
    assert_true(eval_policy($src, ['ports' => [80, 443]])[0]->passed);
}

function test_eval_all_quantifier(): void
{
    $src = 'forbid "r" { not all tags matches "prod-*" message "x" }';
    assert_false(eval_policy($src, ['tags' => ['prod-a', 'stg-b']])[0]->passed);
    assert_true(eval_policy($src, ['tags' => ['prod-a', 'prod-b']])[0]->passed);
}

function test_eval_count_aggregate(): void
{
    $src = 'forbid "r" { count(items) > 3 message "x" }';
    assert_false(eval_policy($src, ['items' => [1, 2, 3, 4]])[0]->passed);
    assert_true(eval_policy($src, ['items' => [1]])[0]->passed);
}

function test_eval_arithmetic(): void
{
    $src = 'forbid "r" { a + b > c message "x" }';
    assert_false(eval_policy($src, ['a' => 10, 'b' => 5, 'c' => 12])[0]->passed);
    assert_true(eval_policy($src, ['a' => 1, 'b' => 1, 'c' => 100])[0]->passed);
}

function test_eval_lower_transform(): void
{
    $src = 'forbid "r" { lower(name) == "admin" message "x" }';
    assert_false(eval_policy($src, ['name' => 'ADMIN'])[0]->passed);
}

function test_eval_upper_transform(): void
{
    $src = 'forbid "r" { upper(env) == "PROD" message "x" }';
    assert_false(eval_policy($src, ['env' => 'prod'])[0]->passed);
}

function test_eval_len_transform(): void
{
    $src = 'forbid "r" { len(name) == 0 message "x" }';
    assert_false(eval_policy($src, ['name' => ''])[0]->passed);
}

function test_eval_or_group(): void
{
    $src = 'forbid "r" { x == "a" or x == "b" message "x" }';
    assert_false(eval_policy($src, ['x' => 'b'])[0]->passed);
    assert_true(eval_policy($src, ['x' => 'c'])[0]->passed);
}

function test_eval_message_interpolation(): void
{
    $src = 'forbid "r" { role == "intern" message "{name} is intern" }';
    $r = eval_policy($src, ['role' => 'intern', 'name' => 'alex'])[0];
    assert_eq('alex is intern', $r->message);
}

function test_eval_count_interpolation(): void
{
    $src = 'forbid "r" { count(xs) > 2 message "{count(xs)} items" }';
    $r = eval_policy($src, ['xs' => [1, 2, 3]])[0];
    assert_eq('3 items', $r->message);
}

function test_eval_default_deny_with_permit(): void
{
    $src = 'permit "admins" { role == "admin" message "ok" }';
    $r = eval_policy($src, ['role' => 'admin'], 'deny');
    assert_count(1, $r);
    assert_true($r[0]->passed);
}

function test_eval_default_deny_without_match(): void
{
    $src = 'permit "admins" { role == "admin" message "ok" }';
    $r = eval_policy($src, ['role' => 'user'], 'deny');
    assert_count(2, $r);
    assert_eq('(default-deny)', $r[1]->rule);
    assert_false($r[1]->passed);
}

function test_eval_warn_kind(): void
{
    $src = 'warn "w" { draft == true message "draft pr" }';
    $r = eval_policy($src, ['draft' => true])[0];
    assert_eq('warn', $r->kind);
    assert_false($r->passed);
    assert_eq('draft pr', $r->message);
}

function test_eval_permit_passed_stays_true(): void
{
    $src = 'permit "p" { role == "admin" message "ok" }';
    $r = eval_policy($src, ['role' => 'admin'])[0];
    assert_true($r->passed);
    assert_eq('ok', $r->message);
}

function test_eval_from_directory(): void
{
    $tmp = sys_get_temp_dir() . '/cc-test-' . bin2hex(random_bytes(4));
    mkdir($tmp);
    try {
        file_put_contents($tmp . '/rules.cc', 'forbid "r" { x == "y" message "m" }');
        $eng = CrowdControl::fromDirectory([$tmp]);
        assert_count(1, $eng->policies());
        $r = $eng->evaluate(['x' => 'y']);
        assert_false($r[0]->passed);
    } finally {
        @unlink($tmp . '/rules.cc');
        @rmdir($tmp);
    }
}
