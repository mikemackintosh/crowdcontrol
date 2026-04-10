<?php

declare(strict_types=1);

use MikeMackintosh\CrowdControl\CrowdControl;
use MikeMackintosh\CrowdControl\Schema;
use MikeMackintosh\CrowdControl\Validate;

function test_validate_unknown_field(): void
{
    $policies = [CrowdControl::parse('forbid "r" { unknown.field == "x" }')];
    $schema = new Schema(['resource.type' => 'string']);
    $warnings = Validate::validatePolicies($policies, $schema);
    $found = false;
    foreach ($warnings as $w) {
        if ($w->field === 'unknown.field') {
            $found = true;
        }
    }
    assert_true($found, 'expected warning for unknown.field');
}

function test_validate_known_field_no_warning(): void
{
    $policies = [CrowdControl::parse('forbid "r" { resource.type == "x" }')];
    $schema = new Schema(['resource.type' => 'string']);
    $warnings = Validate::validatePolicies($policies, $schema);
    assert_count(0, $warnings);
}

function test_validate_operator_mismatch(): void
{
    $policies = [CrowdControl::parse('forbid "r" { user.name < 5 }')];
    $schema = new Schema(['user.name' => 'string']);
    $warnings = Validate::validatePolicies($policies, $schema);
    $found = false;
    foreach ($warnings as $w) {
        if (str_contains($w->message, '<')) {
            $found = true;
        }
    }
    assert_true($found);
}

function test_validate_count_on_string(): void
{
    $policies = [CrowdControl::parse('forbid "r" { count(x) > 3 }')];
    $schema = new Schema(['x' => 'string']);
    $warnings = Validate::validatePolicies($policies, $schema);
    $found = false;
    foreach ($warnings as $w) {
        if (str_contains($w->message, 'count')) {
            $found = true;
        }
    }
    assert_true($found);
}

function test_validate_interpolation_unknown_field(): void
{
    $src = 'forbid "r" { y == "x" message "hi {user.name}" }';
    $policies = [CrowdControl::parse($src)];
    $schema = new Schema(['y' => 'string']);
    $warnings = Validate::validatePolicies($policies, $schema);
    $found = false;
    foreach ($warnings as $w) {
        if ($w->field === 'user.name') {
            $found = true;
        }
    }
    assert_true($found);
}
