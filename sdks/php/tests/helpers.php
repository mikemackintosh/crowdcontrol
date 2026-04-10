<?php

declare(strict_types=1);

/**
 * Bespoke assertion helpers for the PHP SDK tests.
 *
 * PHP has no stdlib test framework, and PHPUnit would violate the
 * "zero runtime deps" directive. This file + tests/run.php is the
 * entire harness.
 */

final class TestFailure extends \RuntimeException
{
}

function assert_eq(mixed $expected, mixed $actual, string $msg = ''): void
{
    if ($expected !== $actual) {
        $e = var_export($expected, true);
        $a = var_export($actual, true);
        throw new TestFailure(($msg !== '' ? "{$msg}: " : '') . "expected {$e}, got {$a}");
    }
}

function assert_true(bool $cond, string $msg = ''): void
{
    if (!$cond) {
        throw new TestFailure($msg !== '' ? $msg : 'expected true, got false');
    }
}

function assert_false(bool $cond, string $msg = ''): void
{
    if ($cond) {
        throw new TestFailure($msg !== '' ? $msg : 'expected false, got true');
    }
}

function assert_null(mixed $v, string $msg = ''): void
{
    if ($v !== null) {
        $a = var_export($v, true);
        throw new TestFailure(($msg !== '' ? "{$msg}: " : '') . "expected null, got {$a}");
    }
}

function assert_not_null(mixed $v, string $msg = ''): void
{
    if ($v === null) {
        throw new TestFailure($msg !== '' ? $msg : 'expected non-null, got null');
    }
}

function assert_count(int $expected, array $actual, string $msg = ''): void
{
    if (count($actual) !== $expected) {
        throw new TestFailure(($msg !== '' ? "{$msg}: " : '') . "expected count {$expected}, got " . count($actual));
    }
}

function assert_contains(string $needle, string $haystack, string $msg = ''): void
{
    if (!str_contains($haystack, $needle)) {
        throw new TestFailure(($msg !== '' ? "{$msg}: " : '') . "expected '{$haystack}' to contain '{$needle}'");
    }
}

function assert_throws(callable $fn, string $exceptionClass, string $msg = ''): void
{
    try {
        $fn();
    } catch (\Throwable $e) {
        if ($e instanceof $exceptionClass) {
            return;
        }
        throw new TestFailure(($msg !== '' ? "{$msg}: " : '') . "expected {$exceptionClass}, got " . get_class($e) . ": " . $e->getMessage());
    }
    throw new TestFailure($msg !== '' ? $msg : "expected {$exceptionClass}, got no exception");
}
