<?php

declare(strict_types=1);

/**
 * Tiny test runner — discovers every tests/*_test.php file, runs every
 * function named `test_*` inside, and tallies results.
 */

require_once __DIR__ . '/../src/autoload.php';
require_once __DIR__ . '/helpers.php';

$files = glob(__DIR__ . '/*_test.php') ?: [];
sort($files);

$passed = 0;
$failed = 0;
$errors = [];

foreach ($files as $file) {
    $before = get_defined_functions()['user'];
    require_once $file;
    $after = get_defined_functions()['user'];
    $new = array_diff($after, $before);

    $tests = array_values(array_filter($new, static fn(string $fn) => str_starts_with($fn, 'test_')));
    sort($tests);

    $label = basename($file);
    echo "=== {$label} ===\n";
    foreach ($tests as $test) {
        try {
            $test();
            $passed++;
            echo "  PASS: {$test}\n";
        } catch (\Throwable $e) {
            $failed++;
            $errors[] = "{$label}::{$test} — " . $e->getMessage();
            echo "  FAIL: {$test} — " . $e->getMessage() . "\n";
        }
    }
}

echo "\n{$passed} passed, {$failed} failed\n";
if ($failed > 0) {
    echo "\nFailures:\n";
    foreach ($errors as $err) {
        echo "  {$err}\n";
    }
    exit(1);
}
exit(0);
