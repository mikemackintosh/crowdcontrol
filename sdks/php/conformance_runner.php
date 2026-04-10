<?php

declare(strict_types=1);

/**
 * PHP SDK conformance runner.
 *
 * Reads every case file in the shared conformance suite and verifies that
 * the PHP implementation produces identical decisions to the Go reference.
 *
 * Usage:
 *
 *     php conformance_runner.php [SUITE_DIR]
 *     php conformance_runner.php -v        # also print passing cases
 *     php conformance_runner.php -f permit # only run cases matching 'permit'
 */

require_once __DIR__ . '/src/autoload.php';

use MikeMackintosh\CrowdControl\CrowdControl;

$argv = $_SERVER['argv'] ?? [];
array_shift($argv);

$verbose = false;
$filter = '';
$suiteDir = __DIR__ . '/../../conformance/suite';

for ($i = 0; $i < count($argv); $i++) {
    $arg = $argv[$i];
    if ($arg === '-v' || $arg === '--verbose') {
        $verbose = true;
    } elseif ($arg === '-f' || $arg === '--filter') {
        $filter = $argv[++$i] ?? '';
    } else {
        $suiteDir = $arg;
    }
}

if (!is_dir($suiteDir)) {
    fwrite(STDERR, "suite dir not found: {$suiteDir}\n");
    exit(2);
}

$files = glob(rtrim($suiteDir, '/') . '/*.json') ?: [];
sort($files);

if (empty($files)) {
    fwrite(STDERR, "no conformance cases found in {$suiteDir}\n");
    exit(2);
}

$passed = 0;
$failed = 0;

foreach ($files as $path) {
    $raw = file_get_contents($path);
    if ($raw === false) {
        echo "FAIL: " . basename($path) . " — cannot read file\n";
        $failed++;
        continue;
    }
    try {
        $case = json_decode($raw, true, 512, JSON_THROW_ON_ERROR);
    } catch (JsonException $e) {
        echo "FAIL: " . basename($path) . " — parse error: " . $e->getMessage() . "\n";
        $failed++;
        continue;
    }

    $name = $case['name'] ?? basename($path, '.json');
    if ($filter !== '' && !str_contains($name, $filter)) {
        continue;
    }

    [$ok, $msg] = runCase($case);
    if ($ok) {
        $passed++;
        if ($verbose) {
            echo "PASS: {$name}\n";
        }
    } else {
        $failed++;
        echo "FAIL: {$name} — {$msg}\n";
    }
}

echo "\n{$passed} passed, {$failed} failed\n";
exit($failed > 0 ? 1 : 0);

/**
 * @param array<string, mixed> $case
 * @return array{bool, string}
 */
function runCase(array $case): array
{
    $defaultEffect = $case['default_effect'] ?? 'allow';
    if (!in_array($defaultEffect, ['allow', 'deny'], true)) {
        return [false, "unknown default_effect '{$defaultEffect}'"];
    }

    try {
        $engine = CrowdControl::fromSource([$case['policy']], $defaultEffect);
    } catch (\Throwable $e) {
        return [false, "parse error: " . $e->getMessage()];
    }

    $results = $engine->evaluate($case['input'] ?? []);
    $expected = $case['expect']['decisions'] ?? [];

    if (count($results) !== count($expected)) {
        $summary = implode(' ', array_map(
            fn($r) => "[{$r->rule}/{$r->kind} passed=" . ($r->passed ? 'true' : 'false') . ']',
            $results
        ));
        return [false, "expected " . count($expected) . " decisions, got " . count($results) . " (results: {$summary})"];
    }

    foreach ($expected as $i => $want) {
        $got = $results[$i];
        if ($got->rule !== $want['rule']) {
            return [false, "decision[{$i}]: rule = '{$got->rule}', want '{$want['rule']}'"];
        }
        if ($got->kind !== $want['kind']) {
            return [false, "decision[{$i}] ({$got->rule}): kind = '{$got->kind}', want '{$want['kind']}'"];
        }
        if ($got->passed !== $want['passed']) {
            return [false, "decision[{$i}] ({$got->rule}): passed = " . ($got->passed ? 'true' : 'false') . ", want " . ($want['passed'] ? 'true' : 'false')];
        }
        if (isset($want['message_exact']) && $want['message_exact'] !== '' && $got->message !== $want['message_exact']) {
            return [false, "decision[{$i}] ({$got->rule}): message = '{$got->message}', want exact '{$want['message_exact']}'"];
        }
        if (isset($want['message_contains']) && $want['message_contains'] !== '' && !str_contains($got->message, $want['message_contains'])) {
            return [false, "decision[{$i}] ({$got->rule}): message = '{$got->message}', want contains '{$want['message_contains']}'"];
        }
    }

    return [true, ''];
}
