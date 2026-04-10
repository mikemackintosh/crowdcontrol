<?php

declare(strict_types=1);

/**
 * Demo: load an in-memory CrowdControl policy and evaluate it.
 *
 * Run with:
 *     php examples/demo.php
 */

require_once __DIR__ . '/../src/autoload.php';

use MikeMackintosh\CrowdControl\CrowdControl;
use MikeMackintosh\CrowdControl\Evaluator;

$policy = <<<'CC'
forbid "no-prod-deletes-by-interns" {
    description "Interns may not delete production resources"
    owner       "platform-security"

    user.role == "intern"
    request.action == "delete"
    resource.environment == "production"

    message "{user.name} is an intern and cannot delete production resources"
}

warn "large-changeset" {
    count(plan.changes) > 5
    message "this change touches {count(plan.changes)} resources"
}

permit "emergency-override" {
    user.groups contains "oncall"
    request.labels contains "emergency"
    message "approved as emergency override"
}
CC;

$input = [
    'user' => [
        'name' => 'alex',
        'role' => 'intern',
        'groups' => ['dev'],
    ],
    'request' => [
        'action' => 'delete',
        'labels' => ['bugfix'],
    ],
    'resource' => [
        'environment' => 'production',
    ],
    'plan' => [
        'changes' => [1, 2, 3, 4, 5, 6, 7],
    ],
];

$engine = CrowdControl::fromSource([$policy]);
$results = $engine->evaluate($input);

echo "Input:\n";
echo json_encode($input, JSON_PRETTY_PRINT) . "\n\n";

echo "Decisions:\n";
foreach ($results as $r) {
    $tag = $r->passed ? 'PASS' : ($r->kind === 'warn' ? 'WARN' : 'DENY');
    $msg = $r->message !== '' ? ": {$r->message}" : '';
    echo "  [{$tag}] {$r->rule} ({$r->kind}){$msg}\n";
}

[$output, $allPassed] = Evaluator::formatResults($results);
echo "\nSummary:\n{$output}";

exit($allPassed ? 0 : 1);
