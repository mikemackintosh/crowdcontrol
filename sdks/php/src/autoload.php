<?php

declare(strict_types=1);

// Tiny stdlib-only bootstrap for MikeMackintosh\CrowdControl\*.
// Types.php defines multiple enums and value classes in one file, so we
// eagerly require the whole SDK here instead of relying on PSR-4 lazy
// loading.

require_once __DIR__ . '/Types.php';
require_once __DIR__ . '/Lexer.php';
require_once __DIR__ . '/Parser.php';
require_once __DIR__ . '/Evaluator.php';
require_once __DIR__ . '/Validate.php';
require_once __DIR__ . '/CrowdControl.php';
