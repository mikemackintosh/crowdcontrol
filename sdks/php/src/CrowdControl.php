<?php

declare(strict_types=1);

namespace MikeMackintosh\CrowdControl;

/**
 * CrowdControl — pure-PHP SDK.
 *
 * Top-level static API for loading and evaluating CrowdControl policies.
 * Use the static factories to build an Engine, then call evaluate() with
 * a JSON-like associative array.
 *
 * @see https://github.com/mikemackintosh/crowdcontrol
 */
final class CrowdControl
{
    public const VERSION = '0.1.0';
    public const POLICY_EXT = '.cc';

    /**
     * Parse a CrowdControl policy source string into a Policy AST.
     */
    public static function parse(string $source): Policy
    {
        return Parser::parse($source);
    }

    /**
     * Build an Engine from one or more in-memory policy source strings.
     *
     * @param list<string> $sources
     */
    public static function fromSource(
        array $sources,
        string|DefaultEffect $defaultEffect = DefaultEffect::Allow,
        bool $explain = false,
    ): Engine {
        $effect = self::coerceEffect($defaultEffect);
        $policies = array_map(static fn(string $src) => Parser::parse($src), $sources);
        return new Engine(array_values($policies), $effect, $explain);
    }

    /**
     * Build an Engine by loading every ``*.cc`` file from the given dirs.
     *
     * @param list<string> $dirs
     */
    public static function fromDirectory(
        array $dirs,
        string|DefaultEffect $defaultEffect = DefaultEffect::Allow,
        bool $explain = false,
    ): Engine {
        $effect = self::coerceEffect($defaultEffect);
        $policies = [];
        foreach ($dirs as $dir) {
            if (!is_dir($dir)) {
                continue;
            }
            $files = scandir($dir) ?: [];
            sort($files);
            foreach ($files as $name) {
                if (str_ends_with($name, self::POLICY_EXT)) {
                    $path = $dir . '/' . $name;
                    if (is_file($path)) {
                        $policies[] = Parser::parse((string) file_get_contents($path));
                    }
                }
            }
        }
        return new Engine($policies, $effect, $explain);
    }

    private static function coerceEffect(string|DefaultEffect $effect): DefaultEffect
    {
        if ($effect instanceof DefaultEffect) {
            return $effect;
        }
        return match ($effect) {
            'allow' => DefaultEffect::Allow,
            'deny' => DefaultEffect::Deny,
            default => throw new \InvalidArgumentException("unknown default_effect '{$effect}' (expected 'allow' or 'deny')"),
        };
    }
}
