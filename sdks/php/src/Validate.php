<?php

declare(strict_types=1);

namespace MikeMackintosh\CrowdControl;

/**
 * Ports github.com/mikemackintosh/crowdcontrol/evaluator/validate.go to PHP.
 * Static schema validation — produces non-fatal warnings.
 */

final class Validate
{
    /**
     * @param list<Policy> $policies
     * @return list<SchemaWarning>
     */
    public static function validatePolicies(array $policies, Schema $schema): array
    {
        $warnings = [];
        foreach ($policies as $policy) {
            foreach ($policy->rules as $rule) {
                foreach ($rule->conditions as $cond) {
                    array_push($warnings, ...self::validateCondition($cond, $schema, $rule->name));
                }
                foreach ($rule->unlesses as $u) {
                    array_push($warnings, ...self::validateCondition($u, $schema, $rule->name));
                }
                if ($rule->message !== '') {
                    array_push($warnings, ...self::validateInterpolations($rule->message, $schema, $rule->name));
                }
            }
        }
        return $warnings;
    }

    /**
     * @return list<SchemaWarning>
     */
    private static function validateCondition(Condition $cond, Schema $schema, string $ruleName): array
    {
        $warnings = [];
        switch ($cond->type) {
            case ConditionType::Field:
                if ($cond->field !== '') {
                    array_push($warnings, ...self::checkField($cond->field, $schema, $ruleName, $cond));
                }
                break;
            case ConditionType::HasCheck:
                if ($cond->field !== '') {
                    array_push($warnings, ...self::checkFieldExists($cond->field, $schema, $ruleName));
                }
                break;
            case ConditionType::Aggregate:
                if ($cond->aggregateTarget !== '') {
                    array_push($warnings, ...self::checkAggregateField($cond->aggregateTarget, $schema, $ruleName));
                }
                break;
            case ConditionType::AnyQ:
            case ConditionType::AllQ:
                if ($cond->listField !== '') {
                    array_push($warnings, ...self::checkListField($cond->listField, $schema, $ruleName));
                }
                if ($cond->predicate !== null) {
                    array_push($warnings, ...self::validateCondition($cond->predicate, $schema, $ruleName));
                }
                break;
            case ConditionType::OrGroup:
                foreach ($cond->orGroup as $sub) {
                    array_push($warnings, ...self::validateCondition($sub, $schema, $ruleName));
                }
                break;
            case ConditionType::ExprCheck:
                if ($cond->leftExpr !== null) {
                    array_push($warnings, ...self::checkExprFields($cond->leftExpr, $schema, $ruleName));
                }
                if ($cond->rightExpr !== null) {
                    array_push($warnings, ...self::checkExprFields($cond->rightExpr, $schema, $ruleName));
                }
                break;
        }
        return $warnings;
    }

    /**
     * @return list<SchemaWarning>
     */
    private static function checkField(string $field, Schema $schema, string $ruleName, Condition $cond): array
    {
        $expected = self::lookupField($schema, $field);
        if ($expected === null) {
            return [new SchemaWarning($ruleName, $field, "field '{$field}' not found in schema")];
        }
        $op = $cond->op;
        if (in_array($op, ['<', '>', '<=', '>='], true)) {
            if ($expected !== 'number' && $expected !== 'any') {
                return [new SchemaWarning($ruleName, $field, "operator {$op} used on field '{$field}' of type {$expected}")];
            }
        } elseif (in_array($op, ['contains', 'intersects', 'is_subset'], true)) {
            if (!in_array($expected, ['list', 'string', 'any'], true)) {
                return [new SchemaWarning($ruleName, $field, "operator {$op} used on field '{$field}' of type {$expected}")];
            }
        } elseif ($op === 'in') {
            if (!in_array($expected, ['string', 'any'], true)) {
                return [new SchemaWarning($ruleName, $field, "operator 'in' used on field '{$field}' of type {$expected}")];
            }
        }
        return [];
    }

    /**
     * @return list<SchemaWarning>
     */
    private static function checkFieldExists(string $field, Schema $schema, string $ruleName): array
    {
        if (self::lookupField($schema, $field) === null) {
            return [new SchemaWarning($ruleName, $field, "field '{$field}' not found in schema (used with 'has')")];
        }
        return [];
    }

    /**
     * @return list<SchemaWarning>
     */
    private static function checkAggregateField(string $field, Schema $schema, string $ruleName): array
    {
        $expected = self::lookupField($schema, $field);
        if ($expected === null) {
            return [new SchemaWarning($ruleName, $field, "field '{$field}' not found in schema (used with 'count')")];
        }
        if (!in_array($expected, ['list', 'number', 'any'], true)) {
            return [new SchemaWarning($ruleName, $field, "count() used on field '{$field}' of type {$expected}, expected list or number")];
        }
        return [];
    }

    /**
     * @return list<SchemaWarning>
     */
    private static function checkListField(string $field, Schema $schema, string $ruleName): array
    {
        $expected = self::lookupField($schema, $field);
        if ($expected === null) {
            return [new SchemaWarning($ruleName, $field, "field '{$field}' not found in schema (used with quantifier)")];
        }
        if (!in_array($expected, ['list', 'any'], true)) {
            return [new SchemaWarning($ruleName, $field, "quantifier used on field '{$field}' of type {$expected}, expected list")];
        }
        return [];
    }

    /**
     * @return list<SchemaWarning>
     */
    private static function checkExprFields(Expr $expr, Schema $schema, string $ruleName): array
    {
        $warnings = [];
        switch ($expr->kind) {
            case ExprKind::Field:
                if ($expr->field !== '') {
                    $expected = self::lookupField($schema, $expr->field);
                    if ($expected === null) {
                        $warnings[] = new SchemaWarning($ruleName, $expr->field, "field '{$expr->field}' not found in schema (used in arithmetic)");
                    } elseif (!in_array($expected, ['number', 'any'], true)) {
                        $warnings[] = new SchemaWarning($ruleName, $expr->field, "arithmetic used on field '{$expr->field}' of type {$expected}, expected number");
                    }
                }
                break;
            case ExprKind::Count:
                if ($expr->aggTarget !== '') {
                    array_push($warnings, ...self::checkAggregateField($expr->aggTarget, $schema, $ruleName));
                }
                break;
            case ExprKind::Len:
                if ($expr->field !== '') {
                    $expected = self::lookupField($schema, $expr->field);
                    if ($expected === null) {
                        $warnings[] = new SchemaWarning($ruleName, $expr->field, "field '{$expr->field}' not found in schema (used with len)");
                    }
                }
                break;
            case ExprKind::Binary:
                if ($expr->left !== null) {
                    array_push($warnings, ...self::checkExprFields($expr->left, $schema, $ruleName));
                }
                if ($expr->right !== null) {
                    array_push($warnings, ...self::checkExprFields($expr->right, $schema, $ruleName));
                }
                break;
            case ExprKind::Literal:
                break;
        }
        return $warnings;
    }

    /**
     * @return list<SchemaWarning>
     */
    private static function validateInterpolations(string $msg, Schema $schema, string $ruleName): array
    {
        $warnings = [];
        if (preg_match_all('/\{([^}]+)\}/', $msg, $matches) === false) {
            return $warnings;
        }
        foreach ($matches[1] as $expr) {
            if (str_starts_with($expr, 'count(') && str_ends_with($expr, ')')) {
                continue;
            }
            if (self::lookupField($schema, $expr) === null) {
                $warnings[] = new SchemaWarning($ruleName, $expr, "message interpolation references unknown field '{$expr}'");
            }
        }
        return $warnings;
    }

    private static function lookupField(Schema $schema, string $field): ?string
    {
        if (array_key_exists($field, $schema->fields)) {
            return $schema->fields[$field];
        }
        $parts = explode('.', $field);
        for ($i = count($parts) - 1; $i > 0; $i--) {
            $prefix = implode('.', array_slice($parts, 0, $i));
            if (array_key_exists($prefix, $schema->fields) && $schema->fields[$prefix] === 'map') {
                return 'any';
            }
        }
        return null;
    }

    /**
     * @param list<SchemaWarning> $warnings
     */
    public static function formatWarnings(array $warnings): string
    {
        if (empty($warnings)) {
            return '';
        }
        $lines = array_map(fn(SchemaWarning $w) => "  {$w->rule}: {$w->message}", $warnings);
        return implode("\n", $lines) . "\n";
    }
}
