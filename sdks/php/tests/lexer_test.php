<?php

declare(strict_types=1);

use MikeMackintosh\CrowdControl\Lexer;
use MikeMackintosh\CrowdControl\LexException;
use MikeMackintosh\CrowdControl\TokenType;

function tokens_no_eof(string $src): array
{
    $toks = Lexer::tokenize($src);
    // drop trailing EOF
    array_pop($toks);
    return $toks;
}

function test_lexer_empty(): void
{
    $toks = tokens_no_eof('');
    assert_count(0, $toks);
}

function test_lexer_keywords(): void
{
    $toks = tokens_no_eof('forbid warn permit unless');
    assert_count(4, $toks);
    foreach ($toks as $t) {
        assert_eq(TokenType::Ident, $t->type);
    }
    assert_eq('forbid', $toks[0]->val);
    assert_eq('unless', $toks[3]->val);
}

function test_lexer_string_with_escapes(): void
{
    $toks = tokens_no_eof('"hello\nworld\t\"done\""');
    assert_count(1, $toks);
    assert_eq(TokenType::StringT, $toks[0]->type);
    assert_eq("hello\nworld\t\"done\"", $toks[0]->val);
}

function test_lexer_numbers(): void
{
    $toks = tokens_no_eof('42 3.14');
    assert_count(2, $toks);
    assert_eq(TokenType::Number, $toks[0]->type);
    assert_eq('42', $toks[0]->val);
    assert_eq('3.14', $toks[1]->val);
}

function test_lexer_dotted_path(): void
{
    $toks = tokens_no_eof('resource.type');
    assert_count(3, $toks);
    assert_eq(TokenType::Ident, $toks[0]->type);
    assert_eq(TokenType::Dot, $toks[1]->type);
    assert_eq(TokenType::Ident, $toks[2]->type);
}

function test_lexer_two_char_operators(): void
{
    $toks = tokens_no_eof('== != <= >=');
    assert_count(4, $toks);
    assert_eq(TokenType::Eq, $toks[0]->type);
    assert_eq(TokenType::Neq, $toks[1]->type);
    assert_eq(TokenType::Lte, $toks[2]->type);
    assert_eq(TokenType::Gte, $toks[3]->type);
}

function test_lexer_single_char_operators(): void
{
    $toks = tokens_no_eof('< > + - * /');
    assert_count(6, $toks);
    assert_eq(TokenType::Lt, $toks[0]->type);
    assert_eq(TokenType::Gt, $toks[1]->type);
    assert_eq(TokenType::Plus, $toks[2]->type);
    assert_eq(TokenType::Minus, $toks[3]->type);
    assert_eq(TokenType::Star, $toks[4]->type);
    assert_eq(TokenType::Slash, $toks[5]->type);
}

function test_lexer_punctuation(): void
{
    $toks = tokens_no_eof('{ } [ ] ( ) , .');
    assert_count(8, $toks);
}

function test_lexer_hash_comment(): void
{
    $toks = tokens_no_eof("# comment\nforbid");
    assert_count(1, $toks);
    assert_eq('forbid', $toks[0]->val);
}

function test_lexer_double_slash_comment(): void
{
    $toks = tokens_no_eof("// comment\nforbid");
    assert_count(1, $toks);
    assert_eq('forbid', $toks[0]->val);
}

function test_lexer_line_col_tracking(): void
{
    $toks = tokens_no_eof("forbid\n  warn");
    assert_eq(1, $toks[0]->line);
    assert_eq(1, $toks[0]->col);
    assert_eq(2, $toks[1]->line);
    assert_eq(3, $toks[1]->col);
}

function test_lexer_unterminated_string(): void
{
    assert_throws(static fn() => Lexer::tokenize('"no closing'), LexException::class);
}

function test_lexer_unexpected_char(): void
{
    assert_throws(static fn() => Lexer::tokenize('@'), LexException::class);
}

function test_lexer_ident_with_underscore_and_digits(): void
{
    $toks = tokens_no_eof('foo_bar_123');
    assert_count(1, $toks);
    assert_eq('foo_bar_123', $toks[0]->val);
}
