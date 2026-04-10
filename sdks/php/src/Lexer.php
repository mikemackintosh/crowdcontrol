<?php

declare(strict_types=1);

namespace MikeMackintosh\CrowdControl;

/**
 * Ports github.com/mikemackintosh/crowdcontrol/parser/lexer.go to PHP.
 */

enum TokenType: int
{
    case Eof = 0;
    case Ident = 1;
    case StringT = 2;
    case Number = 3;
    case LBrace = 4;
    case RBrace = 5;
    case LBracket = 6;
    case RBracket = 7;
    case LParen = 8;
    case RParen = 9;
    case Dot = 10;
    case Comma = 11;
    case Eq = 12;
    case Neq = 13;
    case Lt = 14;
    case Gt = 15;
    case Lte = 16;
    case Gte = 17;
    case Star = 18;
    case Plus = 19;
    case Minus = 20;
    case Slash = 21;
}

final class Token
{
    public function __construct(
        public TokenType $type,
        public string $val = '',
        public int $line = 0,
        public int $col = 0,
    ) {
    }

    public function __toString(): string
    {
        return $this->type === TokenType::Eof ? 'EOF' : "'" . $this->val . "'";
    }
}

final class LexException extends \RuntimeException
{
}

final class Lexer
{
    /** @var array<int, string> */
    private array $chars;
    private int $pos = 0;
    private int $line = 1;
    private int $col = 1;
    /** @var list<Token> */
    private array $tokens = [];

    public function __construct(string $source)
    {
        // Split into Unicode code points so multi-byte characters work.
        $this->chars = preg_split('//u', $source, -1, PREG_SPLIT_NO_EMPTY) ?: [];
    }

    /**
     * @return list<Token>
     */
    public static function tokenize(string $source): array
    {
        return (new self($source))->run();
    }

    /**
     * @return list<Token>
     */
    public function run(): array
    {
        $n = count($this->chars);
        while ($this->pos < $n) {
            $ch = $this->chars[$this->pos];

            // Whitespace
            if ($ch === ' ' || $ch === "\t" || $ch === "\r" || $ch === "\n") {
                if ($ch === "\n") {
                    $this->line++;
                    $this->col = 1;
                } else {
                    $this->col++;
                }
                $this->pos++;
                continue;
            }

            // Comments: # or //
            if ($ch === '#' || ($ch === '/' && $this->pos + 1 < $n && $this->chars[$this->pos + 1] === '/')) {
                while ($this->pos < $n && $this->chars[$this->pos] !== "\n") {
                    $this->pos++;
                }
                continue;
            }

            // String literal
            if ($ch === '"') {
                $this->tokens[] = $this->lexString();
                continue;
            }

            // Number
            if (ctype_digit($ch)) {
                $this->tokens[] = $this->lexNumber();
                continue;
            }

            // Identifier / keyword
            if (ctype_alpha($ch) || $ch === '_') {
                $this->tokens[] = $this->lexIdent();
                continue;
            }

            // Two-char operators
            if ($this->pos + 1 < $n) {
                $two = $ch . $this->chars[$this->pos + 1];
                $mapping = [
                    '==' => TokenType::Eq,
                    '!=' => TokenType::Neq,
                    '<=' => TokenType::Lte,
                    '>=' => TokenType::Gte,
                ];
                if (isset($mapping[$two])) {
                    $this->tokens[] = new Token($mapping[$two], $two, $this->line, $this->col);
                    $this->pos += 2;
                    $this->col += 2;
                    continue;
                }
            }

            // Single-char tokens
            $single = [
                '{' => TokenType::LBrace,
                '}' => TokenType::RBrace,
                '[' => TokenType::LBracket,
                ']' => TokenType::RBracket,
                '(' => TokenType::LParen,
                ')' => TokenType::RParen,
                '.' => TokenType::Dot,
                ',' => TokenType::Comma,
                '<' => TokenType::Lt,
                '>' => TokenType::Gt,
                '*' => TokenType::Star,
                '+' => TokenType::Plus,
                '-' => TokenType::Minus,
                '/' => TokenType::Slash,
            ];
            if (isset($single[$ch])) {
                $this->tokens[] = new Token($single[$ch], $ch, $this->line, $this->col);
                $this->pos++;
                $this->col++;
                continue;
            }

            throw new LexException("line {$this->line} col {$this->col}: unexpected character: {$ch}");
        }

        $this->tokens[] = new Token(TokenType::Eof, '', $this->line, $this->col);
        return $this->tokens;
    }

    private function lexString(): Token
    {
        $startCol = $this->col;
        $this->pos++; // skip opening "
        $this->col++;
        $parts = '';
        $n = count($this->chars);
        while ($this->pos < $n) {
            $ch = $this->chars[$this->pos];
            if ($ch === '"') {
                $this->pos++;
                $this->col++;
                return new Token(TokenType::StringT, $parts, $this->line, $startCol);
            }
            if ($ch === '\\' && $this->pos + 1 < $n) {
                $this->pos++;
                $this->col++;
                $next = $this->chars[$this->pos];
                $parts .= match ($next) {
                    '"', '\\' => $next,
                    'n' => "\n",
                    't' => "\t",
                    default => '\\' . $next,
                };
            } else {
                $parts .= $ch;
            }
            $this->pos++;
            $this->col++;
        }
        throw new LexException("line {$this->line} col {$startCol}: unterminated string");
    }

    private function lexNumber(): Token
    {
        $start = $this->pos;
        $startCol = $this->col;
        $n = count($this->chars);
        while ($this->pos < $n && (ctype_digit($this->chars[$this->pos]) || $this->chars[$this->pos] === '.')) {
            $this->pos++;
            $this->col++;
        }
        $val = implode('', array_slice($this->chars, $start, $this->pos - $start));
        return new Token(TokenType::Number, $val, $this->line, $startCol);
    }

    private function lexIdent(): Token
    {
        $start = $this->pos;
        $startCol = $this->col;
        $n = count($this->chars);
        while ($this->pos < $n) {
            $ch = $this->chars[$this->pos];
            if (ctype_alnum($ch) || $ch === '_') {
                $this->pos++;
                $this->col++;
            } else {
                break;
            }
        }
        $val = implode('', array_slice($this->chars, $start, $this->pos - $start));
        return new Token(TokenType::Ident, $val, $this->line, $startCol);
    }
}
