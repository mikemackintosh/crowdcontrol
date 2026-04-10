/*
 * Lexer for CrowdControl policy source.
 *
 * Ports github.com/mikemackintosh/crowdcontrol/parser/lexer.go to Kotlin.
 * Pure stdlib; no regex.
 */
package io.github.mikemackintosh.crowdcontrol

/** Token kinds recognized by the lexer. */
enum class TokenType {
    EOF,
    IDENT,
    STRING,
    NUMBER,
    LBRACE,
    RBRACE,
    LBRACKET,
    RBRACKET,
    LPAREN,
    RPAREN,
    DOT,
    COMMA,
    EQ,
    NEQ,
    LT,
    GT,
    LTE,
    GTE,
    STAR,
    PLUS,
    MINUS,
    SLASH,
}

/** Lexer/parser error. Public so callers can catch it. */
class ParseError(message: String) : RuntimeException(message)

/** A single lexer token. */
class Token(
    @JvmField val type: TokenType,
    @JvmField val value: String = "",
    @JvmField val line: Int = 0,
    @JvmField val col: Int = 0,
) {
    override fun toString(): String = if (type == TokenType.EOF) "EOF" else "\"$value\""
}

/** Tokenize a CrowdControl source string. Always ends with a single EOF token. */
fun lex(source: String): List<Token> {
    val lx = Lexer(source)
    return lx.run()
}

internal class Lexer(private val input: String) {
    private var pos: Int = 0
    private var line: Int = 1
    private var col: Int = 1
    private val tokens: MutableList<Token> = mutableListOf()
    private val n: Int = input.length

    fun run(): List<Token> {
        while (pos < n) {
            val ch = input[pos]

            // Whitespace.
            if (ch.isWhitespace()) {
                if (ch == '\n') {
                    line += 1
                    col = 1
                } else {
                    col += 1
                }
                pos += 1
                continue
            }

            // Comments: '#' or '//' to end of line.
            if (ch == '#' || (ch == '/' && pos + 1 < n && input[pos + 1] == '/')) {
                while (pos < n && input[pos] != '\n') {
                    pos += 1
                }
                continue
            }

            // String literal.
            if (ch == '"') {
                tokens.add(lexString())
                continue
            }

            // Number.
            if (ch.isDigit()) {
                tokens.add(lexNumber())
                continue
            }

            // Identifier or keyword.
            if (ch.isLetter() || ch == '_') {
                tokens.add(lexIdent())
                continue
            }

            // Two-character operators.
            if (pos + 1 < n) {
                val two = input.substring(pos, pos + 2)
                val twoType = when (two) {
                    "==" -> TokenType.EQ
                    "!=" -> TokenType.NEQ
                    "<=" -> TokenType.LTE
                    ">=" -> TokenType.GTE
                    else -> null
                }
                if (twoType != null) {
                    tokens.add(Token(twoType, two, line, col))
                    pos += 2
                    col += 2
                    continue
                }
            }

            // Single-character tokens.
            val singleType = when (ch) {
                '{' -> TokenType.LBRACE
                '}' -> TokenType.RBRACE
                '[' -> TokenType.LBRACKET
                ']' -> TokenType.RBRACKET
                '(' -> TokenType.LPAREN
                ')' -> TokenType.RPAREN
                '.' -> TokenType.DOT
                ',' -> TokenType.COMMA
                '<' -> TokenType.LT
                '>' -> TokenType.GT
                '*' -> TokenType.STAR
                '+' -> TokenType.PLUS
                '-' -> TokenType.MINUS
                '/' -> TokenType.SLASH
                else -> null
            }
            if (singleType != null) {
                tokens.add(Token(singleType, ch.toString(), line, col))
                pos += 1
                col += 1
                continue
            }

            throw ParseError("line $line col $col: unexpected character: $ch")
        }

        tokens.add(Token(TokenType.EOF, "", line, col))
        return tokens
    }

    private fun lexString(): Token {
        val startCol = col
        pos += 1 // skip opening "
        col += 1
        val sb = StringBuilder()
        while (pos < n) {
            val ch = input[pos]
            if (ch == '"') {
                pos += 1
                col += 1
                return Token(TokenType.STRING, sb.toString(), line, startCol)
            }
            if (ch == '\\' && pos + 1 < n) {
                pos += 1
                col += 1
                when (val nxt = input[pos]) {
                    '"', '\\' -> sb.append(nxt)
                    'n' -> sb.append('\n')
                    't' -> sb.append('\t')
                    else -> {
                        sb.append('\\')
                        sb.append(nxt)
                    }
                }
            } else {
                sb.append(ch)
            }
            pos += 1
            col += 1
        }
        throw ParseError("line $line col $startCol: unterminated string")
    }

    private fun lexNumber(): Token {
        val start = pos
        val startCol = col
        while (pos < n && (input[pos].isDigit() || input[pos] == '.')) {
            pos += 1
            col += 1
        }
        return Token(TokenType.NUMBER, input.substring(start, pos), line, startCol)
    }

    private fun lexIdent(): Token {
        val start = pos
        val startCol = col
        while (pos < n) {
            val ch = input[pos]
            if (ch.isLetterOrDigit() || ch == '_') {
                pos += 1
                col += 1
            } else {
                break
            }
        }
        return Token(TokenType.IDENT, input.substring(start, pos), line, startCol)
    }
}
