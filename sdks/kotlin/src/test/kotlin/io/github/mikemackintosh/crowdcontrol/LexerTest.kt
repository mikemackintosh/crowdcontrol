package io.github.mikemackintosh.crowdcontrol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

class LexerTest {

    @Test
    fun lexesEmptySource() {
        val tokens = lex("")
        assertEquals(1, tokens.size)
        assertEquals(TokenType.EOF, tokens[0].type)
    }

    @Test
    fun lexesKeywordsAsIdents() {
        val tokens = lex("forbid permit warn unless")
        assertEquals(5, tokens.size) // 4 + EOF
        for (i in 0..3) assertEquals(TokenType.IDENT, tokens[i].type)
        assertEquals("forbid", tokens[0].value)
        assertEquals("permit", tokens[1].value)
        assertEquals("warn", tokens[2].value)
        assertEquals("unless", tokens[3].value)
    }

    @Test
    fun lexesStringLiteralsWithEscapes() {
        val tokens = lex("\"hello\\nworld\" \"quote: \\\"\"")
        assertEquals(TokenType.STRING, tokens[0].type)
        assertEquals("hello\nworld", tokens[0].value)
        assertEquals(TokenType.STRING, tokens[1].type)
        assertEquals("quote: \"", tokens[1].value)
    }

    @Test
    fun lexesNumbers() {
        val tokens = lex("42 3.14 100")
        assertEquals(TokenType.NUMBER, tokens[0].type)
        assertEquals("42", tokens[0].value)
        assertEquals("3.14", tokens[1].value)
        assertEquals("100", tokens[2].value)
    }

    @Test
    fun lexesTwoCharOperators() {
        val tokens = lex("== != <= >=")
        assertEquals(TokenType.EQ, tokens[0].type)
        assertEquals(TokenType.NEQ, tokens[1].type)
        assertEquals(TokenType.LTE, tokens[2].type)
        assertEquals(TokenType.GTE, tokens[3].type)
    }

    @Test
    fun lexesSingleCharPunctuation() {
        val tokens = lex("{}[](),.")
        val expectedTypes = listOf(
            TokenType.LBRACE, TokenType.RBRACE,
            TokenType.LBRACKET, TokenType.RBRACKET,
            TokenType.LPAREN, TokenType.RPAREN,
            TokenType.COMMA, TokenType.DOT,
        )
        for ((i, t) in expectedTypes.withIndex()) {
            assertEquals(t, tokens[i].type)
        }
    }

    @Test
    fun skipsLineCommentsBothFlavors() {
        val tokens = lex(
            """
            # hash comment
            forbid // trailing comment
            """.trimIndent()
        )
        assertEquals(TokenType.IDENT, tokens[0].type)
        assertEquals("forbid", tokens[0].value)
        assertEquals(TokenType.EOF, tokens[1].type)
    }

    @Test
    fun reportsUnterminatedString() {
        val err = assertFailsWith<ParseError> { lex("\"unterminated") }
        assertTrue(err.message!!.contains("unterminated string"))
    }

    @Test
    fun tracksLineAndColumn() {
        val tokens = lex("forbid\n  \"rule\"")
        assertEquals(1, tokens[0].line)
        assertEquals(2, tokens[1].line)
    }
}
