/*
 * Tiny JSON reader, stdlib-only.
 *
 * Exists because the Kotlin SDK refuses to depend on Jackson/Gson/
 * kotlinx.serialization. Only needs to handle the subset of JSON used by
 * conformance cases and schema files, but is a correct parser: full
 * object/array/string/number/bool/null support, nested containers,
 * common escapes (\" \\ \/ \n \t \r \b \f \uXXXX), trailing whitespace.
 *
 * Output shapes:
 *   object -> LinkedHashMap<String, Any?>
 *   array  -> ArrayList<Any?>
 *   string -> String
 *   number -> Long (if integer and fits) | Double
 *   bool   -> Boolean
 *   null   -> null
 */
package io.github.mikemackintosh.crowdcontrol

/** Error thrown when JSON input is malformed. */
class JsonParseError(message: String) : RuntimeException(message)

/** Parse a JSON text into a native Kotlin value tree. */
fun parseJson(text: String): Any? {
    val r = JsonReader(text)
    val value = r.readValue()
    r.skipWhitespace()
    if (!r.atEnd()) {
        throw JsonParseError("unexpected trailing content at offset ${r.pos}")
    }
    return value
}

internal class JsonReader(private val input: String) {
    var pos: Int = 0
    private val n: Int = input.length

    fun atEnd(): Boolean = pos >= n

    fun skipWhitespace() {
        while (pos < n) {
            val c = input[pos]
            if (c == ' ' || c == '\t' || c == '\n' || c == '\r') pos += 1
            else break
        }
    }

    fun readValue(): Any? {
        skipWhitespace()
        if (pos >= n) throw JsonParseError("unexpected end of input")
        val c = input[pos]
        return when (c) {
            '{' -> readObject()
            '[' -> readArray()
            '"' -> readString()
            't', 'f' -> readBool()
            'n' -> readNull()
            '-', in '0'..'9' -> readNumber()
            else -> throw JsonParseError("unexpected character '$c' at offset $pos")
        }
    }

    private fun readObject(): LinkedHashMap<String, Any?> {
        expect('{')
        val obj = LinkedHashMap<String, Any?>()
        skipWhitespace()
        if (peek() == '}') {
            pos += 1
            return obj
        }
        while (true) {
            skipWhitespace()
            if (peek() != '"') throw JsonParseError("expected string key at offset $pos")
            val key = readString()
            skipWhitespace()
            if (peek() != ':') throw JsonParseError("expected ':' at offset $pos")
            pos += 1
            val value = readValue()
            obj[key] = value
            skipWhitespace()
            when (peek()) {
                ',' -> {
                    pos += 1
                    continue
                }
                '}' -> {
                    pos += 1
                    return obj
                }
                else -> throw JsonParseError("expected ',' or '}' at offset $pos")
            }
        }
    }

    private fun readArray(): ArrayList<Any?> {
        expect('[')
        val arr = ArrayList<Any?>()
        skipWhitespace()
        if (peek() == ']') {
            pos += 1
            return arr
        }
        while (true) {
            val value = readValue()
            arr.add(value)
            skipWhitespace()
            when (peek()) {
                ',' -> {
                    pos += 1
                    continue
                }
                ']' -> {
                    pos += 1
                    return arr
                }
                else -> throw JsonParseError("expected ',' or ']' at offset $pos")
            }
        }
    }

    fun readString(): String {
        expect('"')
        val sb = StringBuilder()
        while (pos < n) {
            val c = input[pos]
            if (c == '"') {
                pos += 1
                return sb.toString()
            }
            if (c == '\\') {
                pos += 1
                if (pos >= n) throw JsonParseError("unterminated escape at offset $pos")
                when (val esc = input[pos]) {
                    '"', '\\', '/' -> sb.append(esc)
                    'n' -> sb.append('\n')
                    't' -> sb.append('\t')
                    'r' -> sb.append('\r')
                    'b' -> sb.append('\b')
                    'f' -> sb.append('\u000C')
                    'u' -> {
                        if (pos + 4 >= n) throw JsonParseError("invalid unicode escape at offset $pos")
                        val hex = input.substring(pos + 1, pos + 5)
                        val cp = hex.toInt(16)
                        sb.append(cp.toChar())
                        pos += 4
                    }
                    else -> throw JsonParseError("invalid escape \\$esc at offset $pos")
                }
                pos += 1
            } else {
                sb.append(c)
                pos += 1
            }
        }
        throw JsonParseError("unterminated string")
    }

    private fun readBool(): Boolean {
        return if (matchLiteral("true")) true
        else if (matchLiteral("false")) false
        else throw JsonParseError("invalid literal at offset $pos")
    }

    private fun readNull(): Any? {
        if (!matchLiteral("null")) throw JsonParseError("invalid literal at offset $pos")
        return null
    }

    private fun matchLiteral(lit: String): Boolean {
        if (pos + lit.length > n) return false
        for (i in lit.indices) {
            if (input[pos + i] != lit[i]) return false
        }
        pos += lit.length
        return true
    }

    private fun readNumber(): Any {
        val start = pos
        if (input[pos] == '-') pos += 1
        while (pos < n && input[pos].isDigit()) pos += 1
        var isFloat = false
        if (pos < n && input[pos] == '.') {
            isFloat = true
            pos += 1
            while (pos < n && input[pos].isDigit()) pos += 1
        }
        if (pos < n && (input[pos] == 'e' || input[pos] == 'E')) {
            isFloat = true
            pos += 1
            if (pos < n && (input[pos] == '+' || input[pos] == '-')) pos += 1
            while (pos < n && input[pos].isDigit()) pos += 1
        }
        val text = input.substring(start, pos)
        if (!isFloat) {
            text.toLongOrNull()?.let { return it }
        }
        return text.toDoubleOrNull()
            ?: throw JsonParseError("invalid number \"$text\" at offset $start")
    }

    private fun peek(): Char {
        if (pos >= n) throw JsonParseError("unexpected end of input")
        return input[pos]
    }

    private fun expect(c: Char) {
        if (pos >= n || input[pos] != c) {
            throw JsonParseError("expected '$c' at offset $pos")
        }
        pos += 1
    }
}
