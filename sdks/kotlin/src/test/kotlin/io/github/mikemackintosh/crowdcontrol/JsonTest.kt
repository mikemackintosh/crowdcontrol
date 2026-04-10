package io.github.mikemackintosh.crowdcontrol

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

class JsonTest {

    @Test
    fun parsesEmptyObjectAndArray() {
        assertEquals(emptyMap<String, Any?>(), parseJson("{}"))
        assertEquals(emptyList<Any?>(), parseJson("[]"))
    }

    @Test
    fun parsesScalars() {
        assertEquals("hi", parseJson("\"hi\""))
        assertEquals(42L, parseJson("42"))
        assertEquals(-7L, parseJson("-7"))
        assertEquals(3.14, parseJson("3.14"))
        assertEquals(true, parseJson("true"))
        assertEquals(false, parseJson("false"))
        assertNull(parseJson("null"))
    }

    @Test
    fun parsesNestedStructures() {
        val v = parseJson("""{"a": [1, 2, {"b": "c"}], "d": null}""")
        @Suppress("UNCHECKED_CAST")
        val m = v as Map<String, Any?>
        assertEquals(listOf(1L, 2L, mapOf("b" to "c")), m["a"])
        assertNull(m["d"])
    }

    @Test
    fun parsesStringEscapes() {
        assertEquals("a\nb", parseJson("\"a\\nb\""))
        assertEquals("quote\"end", parseJson("\"quote\\\"end\""))
        assertEquals("slash\\", parseJson("\"slash\\\\\""))
        assertEquals("\u00e9", parseJson("\"\\u00e9\""))
    }

    @Test
    fun handlesWhitespace() {
        val v = parseJson("  {  \"k\" :  [ 1 , 2 ]  }  ")
        @Suppress("UNCHECKED_CAST")
        val m = v as Map<String, Any?>
        assertEquals(listOf(1L, 2L), m["k"])
    }

    @Test
    fun rejectsTrailingGarbage() {
        assertFailsWith<JsonParseError> { parseJson("{} extra") }
    }

    @Test
    fun rejectsUnterminatedString() {
        assertFailsWith<JsonParseError> { parseJson("\"open") }
    }

    @Test
    fun preservesObjectInsertionOrder() {
        val v = parseJson("""{"z": 1, "a": 2, "m": 3}""")
        @Suppress("UNCHECKED_CAST")
        val m = v as Map<String, Any?>
        assertEquals(listOf("z", "a", "m"), m.keys.toList())
    }

    @Test
    fun parsesScientificNotationAsDouble() {
        assertEquals(1e5, parseJson("1e5"))
        assertEquals(true, parseJson("1e5") is Double)
    }
}
