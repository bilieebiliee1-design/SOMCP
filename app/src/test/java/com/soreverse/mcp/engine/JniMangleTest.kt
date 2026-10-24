// SPDX-License-Identifier: AGPL-3.0-only
//
// JNI symbol codec tests: escaping round trips, the long-name signature form,
// and the ambiguity the escape rules exist to remove.
package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class JniMangleTest {
    @Test
    fun decodesShortNameIntoClassAndMethod() {
        val r = JniMangle.decode("Java_com_example_Foo_bar")
        assertTrue(r.getBoolean("valid"))
        assertEquals("com.example.Foo", r.getString("className"))
        assertEquals("bar", r.getString("methodName"))
        assertEquals("Java_com_example_Foo_bar", r.getString("shortName"))
    }

    @Test
    fun decodesLongNameWithSignature() {
        val r = JniMangle.decode("Java_com_example_Foo_bar__Ljava_lang_String_2I")
        assertTrue(r.getBoolean("valid"))
        assertEquals("(Ljava/lang/String;I)", r.getString("signature"))
        assertEquals("com.example.Foo", r.getString("className"))
        assertEquals("bar", r.getString("methodName"))
    }

    @Test
    fun encodeProducesTheLongNameForSignatures() {
        // The long name carries the argument descriptor only — no return type.
        assertEquals(
            "Java_com_example_Foo_bar__Ljava_lang_String_2",
            JniMangle.encode("com.example.Foo", "bar", "(Ljava/lang/String;)V")
        )
        assertEquals("Java_com_example_Foo_bar", JniMangle.encode("com.example.Foo", "bar", null))
    }

    @Test
    fun underscoresInNamesSurviveTheRoundTrip() {
        val symbol = JniMangle.encode("a.b", "my_method", null)
        assertEquals("Java_a_b_my_1method", symbol)
        val r = JniMangle.decode(symbol)
        assertTrue(r.getBoolean("valid"))
        assertEquals("my_method", r.getString("methodName"))
        assertEquals("a.b", r.getString("className"))
    }

    @Test
    fun semicolonsAndArraysEscape() {
        assertEquals(
            "Java_a_B_arr___3Ljava_lang_String_2",
            JniMangle.encode("a.B", "arr", "([Ljava/lang/String;)V")
        )
        val r = JniMangle.decode("Java_a_B_arr___3Ljava_lang_String_2")
        // The long name carries the argument descriptor only: the return type V
        // is dropped by encode, so decode cannot and must not report it.
        assertEquals("([Ljava/lang/String;)", r.getString("signature"))
    }

    @Test
    fun nonJniSymbolIsRejectedWithoutGuessing() {
        assertFalse(JniMangle.decode("some_plain_symbol").getBoolean("valid"))
        assertFalse(JniMangle.decode("Java_bare").getBoolean("valid"))
    }
}
