package com.soreverse.mcp

import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.boolean
import kotlinx.serialization.json.double
import kotlinx.serialization.json.jsonArray
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import kotlinx.serialization.json.long
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class RequestFieldsTest {
    @Test
    fun headerValuesRemainStrings() {
        val serialized = serializeRequestFields(
            listOf(RequestField("Authorization", " 123 ")),
            typedValues = false,
        )

        assertEquals(" 123 ", Json.parseToJsonElement(serialized).jsonObject.getValue("Authorization").jsonPrimitive.content)
        assertEquals(listOf(RequestField("Authorization", " 123 ")), parseRequestFields(serialized))
    }

    @Test
    fun bodyValuesInferJsonTypes() {
        val serialized = serializeRequestFields(
            listOf(
                RequestField("nullValue", "null"),
                RequestField("booleanValue", "true"),
                RequestField("integerValue", "42"),
                RequestField("decimalValue", "3.5"),
                RequestField("objectValue", "{\"name\":\"value\"}"),
                RequestField("arrayValue", "[1,\"two\"]"),
            ),
            typedValues = true,
        )
        val json = Json.parseToJsonElement(serialized).jsonObject

        assertEquals(JsonNull, json["nullValue"])
        assertTrue(json.getValue("booleanValue").jsonPrimitive.boolean)
        assertEquals(42L, json.getValue("integerValue").jsonPrimitive.long)
        assertEquals(3.5, json.getValue("decimalValue").jsonPrimitive.double, 0.0)
        assertEquals("value", json.getValue("objectValue").jsonObject.getValue("name").jsonPrimitive.content)
        assertEquals(1L, json.getValue("arrayValue").jsonArray[0].jsonPrimitive.long)
        assertEquals("two", json.getValue("arrayValue").jsonArray[1].jsonPrimitive.content)
    }

    @Test
    fun emptyKeysAreFiltered() {
        val json = Json.parseToJsonElement(
            serializeRequestFields(
                listOf(
                    RequestField("", "ignored"),
                    RequestField("   ", "ignored"),
                    RequestField("kept", "value"),
                ),
                typedValues = false,
            ),
        ).jsonObject

        assertEquals(1, json.size)
        assertFalse(json.containsKey(""))
        assertEquals("value", json.getValue("kept").jsonPrimitive.content)
    }

    @Test
    fun duplicateKeysUseLastValue() {
        val json = Json.parseToJsonElement(
            serializeRequestFields(
                listOf(
                    RequestField("duplicate", "first"),
                    RequestField("duplicate", "last"),
                ),
                typedValues = false,
            ),
        ).jsonObject

        assertEquals(1, json.size)
        assertEquals("last", json.getValue("duplicate").jsonPrimitive.content)
    }
}
