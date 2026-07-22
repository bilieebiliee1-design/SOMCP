package com.soreverse.mcp

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AnalyzeControllerTest {
    @Test
    fun blankRequestDoesNotIncludeHistory() {
        val result = buildDeepTurnRequest(
            request = "",
            messages = listOf(DeepChatMessage(1, DeepChatRole.ASSISTANT, "old")),
            historySoftLimit = 8_000,
        )

        assertEquals("", result)
    }

    @Test
    fun followUpIncludesRecentConversationAndRequest() {
        val messages = (1L..8L).map { id ->
            DeepChatMessage(
                id = id,
                role = if (id % 2L == 0L) DeepChatRole.ASSISTANT else DeepChatRole.USER,
                text = "message-$id",
            )
        }

        val result = buildDeepTurnRequest("next", messages, 8_000)

        assertFalse(result.contains("message-1"))
        assertFalse(result.contains("message-2"))
        assertTrue(result.contains("用户: message-3"))
        assertTrue(result.contains("AI: message-8"))
        assertTrue(result.endsWith("用户本轮问题：next"))
    }

    @Test
    fun historyUsesMinimumSoftLimit() {
        val longText = "x".repeat(5_000)
        val result = buildDeepTurnRequest(
            request = "next",
            messages = listOf(DeepChatMessage(1, DeepChatRole.ASSISTANT, longText)),
            historySoftLimit = 10,
        )

        assertFalse(result.contains("x".repeat(4_001)))
        assertTrue(result.contains("x".repeat(3_900)))
    }
}
