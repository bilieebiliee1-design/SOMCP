package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test

/**
 * Issue #37: `pdg`/`pdgo` end in rz_core_annotated_code_print(), which dereferences
 * the process-global Rizin console context without a NULL check, so the generic
 * command gateway must not be a second way into that crash.
 *
 * The gateway reaches Rizin through rz_core_cmd_str(), which splits on ';' and
 * newlines and runs every segment — so a whole-string prefix check is not enough.
 * The JSON and statement printers never read the console context, so they are
 * deliberately left available: refusing them would delete capability, not secure it.
 */
class DecompilerPrintGuardTest {
    @Test
    fun refusesPlainAnnotatedPrints() {
        assertEquals("pdg", annotatedPrintSegment("pdg"))
        assertEquals("pdg @ 0x1040", annotatedPrintSegment("pdg @ 0x1040"))
        assertEquals("pdgo", annotatedPrintSegment("pdgo"))
        assertEquals("pdgo @ 0x1040", annotatedPrintSegment("pdgo @ 0x1040"))
        assertEquals("pdgd", annotatedPrintSegment("pdgd"))
        assertEquals("pdgx", annotatedPrintSegment("pdgx"))
    }

    @Test
    fun refusesAfterEverySeparatorRizinSplits() {
        assertEquals("pdg", annotatedPrintSegment("s 0x1040;pdg"))
        assertEquals("pdg", annotatedPrintSegment("s 0x1040; pdg"))
        assertEquals("pdg", annotatedPrintSegment("s 0x1040;\tpdg"))
        assertEquals("pdg", annotatedPrintSegment("s 0x1040\npdg"))
        assertEquals("pdg", annotatedPrintSegment("s 0x1040\r\npdg"))
        assertEquals("pdg", annotatedPrintSegment("pd 4;pdg"))
    }

    @Test
    fun keepsContextFreePrintsAvailable() {
        // pdgj = annotated_code_print_json, pdg* = print_comment_cmds: neither reads
        // cons->context, so neither can fault the way #37 did.
        assertNull(annotatedPrintSegment("pdgj"))
        assertNull(annotatedPrintSegment("pdgj @ 0x1040"))
        assertNull(annotatedPrintSegment("pdg*"))
        // pdgs / pdgss / pdgsd list sleigh languages and print no decompiled code.
        assertNull(annotatedPrintSegment("pdgs"))
        assertNull(annotatedPrintSegment("pdgss"))
        assertNull(annotatedPrintSegment("pdgsd arm"))
        // pdd is rizin's own printer, not the annotated-code path.
        assertNull(annotatedPrintSegment("pdd"))
        assertNull(annotatedPrintSegment("pdd @ 0x1040"))
    }

    @Test
    fun allowsDisassemblyAndAnalysis() {
        assertNull(annotatedPrintSegment("pd 32"))
        assertNull(annotatedPrintSegment("pdf @ 0x1040"))
        assertNull(annotatedPrintSegment("afl"))
        assertNull(annotatedPrintSegment("s 0x1040;axtj"))
        assertNull(annotatedPrintSegment(""))
        assertNull(annotatedPrintSegment(";"))
    }

    /**
     * Parity table shared with the C++ copy of this guard
     * (`rizinSegmentIsAnnotatedPrint` / `rizinAnnotatedPrintBlocked` in rizin_core.cpp).
     * Both sides must answer the same for every row: if they drift, the gateway
     * pre-check and the native backstop describe different rules for the same command.
     */
    @Test
    fun matchesTheNativeGuardOnEveryAdversarialForm() {
        val refused = listOf(
            "pdg", "pdgo", "pdgd", "pdgx",
            "pdg @ 0x1040", "pdgo @ 0x1040",
            "pdg~foo", "pdg?",
            "pdgz",
            "s 0x1040;pdg", "s 0x1040; pdg", "s 0x1040;\tpdg",
            "s 0x1040\npdg", "s 0x1040\r\npdg", "pd 4;pdg",
            "  pdg", "\tpdg", ";;pdg",
            "pdg;;", "pdg\n", "pdgo\n",
        )
        val allowed = listOf(
            "pdgj", "pdgj @ 0x1040", "pdg*", "pdg* @ 0x1040",
            "pdgs", "pdgss", "pdgsd arm",
            "pdd", "pdd @ 0x1040",
            "pd 32", "pdf @ 0x1040", "afl", "s 0x1040;axtj", "", ";",
            "izz~pdg", "CCu \"call pdg here\" @ 0x1040",
            "~pdg", "?pdg", "\$pdg",
        )
        for (command in refused) {
            assertNotNull("expected refusal: $command", annotatedPrintSegment(command))
        }
        for (command in allowed) {
            assertNull("expected to pass: $command", annotatedPrintSegment(command))
        }
    }

    @Test
    fun doesNotMatchArgumentsButKeepsUnknownPdgWordsClosed() {
        assertNull(annotatedPrintSegment("izz~pdg"))
        assertNull(annotatedPrintSegment("CCu \"call pdg here\" @ 0x1040"))
        // The word is what decides: `pdg~foo` and `pdg?` still print before they are
        // filtered or answered, so they are refused as well.
        assertEquals("pdg~foo", annotatedPrintSegment("pdg~foo"))
        assertEquals("pdg?", annotatedPrintSegment("pdg?"))
        // `pdgz` is not a rizin command; an unknown pdg-prefixed word fails closed.
        assertEquals("pdgz", annotatedPrintSegment("pdgz"))
    }
}
