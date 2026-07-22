package com.soreverse.mcp.engine

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Test

class ElfSectionResolverTest {
    private val sections = listOf(
        section(".text", 0x100),
        section(".data", 0x200),
        section(".text", 0x300),
    )
    private val elf = ElfFile(ByteArray(0), 64, true, 3, 183, 0, sections, emptyList(), emptyList(), emptyList(), emptyList())

    @Test
    fun resolvesByIndexBeforeOffsetAndName() {
        assertEquals(sections[2], ElfSectionResolver.resolve(elf, ".data@0x200#2"))
    }

    @Test
    fun resolvesByOffsetBeforeName() {
        assertEquals(sections[2], ElfSectionResolver.resolve(elf, ".data@0x300"))
    }

    @Test
    fun resolvesByName() {
        assertEquals(sections[0], ElfSectionResolver.resolve(elf, ".text"))
    }

    @Test
    fun resolvesEngineSectionKey() {
        assertEquals(sections[2], ElfSectionResolver.resolve(elf, "so_section:lib.so!${EngineJson.sectionKey(sections[2], 2)}"))
    }

    @Test
    fun rejectsInvalidLocator() {
        assertNull(ElfSectionResolver.resolve(elf, "so_section:lib.so!.missing@invalid#99"))
    }

    private fun section(name: String, offset: Long) = SectionInfo(name, 1, 0, 0, offset, 16, 0, 0, 1, 0)
}
