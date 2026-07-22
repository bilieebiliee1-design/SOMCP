package com.soreverse.mcp.engine

internal object ElfSectionResolver {
    fun resolve(elf: ElfFile, locator: String): SectionInfo? {
        val locatorValue = locator.trim()
        elf.sections.forEachIndexed { index, section ->
            val key = EngineJson.sectionKey(section, index)
            if (locatorValue == key || locatorValue.endsWith("!$key")) return section
        }
        val target = LocatorParser.target(locator, "so_section")
        val key = locatorValue.substringAfterLast('!').removePrefix("so_section:")
        val index = key.substringAfterLast('#', "").toIntOrNull()
        if (index != null && index in elf.sections.indices) return elf.sections[index]
        val offset = LocatorParser.hex(key.substringAfterLast('@', "").substringBefore('#'))
        if (offset != null) elf.sections.firstOrNull { it.offset == offset }?.let { return it }
        return elf.sections.firstOrNull { it.name == target.substringBefore('#') }
    }
}
