package com.soreverse.mcp.engine

import org.json.JSONObject

internal object EngineJson {
    fun symbolJson(file: String, s: SymbolInfo) = JSONObject().put("locator", "so_symbol:$file!${s.name}").put("name", s.name).put("bind", s.bind).put("type", s.type).put("visibility", s.visibility).put("value", hex(s.value)).put("size", s.size).put("isExported", s.exported).put("isImported", s.imported).put("demangled", JSONObject.NULL)
    fun stringJson(file: String, s: StringInfo) = JSONObject().put("locator", "so_string:$file!${s.offset.toString(16)}").put("offset", hex(s.offset)).put("value", s.value).put("length", s.length).put("section", s.section).put("encoding", s.encoding).put("confidence", s.confidence).put("isTerminated", true)
    fun sectionJson(file: String, s: SectionInfo, index: Int = -1) = JSONObject().put("locator", sectionLocator(file, s, index)).put("name", s.name).put("index", index).put("type", s.type).put("flags", s.flags).put("addr", hex(s.addr)).put("offset", hex(s.offset)).put("size", s.size).put("link", s.link).put("info", s.info).put("addralign", s.addralign).put("entsize", s.entsize)
    fun relocJson(r: RelocInfo) = JSONObject().put("section", r.section).put("offset", hex(r.offset)).put("type", r.type).put("typeName", relocationTypeName(r.type)).put("symbol", r.symbol).put("symbolLocator", if (r.symbol.isNotBlank()) "so_symbol:lib.so!${r.symbol}" else JSONObject.NULL).put("addend", r.addend)

    fun relocationJson(file: String, elf: ElfFile, r: RelocInfo): JSONObject {
        val symbol = r.symbol.takeIf { it.isNotBlank() }
        val symbolInfo = symbol?.let { name -> (elf.symbols + elf.dynSymbols).firstOrNull { it.name == name } }
        return JSONObject()
            .put("locator", "so_reloc:$file!${r.section}!${r.offset.toString(16)}")
            .put("section", r.section)
            .put("offset", hex(r.offset))
            .put("type", r.type)
            .put("typeName", relocationTypeName(r.type))
            .put("symbol", symbol ?: JSONObject.NULL)
            .put("symbolLocator", symbol?.let { "so_symbol:$file!$it" } ?: JSONObject.NULL)
            .put("symbolValue", symbolInfo?.let { hex(it.value) } ?: JSONObject.NULL)
            .put("symbolImported", symbolInfo?.imported ?: JSONObject.NULL)
            .put("addend", r.addend)
    }

    fun relocationTypeName(type: Long): String = when (type) {
        257L -> "R_AARCH64_ABS64"
        258L -> "R_AARCH64_ABS32"
        259L -> "R_AARCH64_ABS16"
        1024L -> "R_AARCH64_COPY"
        1025L -> "R_AARCH64_GLOB_DAT"
        1026L -> "R_AARCH64_JUMP_SLOT"
        1027L -> "R_AARCH64_RELATIVE"
        1031L -> "R_AARCH64_TLS_TPREL64"
        1032L -> "R_AARCH64_TLS_DTPREL32"
        1033L -> "R_AARCH64_IRELATIVE"
        268435456L + 1025L -> "R_AARCH64_GLOB_DAT|ANDROID_PACKED"
        268435456L + 1026L -> "R_AARCH64_JUMP_SLOT|ANDROID_PACKED"
        268435456L + 1027L -> "R_AARCH64_RELATIVE|ANDROID_PACKED"
        else -> "UNKNOWN_$type"
    }

    fun phJson(p: ProgramHeaderInfo) = JSONObject().put("type", p.type).put("flags", p.flags).put("offset", hex(p.offset)).put("vaddr", hex(p.vaddr)).put("paddr", hex(p.paddr)).put("filesz", p.filesz).put("memsz", p.memsz).put("align", p.align)
    fun dynJson(d: DynamicEntryInfo) = JSONObject().put("tag", d.tag).put("value", hex(d.value))
    fun elfSummaryJson(workspaceId: String, editSessionId: String, elf: ElfFile) = JSONObject().put("workspaceId", workspaceId).put("editSessionId", editSessionId).put("bits", elf.bits).put("endian", elf.endian).put("machine", elf.machineName).put("architecture", elf.architecture).put("entry", hex(elf.entry)).put("counts", JSONObject().put("sections", elf.sections.size).put("symbols", elf.symbols.size).put("dynSymbols", elf.dynSymbols.size).put("relocations", elf.relocations.size).put("programHeaders", elf.programHeaders.size).put("dynamicEntries", elf.dynamicEntries.size).put("strings", elf.strings.size))
    fun sectionLocator(file: String, s: SectionInfo, index: Int): String = "so_section:$file!${sectionKey(s, index)}"
    fun sectionKey(s: SectionInfo, index: Int): String = "${s.name}@${hex(s.offset)}#${index.coerceAtLeast(0)}"

    private fun hex(v: Long) = "0x${v.toString(16)}"
}
