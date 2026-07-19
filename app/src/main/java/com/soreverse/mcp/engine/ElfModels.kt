package com.soreverse.mcp.engine

data class SectionInfo(
    val name: String,
    val type: Long,
    val flags: Long,
    val addr: Long,
    val offset: Long,
    val size: Long,
    val link: Int,
    val info: Int,
    val addralign: Long,
    val entsize: Long,
)

data class SymbolInfo(
    val name: String,
    val bind: String,
    val type: String,
    val visibility: String,
    val sectionIndex: Int,
    val value: Long,
    val size: Long,
    val imported: Boolean,
    val exported: Boolean,
)

data class RelocInfo(
    val section: String,
    val offset: Long,
    val type: Long,
    val symbol: String,
    val addend: Long,
)

data class StringInfo(
    val offset: Long,
    val value: String,
    val length: Int,
    val section: String,
    val encoding: String = "UTF-8",
    val confidence: Double = 1.0,
)

data class ProgramHeaderInfo(
    val type: Long,
    val flags: Long,
    val offset: Long,
    val vaddr: Long,
    val paddr: Long,
    val filesz: Long,
    val memsz: Long,
    val align: Long,
)

data class DynamicEntryInfo(
    val tag: Long,
    val value: Long,
)

data class ElfFile(
    val data: ByteArray,
    val bits: Int,
    val littleEndian: Boolean,
    val type: Int,
    val machine: Int,
    val entry: Long,
    val sections: List<SectionInfo>,
    val symbols: List<SymbolInfo>,
    val dynSymbols: List<SymbolInfo>,
    val relocations: List<RelocInfo>,
    val strings: List<StringInfo>,
    val programHeaders: List<ProgramHeaderInfo> = emptyList(),
    val dynamicEntries: List<DynamicEntryInfo> = emptyList(),
) {
    val architecture: String = when (machine) {
        40 -> "arm32"
        183 -> "arm64"
        3 -> "x86"
        62 -> "x86_64"
        8 -> "mips"
        else -> "unknown"
    }

    val endian: String = if (littleEndian) "little" else "big"
    val machineName: String = when (machine) {
        40 -> "EM_ARM"
        183 -> "EM_AARCH64"
        3 -> "EM_386"
        62 -> "EM_X86_64"
        8 -> "EM_MIPS"
        else -> "EM_$machine"
    }
}
