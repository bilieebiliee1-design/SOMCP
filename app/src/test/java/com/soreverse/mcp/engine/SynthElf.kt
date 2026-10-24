// SPDX-License-Identifier: AGPL-3.0-only
//
// Synthetic ELF64/AArch64 fixture for audit tests: identity vaddr mapping,
// PT_LOAD + PT_DYNAMIC + PT_NOTE, dynsym/dynstr/rela/dynamic/text/rodata/note
// sections, an optional W+X section and optional crypto constants in .rodata.
package com.soreverse.mcp.engine

import java.io.ByteArrayOutputStream

internal object SynthElf {
    private val AES_SBOX_32 = byteArrayOf(
        0x63, 0x7c, 0x77, 0x7b, 0xf2.toByte(), 0x6b, 0x6f, 0xc5.toByte(), 0x30, 0x01, 0x67, 0x2b, 0xfe.toByte(), 0xd7.toByte(), 0xab.toByte(), 0x76,
        0xca.toByte(), 0x82.toByte(), 0xc9.toByte(), 0x7d, 0xfa.toByte(), 0x59, 0x47, 0xf0.toByte(), 0xad.toByte(), 0xd4.toByte(), 0xa2.toByte(),
        0xaf.toByte(), 0x9c.toByte(), 0xa4.toByte(), 0x72, 0xc0.toByte()
    )

    private fun le32(v: Int): ByteArray = byteArrayOf(
        (v and 0xff).toByte(),
        ((v shr 8) and 0xff).toByte(),
        ((v shr 16) and 0xff).toByte(),
        ((v shr 24) and 0xff).toByte()
    )

    private fun le64(v: Long): ByteArray = ByteArray(8) { i -> ((v shr (i * 8)) and 0xff).toByte() }

    private fun concat(vararg parts: ByteArray): ByteArray {
        val out = ByteArrayOutputStream()
        parts.forEach { out.write(it) }
        return out.toByteArray()
    }

    fun build(includeCrypto: Boolean = false, withWxSection: Boolean = false): ByteArray {
        val dynstr = "libc.so\u0000libtest.so\u0000Java_com_test_Foo_bar\u0000".toByteArray(Charsets.ISO_8859_1)
        val dynsym = concat(
            ByteArray(24),
            concat(
                le32(19),
                byteArrayOf(0x12, 0),
                le16(5),
                le64(0x100),
                le64(16)
            )
        )
        val rela = concat(le64(0x2000), le64(1027), le64(0))
        val dynstrOffset = 64 + 3 * 56 + dynsym.size
        val dynamic = dynamicTable(dynstr.size, dynstrOffset)
        val note = concat(
            le32(8),
            le32(12),
            le32(1),
            "Android\u0000".toByteArray(Charsets.ISO_8859_1),
            le32(29),
            le32(((27L shl 25) or (1L shl 14) or 855L).toInt()),
            "b1\u0000\u0000".toByteArray(Charsets.ISO_8859_1)
        )
        val rodata = concat(
            "https://example.com/path\u000010.0.0.1:8080\u0000/proc/self/maps\u0000ro.build.version.sdk\u0000".toByteArray(Charsets.ISO_8859_1),
            byteArrayOf(0x74, 0, 0x65, 0, 0x73, 0, 0x74, 0),
            if (includeCrypto) {
                concat(
                    AES_SBOX_32,
                    "expand 32-byte k".toByteArray(Charsets.US_ASCII),
                    byteArrayOf(0x78, 0xa5.toByte(), 0x76, 0xd7.toByte())
                )
            } else {
                ByteArray(0)
            }
        )
        val text = concat(
            byteArrayOf(0x1f, 0x20, 0x03, 0xd5.toByte(), 0x1f, 0x20, 0x03, 0xd5.toByte(), 0x14, 0x00, 0x00, 0x14, 0x1f, 0x20, 0x03, 0xd5.toByte()),
            ByteArray(32)
        )
        val sections = mutableListOf(
            Sec(".dynsym", 11, 0x2, dynsym, entsize = 24, link = 2),
            Sec(".dynstr", 3, 0x2, dynstr),
            Sec(".rela.dyn", 4, 0x2, rela, entsize = 24, link = 1),
            Sec(".dynamic", 6, 0x6, dynamic, entsize = 16, link = 2),
            Sec(".text", 1, 0x6, text, align = 16),
            Sec(".rodata", 1, 0x2, rodata),
            Sec(".note.android.ident", 7, 0x2, note, align = 4)
        )
        if (withWxSection) sections += Sec(".wx_evil", 1, 0x7, ByteArray(16))
        val shstrtabNames = listOf("") + sections.map { it.name } + listOf(".shstrtab")
        val shstrtab = shstrtabNames.joinToString("\u0000").toByteArray(Charsets.ISO_8859_1) + byteArrayOf(0)
        sections += Sec(".shstrtab", 3, 0, shstrtab)

        val shnum = sections.size + 1
        val phnum = 3
        val phdrEnd = 64 + phnum * 56
        var cursor = phdrEnd
        val offsets = mutableListOf<Long>()
        sections.forEach { sec ->
            offsets += cursor.toLong()
            cursor += sec.bytes.size
        }
        var shoff = cursor
        if (shoff % 8 != 0) shoff += 8 - (shoff % 8)
        val total = shoff + shnum * 64

        val nameOffsets = HashMap<String, Int>()
        var nameCursor = 0
        shstrtabNames.forEach { n ->
            nameOffsets[n] = nameCursor
            nameCursor += n.length + 1
        }

        val textIndex = sections.indexOfFirst { it.name == ".text" }
        val ehdr = concat(
            byteArrayOf(0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0), ByteArray(8),
            le16(3), le16(183), le32(1), le64(offsets[textIndex]), le64(64), le64(shoff.toLong()),
            le32(0), le16(64), le16(56), le16(phnum), le16(64), le16(shnum), le16(shnum - 1)
        )
        val phdrs = concat(
            phdr(type = 1, flags = 7, offset = 0, vaddr = 0, filesz = total.toLong(), memsz = total.toLong(), align = 0x1000),
            phdr(
                type = 2,
                flags = 6,
                offset = offsets[sections.indexOfFirst { it.name == ".dynamic" }],
                vaddr = offsets[sections.indexOfFirst { it.name == ".dynamic" }],
                filesz = sections.first { it.name == ".dynamic" }.bytes.size.toLong(),
                memsz = sections.first { it.name == ".dynamic" }.bytes.size.toLong(),
                align = 8
            ),
            phdr(
                type = 4,
                flags = 4,
                offset = offsets[sections.indexOfFirst { it.name == ".note.android.ident" }],
                vaddr = offsets[sections.indexOfFirst { it.name == ".note.android.ident" }],
                filesz = sections.first { it.name == ".note.android.ident" }.bytes.size.toLong(),
                memsz = sections.first { it.name == ".note.android.ident" }.bytes.size.toLong(),
                align = 4
            )
        )

        val body = ByteArrayOutputStream()
        body.write(ehdr)
        body.write(phdrs)
        sections.forEachIndexed { i, sec ->
            require(body.size() == offsets[i].toInt()) { "layout drift at ${sec.name}" }
            body.write(sec.bytes)
        }
        require(body.size() <= shoff) { "shdr overlap" }
        repeat(shoff - body.size()) { body.write(0) }
        // section headers: null entry first
        body.write(ByteArray(64))
        sections.forEachIndexed { i, sec ->
            body.write(
                concat(
                    le32(nameOffsets[sec.name] ?: 0), le32(sec.type), le64(sec.flags), le64(offsets[i]),
                    le64(offsets[i]), le64(sec.bytes.size.toLong()), le32(sec.link), le32(sec.info),
                    le64(sec.align), le64(sec.entsize)
                )
            )
        }
        val out = body.toByteArray()
        require(out.size == total) { "size mismatch ${out.size} != $total" }
        return out
    }

    private class Sec(
        val name: String,
        val type: Int,
        val flags: Long,
        val bytes: ByteArray,
        val entsize: Long = 0,
        val link: Int = 0,
        val info: Int = 0,
        val align: Long = 1
    )

    private fun le16(v: Int) = byteArrayOf((v and 0xff).toByte(), ((v shr 8) and 0xff).toByte())

    private fun phdr(type: Int, flags: Int, offset: Long, vaddr: Long, filesz: Long, memsz: Long, align: Long): ByteArray =
        concat(le32(type), le32(flags), le64(offset), le64(vaddr), le64(vaddr), le64(filesz), le64(memsz), le64(align))

    private fun dynamicTable(dynstrSize: Int, dynstrOffset: Int): ByteArray = concat(
        le64(1), le64(0), // DT_NEEDED libc.so
        le64(14), le64(8), // DT_SONAME libtest.so
        le64(5), le64(dynstrOffset.toLong()), // DT_STRTAB (identity vaddr mapping)
        le64(10), le64(dynstrSize.toLong()), // DT_STRSZ
        le64(30), le64(0x8), // DT_FLAGS = BIND_NOW
        le64(0x6ffffffbL), le64(0x1), // DT_FLAGS_1 = NOW
        le64(0), le64(0) // DT_NULL
    )
}
