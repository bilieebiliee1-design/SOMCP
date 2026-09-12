#!/usr/bin/env python3
# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - tools/verify_unicorn_jni.py
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
"""Fail the build when libunicorn.so is not the unidbg unicorn2 JNI bridge.

Why this check exists
---------------------
SOMCP drives unidbg through its *unicorn2* backend: `Unicorn2Factory` creates a
`Unicorn2Backend`, which wraps `com.github.unidbg.arm.backend.unicorn.Unicorn`.
That Java class is a plain **JNI** binding - every entry point is a `native`
method whose symbol name is derived from the class and method name, i.e.

    Java_com_github_unidbg_arm_backend_unicorn_Unicorn_<method>

Consequently the `libunicorn.so` shipped inside the APK must export those
symbols. The raw unicorn engine does *not*: it only exports the flat `uc_*`
C API, and the JNI bridge lives in unidbg's own
`backend/unicorn2/src/main/native/unicorn.c`, which has to be compiled and
linked against the engine archive.

Shipping an engine-only `libunicorn.so` is a silent failure at runtime:
`System.loadLibrary("unicorn")` succeeds, so `UnidbgEmulator.available()` still
reports the backend as usable; only when a session is opened does
`Unicorn2Backend` fail to bind and (because the app registers
`Unicorn2Factory(true)`) `BackendFactory.newBackend` swallows the error and
falls back to the legacy `UnicornBackend`, which then dies with
`NoClassDefFoundError: unicorn.Unicorn` on builds that do not bundle the
`unicorn.*` classes - see issue #91. That produced a release APK whose
emulation path could never work while still looking "bundled-ok".

Usage
-----
    python3 tools/verify_unicorn_jni.py <libunicorn.so> [more .so ...]
    python3 tools/verify_unicorn_jni.py --abi arm64-v8a <SOMCP-*.apk>

Exit status is 0 only when every inspected library exports the bridge.
"""

from __future__ import annotations

import argparse
import struct
import sys
import zipfile
from typing import Iterable

# Every native method of com.github.unidbg.arm.backend.unicorn.Unicorn (unidbg
# 0.9.9) maps to a symbol with this prefix. JNI escapes '_' inside Java names
# as "_1", hence e.g. `emu_1start` for `emu_start`.
JNI_PREFIX = "Java_com_github_unidbg_arm_backend_unicorn_Unicorn_"

# Methods the backend cannot work without. Matched as prefixes so overloaded
# entry points (whose names carry a signature suffix, e.g. reg_1read__JII) and
# future additions do not make this check brittle.
REQUIRED_METHOD_PREFIXES = (
    "nativeInitialize",
    "nativeDestroy",
    "emu_1start",
    "emu_1stop",
    "mem_1read",
    "mem_1write",
    "mem_1map",
    "mem_1protect",
    "mem_1unmap",
    "reg_1read",
    "reg_1write",
    "context_1alloc",
    "context_1save",
    "context_1restore",
    "hook_1del",
    "registerHook",
    "registerDebugger",
    "addBreakPoint",
    "removeBreakPoint",
    "setSingleStep",
    "free",
)

# The bridge has 31 exported entry points today; requiring a clear majority
# catches a truncated/partial link without turning an upstream addition into a
# build failure.
MIN_EXPORTED_SYMBOLS = 20

APK_LIB_PREFIX = "lib/"
APK_LIB_NAME = "libunicorn.so"


class VerifyError(Exception):
    """Raised when a library is unreadable or does not satisfy the contract."""


def _read_dynamic_symbols(blob: bytes) -> list[str]:
    """Return the names of the defined symbols in an ELF's .dynsym.

    Only the dynamic symbol table matters: that is what the Android dynamic
    linker resolves JNI entry points against.
    """
    if len(blob) < 52 or blob[:4] != b"\x7fELF":
        raise VerifyError("not an ELF file")

    elf_class = blob[4]
    data = blob[5]
    if data != 1:
        raise VerifyError("big-endian ELF is not supported")

    if elf_class == 2:  # ELF64
        shoff, = struct.unpack_from("<Q", blob, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 0x3A)
        sh_fmt = "<IIQQQQIIQQ"
        sym_fmt = "<IBBHQQ"
        sym_size = 24
    elif elf_class == 1:  # ELF32
        shoff, = struct.unpack_from("<I", blob, 0x20)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", blob, 0x2E)
        sh_fmt = "<IIIIIIIIII"
        sym_fmt = "<IIIBBH"
        sym_size = 16
    else:
        raise VerifyError(f"unknown ELF class {elf_class}")

    if not shoff or not shnum:
        raise VerifyError("ELF has no section headers (stripped section table?)")

    sections = []
    for index in range(shnum):
        offset = shoff + index * shentsize
        if offset + struct.calcsize(sh_fmt) > len(blob):
            raise VerifyError("truncated section header table")
        values = struct.unpack_from(sh_fmt, blob, offset)
        sections.append(
            {
                "name": values[0],
                "type": values[1],
                "offset": values[4],
                "size": values[5],
                "link": values[6],
                "entsize": values[9],
            }
        )

    def section_name(name_offset: int) -> str:
        strtab = sections[shstrndx]
        start = strtab["offset"] + name_offset
        end = blob.index(b"\0", start)
        return blob[start:end].decode("utf-8", "replace")

    named = {}
    for section in sections:
        named.setdefault(section_name(section["name"]), section)

    dynsym = named.get(".dynsym")
    dynstr = named.get(".dynstr")
    if dynsym is None or dynstr is None:
        raise VerifyError("ELF has no .dynsym/.dynstr (no exported symbols)")

    string_table = blob[dynstr["offset"]: dynstr["offset"] + dynstr["size"]]
    entry_size = dynsym["entsize"] or sym_size
    count = dynsym["size"] // entry_size

    def string_at(offset: int) -> str:
        if offset >= len(string_table):
            return ""
        end = string_table.find(b"\0", offset)
        if end < 0:
            end = len(string_table)
        return string_table[offset:end].decode("utf-8", "replace")

    symbols: list[str] = []
    for index in range(count):
        offset = dynsym["offset"] + index * entry_size
        if offset + struct.calcsize(sym_fmt) > len(blob):
            break
        values = struct.unpack_from(sym_fmt, blob, offset)
        name_offset = values[0]
        # shndx == 0 means UND (imported, not exported).
        shndx = values[3] if elf_class == 2 else values[5]
        if shndx == 0:
            continue
        name = string_at(name_offset)
        if name:
            symbols.append(name)
    return symbols


def _check_symbols(symbols: Iterable[str], label: str) -> bool:
    bridge = sorted({s for s in symbols if s.startswith(JNI_PREFIX)})
    methods = {s[len(JNI_PREFIX):] for s in bridge}
    missing = [
        prefix
        for prefix in REQUIRED_METHOD_PREFIXES
        if not any(method.startswith(prefix) for method in methods)
    ]

    print(f"[verify-unicorn-jni] {label}")
    print(f"  exported unidbg unicorn2 JNI symbols: {len(bridge)} (need >= {MIN_EXPORTED_SYMBOLS})")

    problems = []
    if len(bridge) < MIN_EXPORTED_SYMBOLS:
        problems.append(
            "too few JNI entry points - this looks like the raw unicorn engine "
            "(uc_* API only) instead of unidbg's JNI bridge"
        )
    if missing:
        problems.append("missing required entry points: " + ", ".join(missing))

    if problems:
        for problem in problems:
            print(f"  FAIL: {problem}")
        print(
            "  hint: rebuild with build-unidbg-native.sh / build-unidbg-native.ps1; the bridge is "
            "unidbg's backend/unicorn2/src/main/native/unicorn.c linked against the unicorn engine archive"
        )
        return False

    print("  OK: JNI bridge present")
    return True


def _verify_file(path: str) -> bool:
    with open(path, "rb") as handle:
        blob = handle.read()
    return _check_symbols(_read_dynamic_symbols(blob), path)


def _verify_apk(path: str, abis: list[str]) -> bool:
    ok = True
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        for abi in abis:
            entry = f"{APK_LIB_PREFIX}{abi}/{APK_LIB_NAME}"
            if entry not in names:
                # 32-bit ABIs legitimately have no unicorn (QEMU/__uint128_t).
                print(f"[verify-unicorn-jni] {path}!{entry}: absent (skipped)")
                continue
            blob = archive.read(entry)
            label = f"{path}!{entry}"
            # Kept separate so a parse failure is reported per ABI.
            try:
                symbols = _read_dynamic_symbols(blob)
            except VerifyError as error:
                print(f"[verify-unicorn-jni] {label}")
                print(f"  FAIL: {error}")
                ok = False
                continue
            ok = _check_symbols(symbols, label) and ok
    return ok


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("paths", nargs="+", help="libunicorn.so and/or APK files to inspect")
    parser.add_argument(
        "--abi",
        action="append",
        dest="abis",
        help="ABI to inspect inside an APK (repeatable; default: arm64-v8a x86_64)",
    )
    args = parser.parse_args(argv)
    abis = args.abis or ["arm64-v8a", "x86_64"]

    ok = True
    for path in args.paths:
        if path.lower().endswith(".apk"):
            ok = _verify_apk(path, abis) and ok
        else:
            try:
                ok = _verify_file(path) and ok
            except (OSError, VerifyError) as error:
                print(f"[verify-unicorn-jni] {path}")
                print(f"  FAIL: {error}")
                ok = False

    if ok:
        print("[verify-unicorn-jni] PASS")
        return 0
    print("[verify-unicorn-jni] FAILED")
    return 1


if __name__ == "__main__":
    sys.exit(main())
