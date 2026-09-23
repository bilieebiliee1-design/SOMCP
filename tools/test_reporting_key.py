#!/usr/bin/env python3
"""
test_reporting_key.py — round-trip test for the reporting API key codec.

Verifies that the *production* C++ decoder (app/src/main/cpp/reporting_key.h,
compiled unchanged) reproduces exactly what app/generate_header.py encrypts:

  for each case:
    1. run generate_header.py with a TM key (+ optional reporting key)
    2. emit rk_expected.h with the expected plaintext bytes
    3. compile tools/test_reporting_key.cpp to wasm32 with clang (NDK's)
    4. run check() under node; 0 == round-trip OK

Also asserts the python-side guards: over-long keys and the all-zero fallback
TM secret must make the generator fail instead of shipping weak material.

Usage:  python tools/test_reporting_key.py
Requires: node on PATH and an NDK clang++ (override via RK_CLANGXX).
"""
# SPDX-License-Identifier: AGPL-3.0-only
#
# Copyright (C) 2026 bilieebiliee1-design
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import hashlib
import os
import subprocess
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
GEN = REPO / "app" / "generate_header.py"
HARNESS = REPO / "tools" / "test_reporting_key.cpp"
CPP_DIR = REPO / "app" / "src" / "main" / "cpp"

def _ndk_search_roots() -> list[Path]:
    """Candidate NDK roots in priority order: explicit NDK vars, then
    $ANDROID_HOME/ndk, then typical per-OS SDK locations."""
    roots: list[Path] = []
    for var in ("ANDROID_NDK_HOME", "ANDROID_NDK_ROOT", "NDK_HOME", "NDK_ROOT"):
        v = os.environ.get(var, "").strip()
        if v:
            roots.append(Path(v))
    for var in ("ANDROID_HOME", "ANDROID_SDK_ROOT"):
        v = os.environ.get(var, "").strip()
        if v:
            roots.append(Path(v) / "ndk")
    roots += [
        Path("D:/Android/Sdk/ndk"),
        Path.home() / "Android" / "Sdk" / "ndk",
        Path.home() / "Library" / "Android" / "sdk" / "ndk",
    ]
    return roots


def find_clangxx() -> Path | None:
    env = os.environ.get("RK_CLANGXX", "").strip()
    if env:
        return Path(env)
    for root in _ndk_search_roots():
        if not root.is_dir():
            continue
        # An NDK var may point straight at one NDK, or at an `ndk/` dir of
        # versioned children; probe both shapes.
        for ndk in sorted([root, *filter(Path.is_dir, root.iterdir())]):
            for c in sorted(ndk.glob("toolchains/llvm/prebuilt/*/bin/clang++*")):
                if c.is_file():
                    return c
    return None


def run_gen(tmp: Path, tm_key: str, extra_gen: list) -> subprocess.CompletedProcess:
    # cwd=tmp + scrubbed env so the generator cannot pick up a developer's
    # local.properties / $LRP_API_KEY / $TM.
    env = {k: v for k, v in os.environ.items() if k not in ("LRP_API_KEY", "TM")}
    return subprocess.run(
        [sys.executable, str(GEN), "--key", tm_key, "--dst", str(tmp / "key_generated.h"), *extra_gen],
        cwd=tmp, capture_output=True, text=True, env=env,
    )


def write_expected(tmp: Path, plain: str) -> None:
    data = plain.encode("utf-8")
    body = ", ".join(str(b) for b in data) if data else "0"
    (tmp / "rk_expected.h").write_text(
        "#include <stdint.h>\n"
        f"static const uint8_t kExpected[] = {{{body}}};\n"
        f"static const size_t RK_EXPECTED_LEN = {len(data)};\n",
        encoding="utf-8",
    )


def wasm_roundtrip(clangxx: Path, tmp: Path) -> int:
    exe = str(clangxx)
    wasm = tmp / "check.wasm"
    cp = subprocess.run(
        [exe, "--target=wasm32-unknown-unknown", "-std=c++17", "-O1",
         "-nostdlib", "-fno-exceptions", "-fno-rtti", "-Wall", "-Wextra",
         "-I", str(tmp), "-I", str(CPP_DIR),
         "-Wl,--no-entry", "-Wl,--export=check", "-Wl,--allow-undefined",
         "-o", str(wasm), str(HARNESS)],
        check=False, capture_output=True, text=True,
    )
    if cp.returncode != 0:
        print(cp.stdout + cp.stderr)
        raise RuntimeError("wasm compile failed")
    js = (
        "const fs=require('fs');const b=fs.readFileSync(process.argv[1]);"
        "WebAssembly.instantiate(b,{}).then(r=>process.exit(r.instance.exports.check()));"
    )
    return subprocess.run(["node", "-e", js, str(wasm)], check=False).returncode


def case_ok(name: str, cond: bool) -> bool:
    print(f"[{'PASS' if cond else 'FAIL'}] {name}")
    return cond


def main() -> int:
    clangxx = find_clangxx()
    if clangxx is None or not Path(clangxx).exists():
        print(
            "SKIP: no NDK clang++ found. Install an Android NDK (r29+) and set one of "
            "RK_CLANGXX (path to clang++), ANDROID_NDK_HOME/ANDROID_NDK_ROOT, or "
            "ANDROID_HOME (searched as $ANDROID_HOME/ndk/*/); also probed "
            "~/Android/Sdk/ndk, ~/Library/Android/sdk/ndk and D:/Android/Sdk/ndk."
        )
        return 0
    try:
        subprocess.run(["node", "--version"], check=True, capture_output=True)
    except (OSError, subprocess.CalledProcessError):
        print("SKIP: node not available")
        return 0

    tm = "90FEDAC1F020C6C5"
    ok = True

    # Python-side guards (no wasm needed).
    with tempfile.TemporaryDirectory() as td:
        tmp = Path(td)
        p = run_gen(tmp, tm, ["--reporting-key", "x" * 513])
        ok &= case_ok("generator rejects key > 512 bytes", p.returncode != 0)
        p = run_gen(tmp, "0000000000000000", ["--reporting-key", "sk-real-key"])
        ok &= case_ok("generator rejects all-zero TM + real key", p.returncode != 0)

    for name, plain in [
        ("ascii key", "sk-lrp-0123456789abcdef"),
        ("multi-block key (66 chars)", "K" + "e9x_" * 16),   # 65 chars, crosses 32B boundary
        ("no key injected", ""),
    ]:
        with tempfile.TemporaryDirectory() as td:
            tmp = Path(td)
            args = ["--reporting-key", plain] if plain else []
            p = run_gen(tmp, tm, args)
            if p.returncode != 0:
                print(f"[FAIL] {name}: generator failed: {p.stderr.strip()}")
                ok = False
                continue
            write_expected(tmp, plain)
            rc = wasm_roundtrip(clangxx, tmp)
            ok &= case_ok(f"round-trip: {name}", rc == 0)

    print("ALL OK" if ok else "FAILURES PRESENT")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
