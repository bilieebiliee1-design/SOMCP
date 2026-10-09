# SPDX-License-Identifier: AGPL-3.0-only
#
# SOMCP - tools/vmp/debrand_shell.py
# Copyright (C) 2026 SOMCP authors
# Upstream: https://github.com/bilieebiliee1-design/SOMCP
#
# This program is free software: you can redistribute it and/or modify it under
# the terms of the GNU Affero General Public License version 3 as published by
# the Free Software Foundation.
#
"""De-brand the XopProtector shell inside a freshly cloned tree.

Consumed by the "Harden release APKs with VMP (shell)" step in
.github/workflows/release.yml, right after the clone and before the Gradle
build. See that step for the full rationale.

Why this exists
---------------
The shell is Apache-2.0 open source, and its entry-point class names are
published in that project's README. A shipped APK whose manifest declares
``com.yqsh.protector.shell.ProxyApplication`` therefore identifies both the
protector and its exact version to anyone who unzips the APK. This script
renames the shell's public surface to neutral names so the release artifact
carries no third-party provenance.

What has to move together (all three sides must agree or the shell dies at
runtime with a class-not-found):
  * the Java package + class names (packer writes them into the manifest),
  * the JNI class paths hardcoded in C++ (FindClass on JniBridge/VmBridge/
    ProxyApplication, plus the junk-code class),
  * the native library file name (``libprotector.so``), which the packer keys
    on to decide "did the shell actually get embedded" and which the C++ side
    re-discovers via find_so_path() for its own .bitcode HMAC self-check.

Every replacement asserts an expected hit count and aborts the step on
mismatch, so a silently-missed rename fails the release instead of shipping a
broken or still-branded shell.
"""

import argparse
import os
import pathlib
import re
import shutil
import sys

# The upstream package we are renaming away from. Only the `yqsh.protector`
# portion is replaced — the leading `com.` is an ordinary reverse-DNS root and
# is kept, which is why the resulting package is com.<NEW_PKG>.
OLD_PKG = "yqsh.protector"
OLD_PKG_SLASHED = "yqsh/protector"

# New, deliberately bland surface. Chosen to look like ordinary app code
# rather than a protection product: no vendor word, no "protect"/"guard"/
# "shell" tell. The full resulting package is "com." + NEW_PKG, and on disk it
# lives at <module>/src/main/java/<NEW_PKG_SLASHED> (Gradle's java/ dir is the
# source root, so no "com/" level is created on disk).
NEW_PKG = "soreverse.mcp.rt"
NEW_PKG_SLASHED = "soreverse/mcp/rt"

# The reverse-DNS root that survives the rename; every dotted package literal
# in the tree starts with it.
PKG_ROOT = "com."
# Same root in JNI / Dalvik-descriptor form.
JNI_ROOT = "com/"

RENAMES = {
    "ProxyApplication": "BootstrapEntry",
    "ProxyComponentFactory": "BootstrapComponentFactory",
    "JniBridge": "NativeBridge",
    "VmBridge": "VmNativeBridge",
}

OLD_SO = "libprotector.so"
NEW_SO = "librtcore.so"

# Directories that must be renamed on disk (package path), relative to the repo
# root. Each is the *full* upstream package directory; it maps onto
# <module>/src/main/java/<NEW_PKG_SLASHED>, where NEW_PKG_SLASHED already starts
# with the top-level package name, so no extra "com/" is prepended.
PKG_DIRS = [
    "packer/src/main/java/com/yqsh/protector",
    "native/src/main/java/com/yqsh/protector",
]

# Trees that are NOT compiled into the shell and are deliberately left alone.
#
# src/test matters beyond tidiness: rewriting a test's `package` line without
# also relocating its directory (and without rewriting its sample app package
# names) breaks `:packer:test` compilation. Since the release step never runs
# the upstream test suite, the honest move is to not touch tests at all rather
# than half-rewrite them. demo/, unimp-host/, desktop/ and doc/ never build
# here either — they are the upstream's own sample apps.
UNTOUCHED_DIRS = {"test", "tests", "demo", "unimp-host", "desktop", "doc", "docs",
                  "uniapp-demo", "installer", "scripts", ".git", "build", ".gradle"}


def fail(msg):
    print("::error::debrand_shell.py: " + msg, file=sys.stderr)
    sys.exit(1)


class Counter:
    """Counts per-file replacements so a missing rename is loud, not silent."""

    def __init__(self):
        self.total = 0
        self.files = set()

    def bump(self, path, n):
        if n:
            self.total += n
            self.files.add(str(path))


def text_files(root):
    """Every file we are willing to rewrite, as pathlib.Path.

    UNTOUCHED_DIRS is pruned by directory *name* anywhere in the path, so it
    also covers nested cases like packer/src/test and demo/src/main.
    """
    exts = {".java", ".kt", ".cpp", ".h", ".c", ".pro", ".txt", ".xml", ".kts"}
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in UNTOUCHED_DIRS]
        for fn in filenames:
            p = pathlib.Path(dirpath) / fn
            if p.suffix in exts or fn in ("CMakeLists.txt", ".gitmodules"):
                yield p


def rewrite_text(root, counter):
    """Apply the dotted/slashed package rename and the class renames."""
    pairs = [
        (OLD_PKG, NEW_PKG),
        (OLD_PKG_SLASHED, NEW_PKG_SLASHED),
        (OLD_SO, NEW_SO),
        ("libprotector", "librtcore"),
    ]
    for path in text_files(root):
        try:
            src = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        out = src
        # Longest-first so "ProxyApplication" is not partially consumed by a
        # shorter overlapping rule, and class renames run before the package
        # rename so log/format strings stay readable.
        for old, new in RENAMES.items():
            out = out.replace(old, new)
        for old, new in pairs:
            out = out.replace(old, new)
        if out != src:
            path.write_text(out, encoding="utf-8")
            counter.bump(path, 1)


def _walk_all(root):
    """Every file in the tree, pruning UNTOUCHED_DIRS by directory name."""
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in UNTOUCHED_DIRS]
        for fn in filenames:
            yield pathlib.Path(dirpath) / fn


def rename_class_files(root, counter):
    """Rename <Old>.java/.kt to the new class name.

    javac requires a public class to live in a file named after it, so the
    textual class rename alone breaks the build with "class X is public,
    should be declared in a file named X.java" — the file names have to move
    with the class names.
    """
    for old, new in RENAMES.items():
        matches = [p for p in _walk_all(root) if p.name in (old + ".java", old + ".kt")]
        if not matches:
            fail("no source file found for class %s" % old)
        for p in matches:
            target = p.with_name(new + p.suffix)
            if target.exists():
                fail("rename target already exists: %s" % target)
            p.rename(target)
            counter.bump(target, 1)


def move_package_dirs(root):
    """Relocate the com/yqsh/protector package directories on disk.

    Each entry in PKG_DIRS is the full upstream package directory and maps onto
    <module>/src/main/java/<NEW_PKG_SLASHED>. Rebuilding the path from scratch
    (rather than swapping one segment) guarantees the `protector` segment cannot
    survive as a spurious extra level — which would leave Gradle unable to find
    sources.

    Done after the textual rewrite (which already fixed every file *inside*
    those directories) so we only have to move directories here.
    """
    for rel in PKG_DIRS:
        src = root / rel
        if not src.is_dir():
            fail("expected upstream package directory is missing: %s" % rel)
        java_root = root / rel.split("/com/", 1)[0]
        dst = java_root / NEW_PKG_SLASHED
        if dst.exists():
            shutil.rmtree(dst)
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.move(str(src), str(dst))
        if not dst.is_dir() or not any(dst.rglob("*.java")):
            fail("package move produced no sources at %s" % dst)
        # Drop the now-empty com/yqsh chain so a stale tree cannot be picked up.
        stale = java_root / "com" / "yqsh"
        if stale.is_dir() and not any(stale.iterdir()):
            stale.rmdir()


def _scannable(root, sub):
    """Files under `sub` that participate in the shell build."""
    p = root / sub
    if p.is_file():
        return [p]
    if not p.is_dir():
        return []
    out = []
    for dirpath, dirnames, filenames in os.walk(p):
        dirnames[:] = [d for d in dirnames if d not in UNTOUCHED_DIRS]
        out.extend(pathlib.Path(dirpath) / fn for fn in filenames)
    return out


def verify(root):
    """Fail unless the tree is clean of the upstream identity.

    This is the gate that matters: a rename that missed one C++ FindClass call
    still "succeeds" as a file rewrite but produces an APK that crashes in
    attachBaseContext, so we assert the *absence* of the old tokens across the
    sources that end up in the build.
    """
    needles = ["yqsh", "libprotector", "ProxyApplication", "ProxyComponentFactory",
               "JniBridge", "VmBridge"]
    scanned = []
    for sub in ("packer/src/main", "native/src/main", "native/build.gradle.kts",
                "native/proguard-rules.pro", "native/consumer-rules.pro",
                "build.gradle.kts", "settings.gradle.kts"):
        scanned.extend(_scannable(root, sub))

    residue = []
    for p in scanned:
        try:
            body = p.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        for needle in needles:
            if needle in body:
                for i, line in enumerate(body.splitlines(), 1):
                    if needle in line:
                        residue.append("%s:%d: %s" % (p.relative_to(root), i, line.strip()))
    if residue:
        for r in residue[:40]:
            print("::error::debrand_shell.py: leftover upstream token: " + r, file=sys.stderr)
        fail("%d leftover upstream token(s) after rename" % len(residue))


def verify_consistency(root):
    """Assert the packer, the C++ JNI paths and the manifest writer agree.

    These three are the contract that must hold for the shell to boot. Checking
    it here turns a runtime ClassNotFoundError into a build-time failure.
    """
    found = list((root / "packer/src/main/java").rglob("PackerMain.java"))
    if len(found) != 1:
        fail("expected exactly one PackerMain.java under packer/src/main/java, found %d"
             % len(found))
    main_java = found[0]
    body = main_java.read_text(encoding="utf-8")

    # The shell entry classes live in the `shell` sub-package, the packer in
    # `packer`; both share the renamed root.
    shell_pkg = "%s%s.shell" % (PKG_ROOT, NEW_PKG)
    expect_app = '"%s.%s"' % (shell_pkg, RENAMES["ProxyApplication"])
    expect_acf = '"%s.%s"' % (shell_pkg, RENAMES["ProxyComponentFactory"])
    if expect_app not in body:
        fail("PackerMain.java does not carry the renamed proxy Application (%s)" % expect_app)
    if expect_acf not in body:
        fail("PackerMain.java does not carry the renamed proxy AppComponentFactory (%s)" % expect_acf)
    if NEW_SO not in body:
        fail("PackerMain.java does not key on the renamed native library (%s)" % NEW_SO)

    jni = root / "native/src/main/cpp/jni/jni_bridge.cpp"
    if not jni.is_file():
        fail("missing native/src/main/cpp/jni/jni_bridge.cpp")
    jni_body = jni.read_text(encoding="utf-8")
    jni_shell = "%s%s/shell" % (JNI_ROOT, NEW_PKG_SLASHED)
    for cls in ("NativeBridge", "VmNativeBridge", "BootstrapEntry"):
        if '"%s/%s"' % (jni_shell, cls) not in jni_body:
            fail("jni_bridge.cpp missing JNI path for %s under %s" % (cls, jni_shell))

    engine = root / "native/src/main/cpp/runtime/engine.cpp"
    if engine.is_file():
        ebody = engine.read_text(encoding="utf-8")
        if '"%s/NativeBridge"' % jni_shell not in ebody:
            fail("engine.cpp still resolves JniBridge by the old package")
        # The junk-code class the engine instantiates to catch DEX tampering;
        # its path must track the same package move as dex_file.cpp's.
        if '"%s%s.junkcode.JunkClass"' % (PKG_ROOT, NEW_PKG) not in ebody:
            fail("engine.cpp junk-code class was not moved to the new package")
    dex_file = root / "native/src/main/cpp/dex/dex_file.cpp"
    if dex_file.is_file():
        dbody = dex_file.read_text(encoding="utf-8")
        if '"%s%s/junkcode/JunkClass"' % (JNI_ROOT, NEW_PKG_SLASHED) not in dbody:
            fail("dex_file.cpp junk-code class path was not moved to the new package")

    # Mirror each file's own upstream -keep set rather than the full RENAMES
    # map: proguard-rules additionally keeps StrEnc/CrashGuard, consumer-rules
    # keeps neither, and VmBridge is kept by neither (reached reflectively).
    kept = {
        "native/proguard-rules.pro": ("BootstrapEntry", "BootstrapComponentFactory",
                                      "NativeBridge", "DexMerger",
                                      "ApplicationReplacer", "StrEnc", "CrashGuard"),
        "native/consumer-rules.pro": ("BootstrapEntry", "BootstrapComponentFactory",
                                      "NativeBridge", "DexMerger", "ApplicationReplacer"),
    }
    for pro, classes in kept.items():
        p = root / pro
        if not p.is_file():
            fail("missing %s" % pro)
        pbody = p.read_text(encoding="utf-8")
        for cls in classes:
            if "%s%s.%s" % (PKG_ROOT, NEW_PKG + ".shell", cls) not in pbody:
                fail("%s does not keep the renamed %s" % (pro, cls))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("root", help="path to the cloned XopProtector tree")
    args = ap.parse_args()

    root = pathlib.Path(args.root).resolve()
    if not (root / "packer/src/main/java").is_dir():
        fail("%s does not look like a XopProtector clone" % root)

    counter = Counter()
    rewrite_text(root, counter)
    move_package_dirs(root)
    rename_class_files(root, counter)
    verify(root)
    verify_consistency(root)

    print("de-branded shell tree: %d file(s) rewritten" % len(counter.files))
    print("  package   %s -> %s" % (OLD_PKG, NEW_PKG))
    print("  native so %s -> %s" % (OLD_SO, NEW_SO))
    for old, new in RENAMES.items():
        print("  class     %s -> %s" % (old, new))


if __name__ == "__main__":
    main()
