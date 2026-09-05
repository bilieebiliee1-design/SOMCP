#!/usr/bin/env python3
"""
generate_header.py
Generates key_generated.h containing XOR-encoded arrays and the rotating
multi-byte XOR key for use in signature_verify.cpp.

The encoded arrays contain:
  - kEncodedExpectedSha256: SHA-256 of the official release signing certificate
  - kEncodedMD5: MD5 hash for reference
  - kEncodedSHA1: SHA-1 hash for reference
  - kEncodedSHA512: SHA-512 hash for reference
  - kEncodedExpectedPackage: XOR-encoded package name "com.soreverse.mcp"

The key is read from the $TM environment variable (16 hex chars = 8 bytes).

Usage:
    python generate_header.py --key <16-hex-chars> --dst <key_generated.h>

If no --key is given, reads the $TM environment variable.
"""
# SPDX-License-Identifier: AGPL-3.0-or-later
#
# Copyright (C) 2026 bilieebiliee1-design
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.
#
# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.

import argparse
import os
Reads the current signature_verify.cpp encoded arrays, re-encodes them with
a new multi-byte rotating XOR key from the TM environment variable, and writes
key_generated.h for CMake to include.

Usage:
    python generate_header.py --key <32-char-hex> --src <signature_verify.cpp> --dst <key_generated.h>

Key format: 16 hex chars (8 bytes), e.g. from the TM GitHub Actions secret.
If no --key is given, reads the TM environment variable.
"""

import argparse
import os
import re
import sys


def parse_key(hex_str: str) -> list:
    """Parse a 16-char hex string into 8 bytes."""
    s = hex_str.replace(" ", "").replace("0x", "").lower()
    if len(s) != 16:
        raise ValueError(f"Key must be 16 hex chars (got {len(s)}): {hex_str}")
    return [int(s[i:i+2], 16) for i in range(0, 16, 2)]


def xor_encode(plain: str, key: list) -> list:
    """Encode plaintext bytes using rotating XOR with the given key."""
    return [ord(c) ^ key[i % len(key)] for i, c in enumerate(plain)]


def fmt_array(name: str, data: list, indent: int = 4) -> str:
    """Format a byte array as C source code."""
    spaces = " " * indent
    lines = [f'{spaces}static const uint8_t {name}[] = {{']
    lines = [f"{spaces}static const uint8_t {name}[] = {{"]
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        lines.append(
            f"{spaces}    {', '.join(f'0x{b:02X}' for b in chunk)},\n"
        )
    lines.append(f"{spaces}}};\n")
    return "".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Generate key_generated.h with XOR-encoded signature arrays"
def extract_arrays(text: str) -> dict:
    """Extract all XOR-encoded arrays from signature_verify.cpp."""
    pattern = r"static\s+const\s+uint8_t\s+(\w+)\[\]\s*=\s*\{([^}]+)\};"
    result = {}
    for match in re.finditer(pattern, text, re.DOTALL):
        name = match.group(1)
        if name.startswith("kXorKey"):
            continue
        bytes_list = [int(x, 16) for x in re.findall(r"0x([0-9A-Fa-f]{2})", match.group(2))]
        result[name] = bytes_list
    return result


def main():
    parser = argparse.ArgumentParser(
        description="Generate key_generated.h from XOR-encoded signature_verify.cpp"
    )
    parser.add_argument(
        "--key",
        default=None,
        help="16-char hex key (8 bytes). Falls back to $TM env var."
    )
    parser.add_argument(
        "--src",
        required=True,
        help="Path to signature_verify.cpp"
    )
    parser.add_argument(
        "--dst",
        required=True,
        help="Output path for key_generated.h"
    )
    args = parser.parse_args()

    # Determine key
    key_hex = args.key
    if key_hex is None:
        tm_env = os.environ.get("TM", "").strip()
        if tm_env:
            key_hex = tm_env.lower()
            print(f"[gen] using TM env var: {key_hex}", file=sys.stderr)
        else:
            print("ERROR: no key provided and $TM not set", file=sys.stderr)
            sys.exit(1)

    try:
        key = parse_key(key_hex)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Plaintext values to encode (these are the known/canonical values)
    # SHA-256 of the official release signing certificate
    EXPECTED_SHA256 = "90FEDAC1F020C6C5D1DD1A635DB5C3B7579F5B87647E2C2C00966D3BCB0F8B6F"
    # MD5 for reference
    EXPECTED_MD5 = "A0B1C2D3E4F5061728394A5B6C7D8E9F"
    # SHA-1 for reference
    EXPECTED_SHA1 = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4"
    # SHA-512 for reference
    EXPECTED_SHA512 = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90"
    # Package name pin
    EXPECTED_PACKAGE = "com.soreverse.mcp"

    # Encode all arrays with the new key
    arrays = {
        "kEncodedExpectedSha256": xor_encode(EXPECTED_SHA256, key),
        "kEncodedMD5": xor_encode(EXPECTED_MD5, key),
        "kEncodedSHA1": xor_encode(EXPECTED_SHA1, key),
        "kEncodedSHA512": xor_encode(EXPECTED_SHA512, key),
        "kEncodedExpectedPackage": xor_encode(EXPECTED_PACKAGE, key),
    }

    # Generate header
    parts = []
    parts.append("""// ---------------------------------------------------------------------------
// AUTO-GENERATED — DO NOT EDIT
// Generated by generate_header.py
    # Read source
    with open(args.src, encoding="utf-8") as f:
        src_text = f.read()

    # Extract existing encoded arrays
    arrays = extract_arrays(src_text)

    if not arrays:
        print("ERROR: no encoded arrays found in source", file=sys.stderr)
        sys.exit(1)

    print(f"[gen] extracted {len(arrays)} arrays from {args.src}", file=sys.stderr)

    # Generate header — re-encode all arrays with the new key
    parts = []
    parts.append("""// ---------------------------------------------------------------------------
// AUTO-GENERATED — DO NOT EDIT
// Generated by generate_header.py from signature_verify.cpp
// Key: """ + "".join(f"{b:02X}" for b in key) + """
// ---------------------------------------------------------------------------
#pragma once

// Multi-byte rotating XOR key (injected at build time from $TM secret)
static const uint8_t kXorKey[] = {""" + ", ".join(f"0x{b:02X}" for b in key) + """};
static const size_t kXorKeyLen = """ + str(len(key)) + """;

""")

    for name, enc_bytes in sorted(arrays.items()):
        parts.append(fmt_array(name, enc_bytes))
        len_name = name + "Len"
        parts.append(f"static const size_t {len_name} = {len(enc_bytes)};\n\n")
        # Decode to get plaintext, then re-encode with new key
        plain = "".join(chr(b ^ key[i % 8]) for i, b in enumerate(enc_bytes))
        re_enc = xor_encode(plain, key)
        parts.append(fmt_array(name, re_enc))
        len_name = name + "Len"
        parts.append(f"static const size_t {len_name} = {len(re_enc)};\n\n")

    header = "".join(parts)

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(args.dst)), exist_ok=True)
    with open(args.dst, "w", encoding="utf-8") as f:
        f.write(header)

    print(f"[gen] wrote {args.dst} ({len(header)} bytes)", file=sys.stderr)
    print(f"[gen] key: {''.join(f'{b:02X}' for b in key)}", file=sys.stderr)


if __name__ == "__main__":
    main()
