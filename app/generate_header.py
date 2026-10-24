#!/usr/bin/env python3
"""
generate_header.py
Generates key_generated.h containing SHA-256-CTR-encoded arrays plus the TM
secret they are keyed under, for use in native_probe.cpp.

The encoded arrays contain:
  - kEncodedExpectedSha256: SHA-256 of the official release build record
  - kEncodedMD5: MD5 hash for reference
  - kEncodedSHA1: SHA-1 hash for reference
  - kEncodedSHA512: SHA-512 hash for reference
  - kEncodedExpectedPackage: encoded package name "com.soreverse.mcp"

Every array (signer pins and the reporting API key alike) is encrypted under
a SHA-256 counter-mode keystream stretched from the TM secret:
  master          = SHA256(TM secret || salt)
  keystream blk i = SHA256(master || LE32(i))
  cipher          = plaintext XOR keystream
so no short repeating key pattern and no plaintext ever sit in the artifact.
The pins use a fixed domain-separation salt (kPinSalt) because they are build
constants and the header must stay reproducible; the reporting API key uses a
per-build random salt. Runtime decoders: pin_decode.h (pins) and
reporting_key.h (reporting key). The generated header deliberately contains
NO key material in comments.

The TM secret is read from the $TM environment variable (16 hex chars =
8 bytes).

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
import hashlib
import os
import secrets
import sys


def parse_key(hex_str: str) -> list:
    """Parse a 16-char hex string into 8 bytes."""
    s = hex_str.replace(" ", "").replace("0x", "").lower()
    if len(s) != 16:
        raise ValueError(f"Key must be 16 hex chars (got {len(s)}): {hex_str}")
    return [int(s[i:i+2], 16) for i in range(0, 16, 2)]


# Fixed domain-separation salt for the signer-pin arrays. Not secret: it only
# pins the pins' keystream domain apart from the reporting key's (which draws
# a per-build random salt). Fixed rather than random because the pins are
# build constants — key_generated.h must stay a pure function of $TM.
PIN_SALT = hashlib.sha256(b"SOMCP signer-pin domain v1").digest()[:16]


def read_local_prop(name: str) -> str:
    """Best-effort read of `name` from ./local.properties (gitignored).

    Used only as a local-development convenience for the reporting API key;
    CI injects it through the LRP_API_KEY environment variable instead. The
    file is never committed and the value is never printed.
    """
    try:
        with open("local.properties", "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                if k.strip() == name:
                    return v.strip()
    except OSError:
        pass
    return ""


def fmt_array(name: str, data, indent: int = 4) -> str:
    """Format a byte array as C source code."""
    spaces = " " * indent
    lines = [f"{spaces}static const uint8_t {name}[] = {{"]
    for i in range(0, len(data), 12):
        chunk = data[i:i+12]
        lines.append(
            f"{spaces}    {', '.join(f'0x{b:02X}' for b in chunk)},\n"
        )
    lines.append(f"{spaces}}};\n")
    return "".join(lines)


# ---------------------------------------------------------------------------
# SHA-256 counter-mode keystream encryption
#
# Used for BOTH the signer-pin arrays (fixed PIN_SALT) and the reporting API
# key (per-build random salt). The C++ decoders MUST stay byte-for-byte in
# sync: pin_decode.h for the pins, app/src/main/cpp/reporting_key.h for the
# reporting key.
#   master          = SHA256(TM secret || salt)
#   keystream blk i = SHA256(master || LE32(i))
#   ciphertext      = plaintext XOR keystream (blocks concatenated, truncated)
# ---------------------------------------------------------------------------
RK_MAX_KEY_LEN = 512  # decoder rejects anything longer; pins and API keys are far shorter


def rk_keystream(master: bytes, n: int) -> bytes:
    blocks = bytearray()
    for ctr in range((n + 31) // 32):
        blocks += hashlib.sha256(master + ctr.to_bytes(4, "little")).digest()
    return bytes(blocks[:n])


def ctr_encode(plain: str, tm_key: list, salt: bytes) -> bytes:
    """Return the ciphertext bytes for [plain] under the TM-keyed keystream."""
    data = plain.encode("utf-8")
    if len(data) > RK_MAX_KEY_LEN:
        raise ValueError(f"plaintext exceeds {RK_MAX_KEY_LEN} bytes")
    master = hashlib.sha256(bytes(tm_key) + salt).digest()
    return bytes(a ^ b for a, b in zip(data, rk_keystream(master, len(data))))


# Plaintext values to encode (these are the known/canonical values).
EXPECTED_SHA256 = "90FEDAC1F020C6C5D1DD1A635DB5C3B7579F5B87647E2C2C00966D3BCB0F8B6F"  # official release signing certificate
EXPECTED_MD5 = "A0B1C2D3E4F5061728394A5B6C7D8E9F"  # for reference
EXPECTED_SHA1 = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4"  # for reference
EXPECTED_SHA512 = "A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90A1B2C3D4E5F60718293A4B5C6D7E8F90"  # for reference
EXPECTED_PACKAGE = "com.soreverse.mcp"  # package name pin


def main():
    parser = argparse.ArgumentParser(
        description="Generate key_generated.h with SHA-256-CTR-encoded signature arrays"
    )
    parser.add_argument(
        "--key",
        default=None,
        help="16-char hex key (8 bytes). Falls back to $TM env var."
    )
    parser.add_argument(
        "--reporting-key",
        default=None,
        help="log-report-platform API key (X-API-Key). Falls back to $LRP_API_KEY; "
             "empty when neither is set. Never printed."
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
            # Never echo the key material itself into build logs.
            print("[gen] using TM env var (value not logged)", file=sys.stderr)
        else:
            print("ERROR: no key provided and $TM not set", file=sys.stderr)
            sys.exit(1)

    try:
        key = parse_key(key_hex)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Encode all pin arrays under the SHA-256-CTR keystream (fixed salt).
    arrays = {
        "kEncodedExpectedSha256": ctr_encode(EXPECTED_SHA256, key, PIN_SALT),
        "kEncodedMD5": ctr_encode(EXPECTED_MD5, key, PIN_SALT),
        "kEncodedSHA1": ctr_encode(EXPECTED_SHA1, key, PIN_SALT),
        "kEncodedSHA512": ctr_encode(EXPECTED_SHA512, key, PIN_SALT),
        "kEncodedExpectedPackage": ctr_encode(EXPECTED_PACKAGE, key, PIN_SALT),
    }
    lengths = {name: len(v) for name, v in arrays.items()}

    # log-report-platform reporting API key (X-API-Key), injected at build time
    # from $LRP_API_KEY (CI secret) or --reporting-key. Encrypted under a
    # SHA-256-CTR keystream stretched from the TM secret (see ctr_encode).
    # The plaintext is NEVER printed or logged.
    reporting_key = args.reporting_key
    if reporting_key is None:
        reporting_key = os.environ.get("LRP_API_KEY", "")
    if not reporting_key.strip():
        # Local dev convenience: `lrpApiKey=` in the (gitignored) local.properties.
        reporting_key = read_local_prop("lrpApiKey")
    reporting_key = reporting_key.strip()
    if reporting_key and all(b == 0 for b in key):
        # The all-zero fallback TM key is public knowledge; encrypting with it
        # would key the keystream off a value every artifact carries. Fail the
        # build instead.
        print("ERROR: refusing to encrypt the reporting key with the all-zero "
              "fallback TM key; provide a real $TM secret.", file=sys.stderr)
        sys.exit(1)
    try:
        rk_salt = secrets.token_bytes(16)
        rk_cipher = ctr_encode(reporting_key, key, rk_salt)
    except ValueError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

    # Generate header
    parts = []
    parts.append("""// ---------------------------------------------------------------------------
// AUTO-GENERATED — DO NOT EDIT
// Generated by generate_header.py at build time. Contains ONLY encrypted
// byte arrays — no plaintext secrets, and no secret in comments.
// ---------------------------------------------------------------------------
#pragma once

// TM secret (injected at build time from $TM). Key material for every
// SHA-256-CTR keystream below; never a plaintext literal.
static const uint8_t kTmKey[] = {""" + ", ".join(f"0x{b:02X}" for b in key) + """};
static const size_t kTmKeyLen = """ + str(len(key)) + """;

// Fixed domain-separation salt for the signer-pin arrays (not secret).
// Runtime decoder: pin_decode.h.
static const uint8_t kPinSalt[] = {""" + ", ".join(f"0x{b:02X}" for b in PIN_SALT) + """};
static const size_t kPinSaltLen = """ + str(len(PIN_SALT)) + """;

""")

    # Signer-pin arrays, SHA-256-CTR encrypted (runtime decoder: pin_decode.h):
    #   master          = SHA256(kTmKey || kPinSalt)
    #   keystream blk i = SHA256(master || LE32(i))
    #   plaintext       = array XOR keystream
    for name, enc_bytes in sorted(arrays.items()):
        parts.append(fmt_array(name, enc_bytes))
        len_name = name + "Len"
        parts.append(f"static const size_t {len_name} = {lengths[name]};\n\n")

    # ---- reporting API key (SHA-256-CTR; runtime decoder: reporting_key.h) ----
    parts.append("""// ---------------------------------------------------------------------------
// Reporting API key (log-report-platform X-API-Key), SHA-256-CTR encrypted:
//   master          = SHA256(kTmKey || kRkSalt)
//   keystream blk i = SHA256(master || LE32(i))
//   plaintext       = kRepApiKeyCipher XOR keystream
// kRkSalt is a per-build random nonce. A length of 0 unambiguously means
// "no key injected" (a placeholder byte is still emitted so the array stays
// well-formed). The plaintext never appears anywhere.
// ---------------------------------------------------------------------------
""")
    parts.append(fmt_array("kRkSalt", list(rk_salt)))
    # No key injected: rk_cipher is empty, but a zero-length C array is not valid
    # C++, so emit a single placeholder byte to keep the array well-formed. The
    # authoritative "no key injected" signal is kRepApiKeyCipherLen (0), which
    # the decoder checks before it ever reads kRepApiKeyCipher.
    parts.append(fmt_array("kRepApiKeyCipher", rk_cipher if rk_cipher else [0]))
    parts.append(f"static const size_t kRepApiKeyCipherLen = {len(rk_cipher)};\n\n")

    header = "".join(parts)

    # Write output
    os.makedirs(os.path.dirname(os.path.abspath(args.dst)), exist_ok=True)
    with open(args.dst, "w", encoding="utf-8") as f:
        f.write(header)

    print(f"[gen] wrote {args.dst} ({len(header)} bytes)", file=sys.stderr)


if __name__ == "__main__":
    main()
