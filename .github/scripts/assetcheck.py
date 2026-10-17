#!/usr/bin/env python3
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
"""Assert that a packed APK really carries encrypted assets.

Invoked by the "Harden release APKs with VMP (shell)" step of
.github/workflows/release.yml and .github/workflows/test-v10.yml, once per
shipped APK. Kept here rather than inlined in the workflows so the two call
sites cannot drift apart.

Assets encryption is a three-way contract (packer flag, app read path, this
assertion), so the check reads the shipped container rather than the packer's
log:

  * the packer's index (assets/rtcore/assets.map) exists and lists the expected
    number of paths,
  * every indexed path has ciphertext under assets/rtcore/aenc/ AND no longer
    exists in plaintext -- the latter is what a "relocated but not encrypted"
    run would fail,
  * sampled ciphertext is PAS1-prefixed and long enough to carry an AES-GCM
    nonce and tag, which a byte-for-byte copy would not be.
"""

import sys
import zipfile

AENC = "assets/rtcore/aenc/"
INDEX = "assets/rtcore/assets.map"

# PAS1 magic (4) + AES-GCM nonce (12) + tag (16).
BLOB_OVERHEAD = 4 + 12 + 16

# Floor calibrated on the committed tree: 393 assets (392 Ghidra sleigh files +
# blutter/runners.json). 300 keeps >20% headroom and still catches "the flag was
# silently ignored", which indexes 0 entries.
MIN_ENTRIES = 300

# Always-encrypted sample, plus the first indexed entry (whatever it is), so the
# magic check does not depend on the sleigh tree surviving a future cleanup.
SAMPLES = ["blutter/runners.json"]


def main(apk):
    problems = []
    with zipfile.ZipFile(apk) as archive:
        names = set(archive.namelist())
        if INDEX not in names:
            print("missing index: %s" % INDEX)
            return 1

        index = archive.read(INDEX).decode("utf-8").splitlines()
        entries = [
            line.strip()
            for line in index
            if line.strip() and not line.strip().startswith("#")
        ]
        if len(entries) < MIN_ENTRIES:
            problems.append(
                "index lists only %d encrypted asset(s), expected >= %d"
                % (len(entries), MIN_ENTRIES)
            )

        for rel in entries:
            if AENC + rel not in names:
                problems.append("ciphertext missing: %s" % (AENC + rel))
            if "assets/" + rel in names:
                problems.append("plaintext survived: assets/%s" % rel)

        for rel in SAMPLES + entries[:1]:
            path = AENC + rel
            if path not in names:
                problems.append("expected encrypted asset missing: %s" % path)
                continue
            blob = archive.read(path)
            if blob[:4] != b"PAS1":
                problems.append("%s is not PAS1-prefixed" % path)
            if len(blob) < BLOB_OVERHEAD:
                problems.append("%s is too short to carry nonce+tag" % path)

    for problem in problems:
        print("asset check: %s" % problem)
    return 1 if problems else 0


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("usage: assetcheck.py <apk>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
