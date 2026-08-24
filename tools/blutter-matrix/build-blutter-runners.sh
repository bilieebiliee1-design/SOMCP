# SPDX-License-Identifier: AGPL-3.0-or-later

# Copyright (C) 2026 bilieebiliee1-design

# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU Affero General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.

# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU Affero General Public License for more details.

# You should have received a copy of the GNU Affero General Public License
# along with this program. If not, see <https://www.gnu.org/licenses/>.
#
# build-blutter-runners.sh - Cross-compile the curated Dart AOT analysis
# runners (Blutter) for Android arm64-v8a and, on full success, install the
# regenerated runners.json + libblutter_*.so so they are packaged into the APK.
#
# This is safe by design: everything is built and verified in a staging area
# first, and app/src/main is only touched after the regenerated manifest passes
# verify_manifest.py with at least one runner. On ANY failure the committed
# runners.json / jniLibs stay untouched and the script exits non-zero (callers
# should run it best-effort so a runner build failure never blocks a release).
#
# Usage:
#   bash build-blutter-runners.sh
#
# Environment:
#   ANDROID_NDK_ROOT          explicit NDK root (default: autodetect
#                             ANDROID_HOME/SDK ndk/29.0.14206865)
#   BLUTTER_JOBS              parallel build jobs (default: 4)
#
# Prerequisites:
#   - git submodule update --init --recursive
#   - Android NDK 29.0.14206865, cmake >= 3.22, ninja, python3 on PATH
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"   # <repo>/tools/blutter-matrix
PROJECT="$(cd "$SCRIPT_DIR/../.." && pwd)"
TOOLS="$SCRIPT_DIR"

BLD="$PROJECT/build/blutter-matrix"
CACHE="$BLD/cache"
mkdir -p "$BLD" "$CACHE"

# NOTE: build_icu_android.sh installs into <root>/../arm64-v8a/icu, i.e. here
# $BLD/arm64-v8a/icu. Capstone mirrors that layout into $BLD/arm64-v8a/capstone.
ICU_ROOT="$BLD/arm64-v8a/icu"
CAPSTONE_ROOT="$BLD/arm64-v8a/capstone"
STAGING_MANIFEST="$BLD/staging/runners.json"
STAGING_JNI="$BLD/staging/jniLibs"
MANIFEST_APP="$PROJECT/app/src/main/assets/blutter/runners.json"
JNI_APP="$PROJECT/app/src/main/jniLibs/arm64-v8a"

JOBS="${BLUTTER_JOBS:-4}"
ICU_VERSION="76.1"
ICU_SHA256="dfacb46bfe4747410472ce3e1144bf28a102feeaa4e3875bac9b4c6cf30f4f3e"
ICU_URL="https://github.com/unicode-org/icu/releases/download/release-76-1/icu4c-76_1-src.tgz"

fail() { echo "::error::blutter-runners: $*" >&2; exit 1; }

# --- Locate the Android NDK ------------------------------------------------
NDK="${ANDROID_NDK_ROOT:-}"
if [[ -z "$NDK" ]]; then
  for cand in \
    "$ANDROID_HOME/ndk/29.0.14206865" \
    "$ANDROID_SDK_ROOT/ndk/29.0.14206865" \
    "$HOME/Android/Sdk/ndk/29.0.14206865" \
    /opt/android-ndk/29.0.14206865
  do
    if [[ -f "$cand/build/cmake/android.toolchain.cmake" ]]; then
      NDK="$cand"
      break
    fi
  done
fi
if [[ -z "$NDK" || ! -f "$NDK/build/cmake/android.toolchain.cmake" ]]; then
  echo "::error::blutter-runners: Android NDK 29.0.14206865 not found (set ANDROID_NDK_ROOT or ANDROID_HOME)"
  exit 1
fi
command -v python3 >/dev/null 2>&1 || fail "python3 not found on PATH"
command -v cmake   >/dev/null 2>&1 || fail "cmake not found on PATH"
command -v ninja   >/dev/null 2>&1 || fail "ninja not found on PATH"

# --- ICU for Android arm64 --------------------------------------------------
if [[ ! -f "$ICU_ROOT/lib/libicuuc.a" ]]; then
  tgz="$BLD/icu4c-76_1-src.tgz"
  if [[ ! -f "$tgz" ]]; then
    echo "[blutter-runners] downloading ICU $ICU_VERSION ..."
    curl -fsSL -o "$tgz" "$ICU_URL" || fail "failed to download ICU $ICU_VERSION"
  fi
  if ! (echo "$ICU_SHA256  $tgz" | sha256sum -c - >/dev/null 2>&1); then
    fail "ICU source SHA-256 mismatch (matrix-config androidNdk/icuVersion drift?)"
  fi
  echo "[blutter-runners] cross-compiling ICU $ICU_VERSION for Android arm64 ..."
  bash "$TOOLS/build_icu_android.sh" "$BLD" "$NDK" "$JOBS"
fi
[[ -f "$ICU_ROOT/lib/libicuuc.a" && -f "$ICU_ROOT/lib/libicudata.a" ]] || fail "ICU build incomplete"

# --- Capstone for Android arm64 --------------------------------------------
if [[ ! -f "$CAPSTONE_ROOT/lib/libcapstone.a" ]]; then
  if [[ ! -d "$PROJECT/third_party/capstone-4.0.2-src" ]]; then
    fail "capstone submodule missing - run 'git submodule update --init --recursive'"
  fi
  echo "[blutter-runners] cross-compiling capstone 4.0.2 for Android arm64 ..."
  bash "$TOOLS/build_capstone_android.sh" "$NDK" "$CAPSTONE_ROOT" "$JOBS"
fi
[[ -f "$CAPSTONE_ROOT/lib/libcapstone.a" ]] || fail "capstone build incomplete"

# --- Resolve matrix + build curated runners --------------------------------
echo "[blutter-runners] resolving Flutter/Dart matrix ..."
python3 "$TOOLS/generate_matrix.py" --config "$TOOLS/matrix-config.json" --output "$BLD/index.json"
python3 "$TOOLS/resolve_revisions.py" \
  --input "$BLD/index.json" --output "$BLD/resolved.json" --cache "$CACHE"
python3 "$TOOLS/prepare_build_plan.py" \
  --input "$BLD/resolved.json" --output "$BLD/build-plan-full.json"
python3 "$TOOLS/select_curated.py" \
  --plan "$BLD/build-plan-full.json" --config "$TOOLS/curated-versions.json" --output "$BLD/build-plan-curated.json"

echo "[blutter-runners] cross-compiling curated runners (this can take a while) ..."
python3 "$TOOLS/build_all.py" \
  --plan "$BLD/build-plan-curated.json" \
  --android-ndk "$NDK" --icu-root "$ICU_ROOT" --capstone-root "$CAPSTONE_ROOT" --workers 1

# --- Stage + verify, then install only on full success ----------------------
echo "[blutter-runners] generating + verifying manifest (staging) ..."
python3 "$TOOLS/generate_manifest.py" \
  --plan "$BLD/build-plan-curated.json" --root "$BLD" \
  --manifest "$STAGING_MANIFEST" --jni-root "$STAGING_JNI"
# verify_manifest fails (non-zero) if there is no verified runner at all.
python3 "$TOOLS/verify_manifest.py" --manifest "$STAGING_MANIFEST" --jni-root "$STAGING_JNI"

RUNNERS_COUNT=$(python3 -c "import json,sys;print(len(json.load(open(sys.argv[1]))['runners']))" "$STAGING_MANIFEST")
[[ "$RUNNERS_COUNT" -ge 1 ]] || fail "no verified runner produced; refusing to touch app/src/main"

# Only reachable when verification passed with >=1 runner.
mkdir -p "$JNI_APP" "$(dirname "$MANIFEST_APP")"
rm -f "$JNI_APP"/libblutter_*.so
cp "$STAGING_MANIFEST" "$MANIFEST_APP"
copied=0
for so in "$STAGING_JNI"/arm64-v8a/libblutter_*.so; do
  [[ -f "$so" ]] || continue
  cp "$so" "$JNI_APP/$(basename "$so")"
  copied=$((copied + 1))
done
if [[ "$copied" -ne "$RUNNERS_COUNT" ]]; then
  fail "installed $copied runner(s) but manifest declares $RUNNERS_COUNT; rolling back is impossible - aborting (app/src/main may be inconsistent)"
fi

echo "[blutter-runners] installed $RUNNERS_COUNT verified runner(s):"
python3 -c "import json,sys;print('\n'.join('  - '+r['runnerId']+' ['+r['compatibilityKey']+']' for r in json.load(open(sys.argv[1]))['runners']))" "$MANIFEST_APP"