import argparse
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys


UPSTREAM_COMMIT = "528acbe83ba35a3a53fb97b231cb5f968c7068d1"


def run(command, cwd, log):
    result = subprocess.run(command, cwd=cwd, stdout=log, stderr=subprocess.STDOUT, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"command failed with exit code {result.returncode}: {' '.join(command)}")


def checkout(repository, revision, destination, log):
    if not (destination / ".git").is_dir():
        run(["git", "clone", "--filter=blob:none", repository, str(destination)], destination.parent, log)
    run(["git", "fetch", "origin", revision, "--depth", "1"], destination, log)
    run(["git", "checkout", "--detach", "--force", revision], destination, log)
    run(["git", "reset", "--hard", revision], destination, log)


def write_status(path, status, reason=None, **fields):
    payload = {"status": status, "reason": reason, **fields}
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    temporary.replace(path)


def prepare_dart_project(dart, blutter, runner, log):
    tidy = dart / "runtime" / "tools" / "run_clang_tidy.dart"
    content = tidy.read_text(encoding="utf-8")
    marker = content.find("-std=c++")
    cpp_standard = "17" if marker < 0 else content[marker + 8:marker + 10]
    template = (blutter / "scripts" / "CMakeLists.txt").read_text(encoding="utf-8")
    generated = template.replace("VERSION_PLACE_HOLDER", runner["dartVersion"]).replace("CXX_STD_PLACE_HOLDER", cpp_standard)
    generated = generated.replace('set(CMAKE_INSTALL_PREFIX "${PROJECT_SOURCE_DIR}/../../packages" CACHE PATH "" FORCE)\n', "")
    generated = generated.replace(" PUBLIC dl pthread ${ICU_LIBRARIES}", " PUBLIC dl ${ICU_LIBRARIES} ${ICU_DATA_LIBRARY}")
    (dart / "CMakeLists.txt").write_text(generated, encoding="utf-8")
    (dart / "Config.cmake.in").write_text('@PACKAGE_INIT@\n\ninclude ( "${CMAKE_CURRENT_LIST_DIR}/dartvmTarget.cmake" )\n', encoding="utf-8")
    run([sys.executable, str(blutter / "scripts" / "dartvm_create_srclist.py"), str(dart)], blutter, log)
    version_output = dart / "runtime" / "vm" / "version.cc"
    run([sys.executable, str(dart / "tools" / "make_version.py"), "--input", str(dart / "runtime" / "vm" / "version_in.cc"), "--output", str(version_output), "--no-git-hash", "--no-sdk-hash"], dart, log)
    source_list = dart / "sourcelist.cmake"
    source_text = source_list.read_text(encoding="utf-8")
    if "runtime/vm/version.cc" not in source_text:
        source_list.write_text(source_text.replace("set(SRCS", "set(SRCS\n    ./runtime/vm/version.cc", 1), encoding="utf-8")


def dart_compatibility_definitions(dart):
    object_store = (dart / "runtime" / "vm" / "object_store.h").read_text(encoding="utf-8")
    object_header = (dart / "runtime" / "vm" / "object.h").read_text(encoding="utf-8")
    definitions = []
    if "build_generic_method_extractor_code)" not in object_store:
        definitions.append("NO_METHOD_EXTRACTOR_STUB")
    if "AsTruncatedInt64Value()" not in object_header:
        definitions.append("UNIFORM_INTEGER_ACCESS")
    return definitions


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--plan", default="build/blutter-matrix/build-plan.json")
    parser.add_argument("--runner-id", required=True)
    parser.add_argument("--root", default="build/blutter-matrix")
    parser.add_argument("--blutter-repository", default="https://github.com/worawit/blutter.git")
    parser.add_argument("--dart-repository", default="https://github.com/dart-lang/sdk.git")
    parser.add_argument("--android-ndk", default=os.environ.get("ANDROID_NDK_ROOT", ""))
    parser.add_argument("--cmake", default="cmake")
    parser.add_argument("--ninja", default="ninja")
    parser.add_argument("--icu-root", default=os.environ.get("ANDROID_ICU_ROOT", ""))
    parser.add_argument("--capstone-root", default=os.environ.get("ANDROID_CAPSTONE_ROOT", ""))
    args = parser.parse_args()
    plan = json.loads(pathlib.Path(args.plan).read_text(encoding="utf-8"))
    runner = next((item for item in plan["runners"] if item["runnerId"] == args.runner_id), None)
    if runner is None:
        raise SystemExit(f"runner not found: {args.runner_id}")
    root = pathlib.Path(args.root).resolve()
    output = root / "runners" / args.runner_id
    status = output / "build.json"
    log_path = output / "build.log"
    output.mkdir(parents=True, exist_ok=True)
    (root / "source").mkdir(parents=True, exist_ok=True)
    (root / "packages").mkdir(parents=True, exist_ok=True)
    (root / "dartvm").mkdir(parents=True, exist_ok=True)
    (root / "cmake").mkdir(parents=True, exist_ok=True)
    if runner.get("blutterCommit") != UPSTREAM_COMMIT:
        write_status(status, "failed", "upstream_commit_mismatch", runnerId=args.runner_id)
        raise SystemExit(2)
    if not args.android_ndk or not pathlib.Path(args.android_ndk).is_dir():
        write_status(status, "failed", "android_ndk_unavailable", runnerId=args.runner_id)
        raise SystemExit(2)
    if not args.icu_root or not pathlib.Path(args.icu_root).is_dir():
        write_status(status, "failed", "android_icu_unavailable", runnerId=args.runner_id, buildStatus="failed", smokeStatus="not_run")
        raise SystemExit(2)
    if not args.capstone_root or not pathlib.Path(args.capstone_root).is_dir():
        write_status(status, "failed", "android_capstone_unavailable", runnerId=args.runner_id, buildStatus="failed", smokeStatus="not_run")
        raise SystemExit(2)
    write_status(status, "running", None, runnerId=args.runner_id, libraryName=runner["libraryName"], buildStatus="running", staticStatus="not_run", smokeStatus="not_run")
    with log_path.open("w", encoding="utf-8") as log:
        try:
            source = root / "source"
            dart = source / f"dart-{runner['dartRevision']}"
            blutter = source / f"blutter-{runner['blutterCommit']}"
            checkout(args.dart_repository, runner["dartRevision"], dart, log)
            checkout(args.blutter_repository, runner["blutterCommit"], blutter, log)
            overlay = pathlib.Path(__file__).resolve().parent / "android-runner"
            run(["git", "apply", "--check", str(overlay / "dart-app-accessors.patch")], blutter, log)
            run(["git", "apply", str(overlay / "dart-app-accessors.patch")], blutter, log)
            prepare_dart_project(dart, blutter, runner, log)
            packages = root / "packages" / args.runner_id
            if not (overlay / "CMakeLists.txt").is_file():
                raise RuntimeError("android_runner_overlay_missing")
            dart_build = root / "dartvm" / args.runner_id
            runner_build = root / "cmake" / args.runner_id
            toolchain = pathlib.Path(args.android_ndk) / "build" / "cmake" / "android.toolchain.cmake"
            icu_root = pathlib.Path(args.icu_root).resolve()
            icu_include = icu_root / "include"
            icu_lib = icu_root / "lib"
            run([args.cmake, "-S", str(dart), "-B", str(dart_build), "-G", "Ninja", f"-DCMAKE_TOOLCHAIN_FILE={toolchain}", "-DANDROID_ABI=arm64-v8a", "-DANDROID_PLATFORM=android-26", "-DTARGET_OS=android", "-DTARGET_ARCH=arm64", f"-DCOMPRESSED_PTRS={int(runner['compressedPointers'])}", f"-DICU_ROOT={icu_root}", f"-DCMAKE_PREFIX_PATH={icu_root}", f"-DICU_INCLUDE_DIR={icu_include}", f"-DICU_INCLUDE_DIRS={icu_include}", f"-DICU_LIBRARY={icu_lib / 'libicuuc.a'}", f"-DICU_LIBRARIES={icu_lib / 'libicuuc.a'}", f"-DICU_UC_LIBRARY={icu_lib / 'libicuuc.a'}", f"-DICU_DATA_LIBRARY={icu_lib / 'libicudata.a'}", f"-DCMAKE_INSTALL_PREFIX={packages}", "-DCMAKE_BUILD_TYPE=Release"], dart, log)
            run([args.cmake, "--build", str(dart_build), "--target", "install", "--parallel"], dart, log)
            dart_package = packages / "lib" / "cmake" / f"dartvm{runner['dartVersion']}_android_arm64"
            dart_package_name = f"dartvm{runner['dartVersion']}_android_arm64"
            compatibility = [f"-D{item}=ON" for item in dart_compatibility_definitions(dart)]
            run([args.cmake, "-S", str(overlay), "-B", str(runner_build), "-G", "Ninja", f"-DBLUTTER_SOURCE={blutter / 'blutter'}", f"-DDARTLIB={dart_package_name}", f"-D{dart_package_name}_DIR={dart_package}", f"-DCMAKE_PREFIX_PATH={packages}", f"-DCAPSTONE_ROOT={args.capstone_root}", f"-DRUNNER_LIBRARY={runner['libraryName']}", f"-DRUNNER_ID={runner['runnerId']}", f"-DBLUTTER_COMMIT={runner['blutterCommit']}", f"-DCOMPRESSED_POINTERS={int(runner['compressedPointers'])}", f"-DCMAKE_TOOLCHAIN_FILE={toolchain}", "-DANDROID_ABI=arm64-v8a", "-DANDROID_PLATFORM=android-26", "-DCMAKE_BUILD_TYPE=Release", *compatibility], overlay, log)
            run([args.cmake, "--build", str(runner_build), "--parallel"], overlay, log)
            candidates = list(runner_build.rglob(f"lib{runner['libraryName']}.so"))
            if len(candidates) != 1:
                raise RuntimeError("runner_shared_library_missing_or_ambiguous")
            binary = output / candidates[0].name
            shutil.copy2(candidates[0], binary)
            strip = pathlib.Path(args.android_ndk) / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / "llvm-strip"
            if strip.is_file():
                run([str(strip), "--strip-unneeded", str(binary)], output, log)
            readelf = pathlib.Path(args.android_ndk) / "toolchains" / "llvm" / "prebuilt" / "linux-x86_64" / "bin" / "llvm-readelf"
            if not readelf.is_file():
                readelf = pathlib.Path(shutil.which("llvm-readelf") or "llvm-readelf")
            exports = subprocess.run([str(readelf), "-Ws", str(binary)], capture_output=True, text=True, check=True).stdout
            if "blutter_run_fd" not in exports:
                raise RuntimeError("runner_export_missing")
            digest = hashlib.sha256(binary.read_bytes()).hexdigest()
            write_status(status, "built", None, runnerId=args.runner_id, libraryName=runner["libraryName"], sha256=digest, buildStatus="passed", staticStatus="passed", smokeStatus="not_run")
        except Exception as error:
            reason = str(error)
            if "android_runner_overlay_missing" in reason:
                reason = "blutter_compile_error"
            elif "runner_shared_library" in reason or "runner_export" in reason:
                reason = "android_cross_compile_error"
            write_status(status, "failed", reason, runnerId=args.runner_id, buildStatus="failed", staticStatus="failed", smokeStatus="not_run")
            raise


if __name__ == "__main__":
    main()
