import importlib.util
import json
import pathlib
import tempfile
import unittest
import unittest.mock


ROOT = pathlib.Path(__file__).resolve().parent


def module(name):
    spec = importlib.util.spec_from_file_location(name, ROOT / f"{name}.py")
    value = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(value)
    return value


generate_matrix = module("generate_matrix")
resolve_revisions = module("resolve_revisions")
build_all = module("build_all")
prepare_build_plan = module("prepare_build_plan")


class MatrixTest(unittest.TestCase):
    def test_analysis_modes(self):
        config = {"analysisMinimumDart": "2.16.0", "legacyNoAnalysisMinimumDart": "2.14.0"}
        self.assertEqual("analysis", generate_matrix.analysis_mode("3.12.2", config))
        self.assertEqual("no_analysis", generate_matrix.analysis_mode("2.15.1", config))
        self.assertEqual("unsupported", generate_matrix.analysis_mode("2.13.4", config))
        self.assertEqual("unresolved", generate_matrix.analysis_mode(None, config))

    def test_release_filtering(self):
        archive = {"releases": [{"channel": "stable", "version": "3.0.0", "hash": "a" * 40, "dart_sdk_version": "2.17.0"}, {"channel": "beta", "version": "4.0.0", "hash": "b" * 40, "dart_sdk_version": "3.0.0"}]}
        config = {"channels": ["stable"], "analysisMinimumDart": "2.16.0", "legacyNoAnalysisMinimumDart": "2.14.0"}
        rows = generate_matrix.release_rows(archive, config)
        self.assertEqual(1, len(rows))
        self.assertEqual("3.0.0", rows[0]["flutterVersion"])

    def test_snapshot_hash_matches_dart_algorithm(self):
        payloads = {name: name.encode() for name in resolve_revisions.SNAPSHOT_FILES}
        expected = __import__("hashlib").md5(b"".join(payloads.values())).hexdigest()
        script = f"VM_SNAPSHOT_FILES = {list(payloads)!r}"
        with tempfile.TemporaryDirectory() as directory:
            with unittest.mock.patch.object(resolve_revisions, "fetch_text", return_value=script):
                with unittest.mock.patch.object(resolve_revisions, "fetch_bytes", side_effect=lambda url: payloads[url.rsplit("/", 1)[1]]):
                    result = resolve_revisions.resolve_snapshot("a" * 40, pathlib.Path(directory))
        self.assertEqual(expected, result["snapshotHash"])
        self.assertEqual("dart_make_version", result["snapshotHashSource"])

    def test_snapshot_files_supports_legacy_dart_layout(self):
        script = "VM_SNAPSHOT_FILES = ['clustered_snapshot.h', 'clustered_snapshot.cc']"
        self.assertEqual(("clustered_snapshot.h", "clustered_snapshot.cc"), resolve_revisions.snapshot_files(script))

    def test_completed_runner_requires_matching_binary_digest(self):
        runner = {"runnerId": "runner", "libraryName": "blutter_runner"}
        with tempfile.TemporaryDirectory() as directory:
            root = pathlib.Path(directory)
            output = root / "runners" / runner["runnerId"]
            output.mkdir(parents=True)
            binary = output / "libblutter_runner.so"
            binary.write_bytes(b"runner")
            digest = __import__("hashlib").sha256(binary.read_bytes()).hexdigest()
            (output / "build.json").write_text(json.dumps({"runnerId": "runner", "libraryName": "blutter_runner", "buildStatus": "passed", "staticStatus": "passed", "sha256": digest}), encoding="utf-8")
            self.assertTrue(build_all.completed(root, runner))
            binary.write_bytes(b"corrupt")
            self.assertFalse(build_all.completed(root, runner))

    def test_plan_excludes_runner_without_snapshot_hash(self):
        matrix = {"matrixVersion": "test", "blutterCommit": "a" * 40, "targetAbi": "arm64-v8a", "releases": [{"flutterVersion": "1.0.0", "dartVersion": None, "dartRevision": "b" * 40, "analysisMode": "analysis", "compressedPointers": True}]}
        with tempfile.TemporaryDirectory() as directory:
            source = pathlib.Path(directory) / "resolved.json"
            output = pathlib.Path(directory) / "plan.json"
            source.write_text(json.dumps(matrix), encoding="utf-8")
            with unittest.mock.patch("sys.argv", ["prepare_build_plan.py", "--input", str(source), "--output", str(output)]):
                prepare_build_plan.main()
            plan = json.loads(output.read_text(encoding="utf-8"))
        self.assertEqual([], plan["runners"])
        self.assertEqual("snapshot_hash_unavailable", plan["coverage"][0]["reason"])


if __name__ == "__main__":
    unittest.main()
