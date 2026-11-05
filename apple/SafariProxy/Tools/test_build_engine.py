"""Offline checks for input checksum refusal in the Safari engine builder."""
import importlib.util
from pathlib import Path
import tempfile
import unittest
import zipfile

SPEC = importlib.util.spec_from_file_location("safari_engine_builder", Path(__file__).with_name("build_engine.py"))
builder = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(builder)


class ModuleChecksumTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory(prefix="builder-test-", dir=Path(__file__).resolve().parents[1])
        self.root = Path(self.directory.name)
        self.cache = self.root / "cache"
        self.name, self.version = "example.invalid/dependency", "v1.0.0"
        self.prefix = self.name + "@" + self.version
        self.source = self.cache / self.prefix
        self.source.mkdir(parents=True)
        self.mod = b"module example.invalid/dependency\n\ngo 1.27.1\n"
        self.code = b"package dependency\nconst Value = 7\n"
        (self.source / "go.mod").write_bytes(self.mod)
        (self.source / "value.go").write_bytes(self.code)
        self.metadata = self.cache / "cache/download" / self.name / "@v"
        self.metadata.mkdir(parents=True)
        (self.metadata / (self.version + ".mod")).write_bytes(self.mod)
        self.archive = self.metadata / (self.version + ".zip")
        self.write_archive(self.code)
        self.sums = {(self.name, self.version): builder.hash1({self.prefix + "/go.mod": self.mod, self.prefix + "/value.go": self.code}), (self.name, self.version + "/go.mod"): builder.hash1({"go.mod": self.mod})}

    def tearDown(self):
        self.directory.cleanup()

    def write_archive(self, code):
        with zipfile.ZipFile(self.archive, "w") as archive:
            archive.writestr(self.prefix + "/go.mod", self.mod)
            archive.writestr(self.prefix + "/value.go", code)

    def stage(self):
        return builder.stage_module(self.cache, self.root / "private", self.name, self.version, self.sums)

    def test_verified_exact_source_and_archive_stage(self):
        result = self.stage()
        self.assertEqual(result["module_h1"], self.sums[(self.name, self.version)])
        self.assertEqual((self.root / "private" / self.prefix / "value.go").read_bytes(), self.code)

    def test_modified_cached_source_refused(self):
        (self.source / "value.go").write_bytes(self.code + b"// changed\n")
        with self.assertRaisesRegex(ValueError, "cached source checksum mismatch"):
            self.stage()
        self.assertFalse((self.root / "private").exists())

    def test_modified_cached_archive_refused(self):
        self.write_archive(self.code + b"// changed\n")
        with self.assertRaisesRegex(ValueError, "cached archive checksum mismatch"):
            self.stage()
        self.assertFalse((self.root / "private").exists())

    def test_modified_cached_mod_refused(self):
        (self.metadata / (self.version + ".mod")).write_bytes(self.mod + b"// changed\n")
        with self.assertRaisesRegex(ValueError, "cached go.mod checksum mismatch"):
            self.stage()
        self.assertFalse((self.root / "private").exists())


if __name__ == "__main__":
    unittest.main()
