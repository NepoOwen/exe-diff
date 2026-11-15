import json
import os
import tempfile
import unittest

import _path  # noqa: F401
import dump


class DumpTest(unittest.TestCase):
    def test_round_trip(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.dump.json")
            data = {"version": dump.DUMP_VERSION, "old_md5": "ab", "functions": {"5": {"name": "né"}}}
            dump.save(path, data)
            self.assertFalse(os.path.exists(path + ".tmp"))
            self.assertEqual(dump.load(path), data)

    def test_save_is_compact(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            dump.save(path, {"old_md5": "ab", "functions": {"5": {"insn": [1, 2]}}, "name": "né"})
            with open(path, "r", encoding="utf-8") as f:
                text = f.read()
            self.assertNotIn("\n", text)
            self.assertNotIn(": ", text)
            self.assertNotIn(", ", text)
            self.assertIn("né", text)

    def test_save_stamps_version(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            dump.save(path, {"old_md5": "ab"})
            self.assertEqual(dump.load(path)["version"], dump.DUMP_VERSION)

    def test_version_mismatch(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            with open(path, "w", encoding="utf-8") as f:
                json.dump({"version": 99}, f)
            with self.assertRaises(ValueError):
                dump.load(path)

    def test_missing_file(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(ValueError):
                dump.load(os.path.join(d, "none.json"))

    def test_failed_save_leaves_original(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "x.json")
            dump.save(path, {"old_md5": "one"})
            with self.assertRaises(TypeError):
                dump.save(path, {"old_md5": object()})
            self.assertEqual(dump.load(path)["old_md5"], "one")
            self.assertFalse(os.path.exists(path + ".tmp"))

    def test_unwritable_dir(self):
        with tempfile.TemporaryDirectory() as d:
            with self.assertRaises(OSError):
                dump.save(os.path.join(d, "missing", "x.json"), {"old_md5": "a"})


if __name__ == "__main__":
    unittest.main()
