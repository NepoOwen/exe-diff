import os
import tempfile
import unittest

import _path  # noqa: F401
import baseline


class BaselineTest(unittest.TestCase):
    def setUp(self):
        self.b = baseline.new_baseline("ab")
        self.b["names"]["4096"] = "?Ida@@YAXXZ"
        self.b["cmts"]["4096"] = "Alternative name is 'x'"
        self.b["rptcmts"]["8192"] = "Microsoft VisualC v14 64bit runtime"

    def test_owner_name(self):
        self.assertIsNone(baseline.owner_name(self.b, 0x1000, "?Ida@@YAXXZ"))
        self.assertEqual(baseline.owner_name(self.b, 0x1000, "PlayerTick"), "PlayerTick")
        self.assertEqual(baseline.owner_name(self.b, 0x3000, "Mine"), "Mine")
        self.assertIsNone(baseline.owner_name(self.b, 0x3000, None))
        self.assertIsNone(baseline.owner_name(self.b, 0x3000, ""))

    def test_owner_cmt(self):
        self.assertIsNone(baseline.owner_cmt(self.b, 0x1000, "cmt", "Alternative name is 'x'"))
        self.assertEqual(baseline.owner_cmt(self.b, 0x1000, "cmt", "Alternative name is 'x'\nmine"), "Alternative name is 'x'\nmine")
        self.assertEqual(baseline.owner_cmt(self.b, 0x1000, "rptcmt", "Alternative name is 'x'"), "Alternative name is 'x'")
        self.assertIsNone(baseline.owner_cmt(self.b, 0x2000, "rptcmt", "Microsoft VisualC v14 64bit runtime"))
        self.assertIsNone(baseline.owner_cmt(self.b, 0x2000, "cmt", ""))

    def test_no_baseline_keeps_everything(self):
        self.assertEqual(baseline.owner_name(None, 0x1000, "?Ida@@YAXXZ"), "?Ida@@YAXXZ")
        self.assertEqual(baseline.owner_cmt(None, 0x1000, "cmt", "Alternative name is 'x'"), "Alternative name is 'x'")
        self.assertIsNone(baseline.owner_cmt(None, 0x1000, "cmt", None))

    def test_owner_type(self):
        self.b["types"]["GUID"] = "typedef struct _GUID GUID;"
        self.assertFalse(baseline.owner_type(self.b, "GUID", "typedef struct _GUID GUID;"))
        self.assertTrue(baseline.owner_type(self.b, "GUID", "struct GUID\n{\n  int mine;\n};"))
        self.assertTrue(baseline.owner_type(self.b, "PlayerData", "struct PlayerData\n{\n  int hp;\n};"))
        self.assertTrue(baseline.owner_type(None, "GUID", "typedef struct _GUID GUID;"))
        del self.b["types"]
        self.assertTrue(baseline.owner_type(self.b, "GUID", "typedef struct _GUID GUID;"))

    def test_baseline_without_types_loads_as_having_none(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 1, "old_md5": "ab", "names": {}, "cmts": {}, "rptcmts": {}}')
            data = baseline.load(path)
            self.assertEqual(data["types"], {})
            self.assertTrue(baseline.owner_type(data, "GUID", "typedef struct _GUID GUID;"))
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 1, "old_md5": "ab", "names": {}, "cmts": {}, "rptcmts": {}, "types": []}')
            with self.assertRaises(ValueError):
                baseline.load(path)

    def test_insn_record(self):
        self.b["insn"]["4100"] = {"cmt": "void (__cdecl *)()", "ops": {"1": {"fmt": "hex"}}}
        self.assertEqual(baseline.insn_record(self.b, 0x1004), {"cmt": "void (__cdecl *)()", "ops": {"1": {"fmt": "hex"}}})
        self.assertIsNone(baseline.insn_record(self.b, 0x1008))
        self.assertIsNone(baseline.insn_record(None, 0x1004))
        del self.b["insn"]
        self.assertIsNone(baseline.insn_record(self.b, 0x1004))

    def test_has_insn(self):
        self.assertTrue(baseline.has_insn(self.b))
        self.assertFalse(baseline.has_insn(None))
        del self.b["insn"]
        self.assertFalse(baseline.has_insn(self.b))

    def test_baseline_without_insn_has_no_insn_records(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 1, "old_md5": "ab", "names": {}, "cmts": {}, "rptcmts": {}, "types": {}}')
            data = baseline.load(path)
            self.assertFalse(baseline.has_insn(data))
            self.assertIsNone(baseline.insn_record(data, 0x1004))
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 1, "old_md5": "ab", "names": {}, "cmts": {}, "rptcmts": {}, "insn": {}}')
            self.assertTrue(baseline.has_insn(baseline.load(path)))
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 1, "old_md5": "ab", "names": {}, "cmts": {}, "rptcmts": {}, "insn": []}')
            with self.assertRaises(ValueError):
                baseline.load(path)

    def test_protos_and_data(self):
        self.assertTrue(baseline.has_protos(self.b))
        self.assertTrue(baseline.has_data(self.b))
        self.b["protos"]["4096"] = "__int64 __fastcall(__int64 a1)"
        self.b["data"]["12288"] = {"name": "jpt_1000", "cmt": "jump table for switch statement"}
        self.assertEqual(baseline.proto_record(self.b, 0x1000), "__int64 __fastcall(__int64 a1)")
        self.assertIsNone(baseline.proto_record(self.b, 0x2000))
        self.assertEqual(baseline.data_record(self.b, 0x3000), {"name": "jpt_1000", "cmt": "jump table for switch statement"})
        self.assertIsNone(baseline.data_record(self.b, 0x3004))
        self.assertFalse(baseline.has_protos(None))
        self.assertFalse(baseline.has_data(None))
        self.assertIsNone(baseline.proto_record(None, 0x1000))
        self.assertIsNone(baseline.data_record(None, 0x3000))
        del self.b["protos"], self.b["data"]
        self.assertFalse(baseline.has_protos(self.b))
        self.assertFalse(baseline.has_data(self.b))

    def test_baseline_without_protos_or_data_loads(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 1, "old_md5": "ab", "names": {}, "cmts": {}, "rptcmts": {}, "insn": {}}')
            data = baseline.load(path)
            self.assertFalse(baseline.has_protos(data))
            self.assertFalse(baseline.has_data(data))
            for key in ("protos", "data"):
                with open(path, "w", encoding="utf-8") as f:
                    f.write('{"version": 1, "old_md5": "ab", "names": {}, "cmts": {}, "rptcmts": {}, "%s": []}' % key)
                with self.assertRaises(ValueError):
                    baseline.load(path)

    def test_round_trip_and_errors(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "baseline.json")
            baseline.save(path, self.b)
            self.assertEqual(baseline.load(path), self.b)
            self.assertFalse(os.path.exists(path + ".tmp"))
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 2}')
            with self.assertRaises(ValueError):
                baseline.load(path)
            with open(path, "w", encoding="utf-8") as f:
                f.write('{"version": 1, "names": {}}')
            with self.assertRaises(ValueError):
                baseline.load(path)
            with self.assertRaises(ValueError):
                baseline.load(os.path.join(d, "missing.json"))


if __name__ == "__main__":
    unittest.main()
