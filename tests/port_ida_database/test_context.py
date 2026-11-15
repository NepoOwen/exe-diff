import os
import tempfile
import unittest
from unittest import mock

import _path  # noqa: F401
import baseline
import context
import portlog

MAP = ("status,name,old_va,new_va,old_size,new_size,method,similarity\n"
       "same,a,0x1000,0x2000,10,10,exact-unique,100\n"
       "same,b,0x1100,0x2100,10,10,exact-group,100\n"
       "changed,c,0x1200,0x2200,10,12,similar,85\n"
       "changed,d,0x1300,0x2300,10,30,similar,60\n"
       "removed,e,0x1400,,10,,,\n")
PAIR = "old_exe=C:\\x y\\Old.exe\r\nold_md5=AA\r\nnew_exe=C:\\x y\\New.exe\r\nnew_md5=bb\r\n"


class ContextTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.dir.cleanup)
        self.map = os.path.join(self.dir.name, "map.csv")
        self.pair = os.path.join(self.dir.name, "pair.txt")
        with open(self.map, "w", encoding="utf-8") as f:
            f.write(MAP)
        with open(self.pair, "w", encoding="utf-8", newline="") as f:
            f.write(PAIR)
        self.env = {"PORTDB_MAP": self.map, "PORTDB_PAIR": self.pair, "PORTDB_DUMP": "d.json", "PORTDB_RESULT": "r.txt"}

    def build(self, extra=None, dump=None):
        env = dict(self.env, **(extra or {}))
        with mock.patch.dict(os.environ, env, clear=False):
            for k in ("PORTDB_MIN_SIMILARITY", "PORTDB_INCLUDE_LIKELY", "PORTDB_OLD_EXE_NAME", "PORTDB_BASELINE", "PORTDB_BASELINE_WARNING"):
                if k not in env:
                    os.environ.pop(k, None)
            return context.build_apply_ctx(dump) if dump is not None else context.build_export_ctx()

    def test_export_defaults(self):
        ctx = self.build()
        self.assertEqual(ctx.pair["old_md5"], "AA")
        self.assertEqual(ctx.old_exe_name, "Old.exe")
        self.assertEqual(ctx.min_similarity, 80)
        self.assertFalse(ctx.include_likely)
        self.assertEqual((ctx.dump_path, ctx.result_path), ("d.json", "r.txt"))
        self.assertEqual([ctx.ported(a) for a in (0x1000, 0x1100, 0x1200, 0x1300, 0x1400)], [True, False, True, False, False])

    def test_options_from_env(self):
        ctx = self.build({"PORTDB_MIN_SIMILARITY": "50", "PORTDB_INCLUDE_LIKELY": "1", "PORTDB_OLD_EXE_NAME": "Given.exe"})
        self.assertEqual(ctx.old_exe_name, "Given.exe")
        self.assertTrue(ctx.ported(0x1100))
        self.assertTrue(ctx.ported(0x1300))

    def test_apply_ctx(self):
        log = portlog.PortLog()
        log.warn("from export")
        ctx = self.build(dump={"log": log.to_json()})
        self.assertEqual(ctx.log.warnings, ["from export"])
        self.assertEqual(ctx.new_start(0x1000), 0x2000)
        self.assertIsNone(ctx.new_start(0x1400))
        self.assertFalse(ctx.gate_ok(0x1000))
        ctx.gate[0x1000] = True
        self.assertTrue(ctx.gate_ok(0x1000))

    def test_new_function_checks_ida_by_default(self):
        ctx = self.build(dump={"log": []})
        self.assertIs(ctx.is_function_start, context.ida_function_start)

        class Func:
            def __init__(self, start):
                self.start_ea = start

        fake = mock.Mock()
        fake.get_func = lambda ea: Func(0x2000) if 0x2000 <= ea < 0x2100 else Func(0x2180) if 0x2180 <= ea < 0x2300 else None
        with mock.patch.dict("sys.modules", {"ida_funcs": fake}):
            self.assertTrue(context.ida_function_start(0x2000))
            self.assertFalse(context.ida_function_start(0x2010))
            self.assertFalse(context.ida_function_start(0x5000))
            self.assertEqual(ctx.new_function(0x1000), 0x2000)
            self.assertIsNone(ctx.new_function(0x1200, "c"))
        self.assertEqual([r["category"] for r in ctx.log.reviews], ["no-new-function"])

    def test_new_function_reports_once(self):
        ctx = self.build(dump={"log": []})
        ctx.is_function_start = lambda ea: ea == 0x2000
        self.assertEqual(ctx.new_function(0x1000, "a"), 0x2000)
        self.assertIsNone(ctx.new_function(0x1400, "e"))
        self.assertIsNone(ctx.new_function(0x1200, "c"))
        self.assertIsNone(ctx.new_function(0x1200, "c"))
        self.assertEqual([(r["category"], r["old"], r["new"]) for r in ctx.log.reviews], [("no-new-function", 0x1200, 0x2200)])
        self.assertTrue(ctx.log.reviews[0]["text"].startswith("c: 0x2200 is not the start of a function"))
        self.assertIsNone(ctx.new_function(0x1300))
        self.assertTrue(ctx.log.reviews[1]["text"].startswith("0x1300: "))

    def test_new_function_quiet(self):
        ctx = self.build(dump={"log": []})
        ctx.is_function_start = lambda ea: ea == 0x2000
        self.assertIsNone(ctx.new_function(0x1200, "c", quiet=True))
        self.assertEqual(ctx.log.reviews, [])
        self.assertEqual(ctx.new_function(0x1000, "a", quiet=True), 0x2000)
        self.assertIsNone(ctx.new_function(0x1200, "c"))
        self.assertEqual([r["category"] for r in ctx.log.reviews], ["no-new-function"])

    def test_shape_wanted(self):
        self.assertEqual(self.build().shape_wanted, set())

    def test_write_result(self):
        path = os.path.join(self.dir.name, "result.txt")
        context.write_result(path, "refused", "this database is not for X.exe")
        with open(path, encoding="utf-8") as f:
            self.assertEqual(f.read().splitlines(), ["refused", "this database is not for X.exe"])

    def test_no_baseline_warns(self):
        ctx = self.build()
        self.assertIsNone(ctx.baseline)
        self.assertEqual(ctx.log.warnings, [baseline.NO_CACHE % "Old.exe"])
        self.assertEqual(ctx.owner_name(0x1000, "?Ida@@YAXXZ"), "?Ida@@YAXXZ")
        self.assertTrue(ctx.owner_type("GUID", "typedef struct _GUID GUID;"))
        ctx = self.build({"PORTDB_BASELINE_WARNING": "the cache is open"})
        self.assertEqual(ctx.log.warnings, ["the cache is open"])

    def test_baseline_loaded(self):
        path = os.path.join(self.dir.name, "baseline.json")
        b = baseline.new_baseline("aa")
        b["names"]["4096"] = "?Ida@@YAXXZ"
        b["cmts"]["4096"] = "Alternative name is 'x'"
        b["types"]["GUID"] = "typedef struct _GUID GUID;"
        baseline.save(path, b)
        ctx = self.build({"PORTDB_BASELINE": path})
        self.assertEqual(ctx.log.warnings, [])
        self.assertFalse(ctx.owner_type("GUID", "typedef struct _GUID GUID;"))
        self.assertTrue(ctx.owner_type("Mine", "struct Mine\n{\n  int a;\n};"))
        self.assertIsNone(ctx.owner_name(0x1000, "?Ida@@YAXXZ"))
        self.assertEqual(ctx.owner_name(0x1000, "Mine"), "Mine")
        self.assertIsNone(ctx.owner_cmt(0x1000, "cmt", "Alternative name is 'x'"))
        self.assertEqual(ctx.owner_cmt(0x1000, "rptcmt", "Alternative name is 'x'"), "Alternative name is 'x'")

    def test_baseline_for_another_exe_is_ignored(self):
        path = os.path.join(self.dir.name, "baseline.json")
        b = baseline.new_baseline("cc")
        b["names"]["4096"] = "?Ida@@YAXXZ"
        baseline.save(path, b)
        ctx = self.build({"PORTDB_BASELINE": path})
        self.assertIsNone(ctx.baseline)
        self.assertEqual(len(ctx.log.warnings), 1)
        self.assertIn("not for Old.exe", ctx.log.warnings[0])
        self.assertEqual(ctx.owner_name(0x1000, "?Ida@@YAXXZ"), "?Ida@@YAXXZ")

    def test_new_dump_has_every_key(self):
        d = context.new_dump("ab")
        self.assertEqual(sorted(d), ["context", "data", "folders", "functions", "log", "notices", "old_md5", "types", "union_types", "version"])
        self.assertEqual((d["union_types"], d["notices"]), ({}, []))


if __name__ == "__main__":
    unittest.main()
