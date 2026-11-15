import unittest

import _path  # noqa: F401
import insnplan


def shape(*rows):
    return {"frsize": 0, "argsize": 0, "insns": [[off, 4, mnem, list(ops), None] for off, mnem, ops in rows]}


RUN = [("mov", (1, 1)), ("add", (1, 5)), ("sub", (1, 5)), ("cmp", (1, 1)), ("jz", (7,)), ("ret", ())]


class OwnerItemsTest(unittest.TestCase):
    def test_no_baseline_keeps_everything(self):
        rec = {"cmt": "mine", "rpt": "r", "ant": ["a1", "a2"], "post": ["p"], "ops": {"1": {"fmt": "hex"}}}
        items = insnplan.owner_items(8, rec, None)
        self.assertEqual(items, [{"off": 8, "kind": "cmt", "text": "mine"}, {"off": 8, "kind": "rpt", "text": "r"},
                                 {"off": 8, "kind": "ant", "lines": ["a1", "a2"]}, {"off": 8, "kind": "post", "lines": ["p"]},
                                 {"off": 8, "kind": "opfmt", "opn": 1, "fmt": "hex"}])

    def test_baseline_drops_ida_data_and_keeps_changes(self):
        base = {"cmt": "void (__cdecl *)()", "rpt": "jumptable case 1", "ops": {"1": {"fmt": "hex"}, "0": {"fmt": "dec"}}}
        rec = {"cmt": "void (__cdecl *)()", "rpt": "mine", "ops": {"1": {"fmt": "enum", "arg": "E"}, "0": {"fmt": "dec"}}}
        items = insnplan.owner_items(0, rec, base)
        self.assertEqual(items, [{"off": 0, "kind": "rpt", "text": "mine", "ida": "jumptable case 1"},
                                 {"off": 0, "kind": "opfmt", "opn": 1, "fmt": "enum", "arg": "E", "ida": {"fmt": "hex"}}])

    def test_unknown_formats_are_not_exported(self):
        self.assertEqual(insnplan.owner_items(0, {"ops": {"0": {"fmt": "other"}}}, None), [])

    def test_want_and_describe(self):
        it = {"off": 3, "kind": "opfmt", "opn": 1, "fmt": "enum", "arg": "E", "serial": 2, "ida": {"fmt": "hex"}, "decls": {"E": "enum E {};"}}
        self.assertEqual(insnplan.want_of(it), {"fmt": "enum", "arg": "E", "serial": 2})
        self.assertEqual(insnplan.describe(it), "enum E format of operand 1")
        self.assertEqual(insnplan.describe({"kind": "opfmt", "opn": 0, "fmt": "stroff", "path": ["S", "T"]}), "struct offset S.T format of operand 0")
        self.assertEqual(insnplan.want_of({"kind": "ant", "lines": ["x"]}), ["x"])
        self.assertEqual(insnplan.describe({"kind": "rpt"}), "repeatable comment")

    def test_desc(self):
        self.assertEqual(insnplan.desc("hex"), {"fmt": "hex"})
        self.assertEqual(insnplan.desc("enum", "E", serial=1), {"fmt": "enum", "arg": "E", "serial": 1})
        self.assertEqual(insnplan.desc("stroff", path=("S",), delta=-4), {"fmt": "stroff", "path": ["S"], "delta": -4})


class TypeProblemTest(unittest.TestCase):
    NEW = {"E": "enum E\n{\n  A = 1,\n};", "S": "struct S\n{\n  int a;\n};", "T": "struct T\n{\n  int b;\n};"}

    def test_type_names(self):
        self.assertEqual(insnplan.type_names({"kind": "opfmt", "fmt": "enum", "arg": "E"}), ["E"])
        self.assertEqual(insnplan.type_names({"kind": "opfmt", "fmt": "stroff", "path": ["S", "T"]}), ["S", "T"])
        self.assertEqual(insnplan.type_names({"kind": "opfmt", "fmt": "hex"}), [])
        self.assertEqual(insnplan.type_names({"kind": "cmt", "text": "x"}), [])

    def test_identical_types_pass(self):
        it = {"kind": "opfmt", "fmt": "stroff", "path": ["S", "T"], "decls": {"S": self.NEW["S"], "T": self.NEW["T"]}}
        self.assertIsNone(insnplan.type_problem(it, self.NEW.get))
        self.assertIsNone(insnplan.type_problem({"kind": "opfmt", "fmt": "dec"}, self.NEW.get))

    def test_differing_missing_or_unknown_types_fail(self):
        it = {"kind": "opfmt", "fmt": "enum", "arg": "E", "decls": {"E": "enum E\n{\n  A = 1,\n  B = 2,\n};"}}
        self.assertEqual(insnplan.type_problem(it, self.NEW.get), "the enum E in the new database is not the same type as in the old one")
        it = {"kind": "opfmt", "fmt": "enum", "arg": "Gone", "decls": {"Gone": "enum Gone {};"}}
        self.assertEqual(insnplan.type_problem(it, self.NEW.get), "the enum Gone is not in the new database")
        it = {"kind": "opfmt", "fmt": "stroff", "path": ["S"], "decls": {"S": None}}
        self.assertEqual(insnplan.type_problem(it, self.NEW.get), "the struct S in the new database is not the same type as in the old one")
        it = {"kind": "opfmt", "fmt": "stroff", "path": ["S"]}
        self.assertIsNotNone(insnplan.type_problem(it, self.NEW.get))

    def test_types_the_format_type_uses_are_checked(self):
        it = {"kind": "opfmt", "fmt": "stroff", "path": ["S"], "decls": {"S": self.NEW["S"], "Inner": "struct Inner\n{\n  int x;\n};"}}
        self.assertEqual(insnplan.type_problem(it, self.NEW.get), "the type Inner is not in the new database")
        it = {"kind": "opfmt", "fmt": "stroff", "path": ["S"], "decls": {"S": self.NEW["S"], "T": self.NEW["T"]}}
        self.assertIsNone(insnplan.type_problem(it, self.NEW.get))
        it = {"kind": "opfmt", "fmt": "enum", "arg": "E", "decls": {"E": self.NEW["E"], "Odd<int>": None}}
        self.assertEqual(insnplan.type_problem(it, self.NEW.get),
                         "the type Odd<int> cannot be checked against the new database: its name is not a plain C name")


class DecideTest(unittest.TestCase):
    def test_decide(self):
        self.assertEqual(insnplan.decide("a", "a", None), "same")
        self.assertEqual(insnplan.decide(None, "a", None), "set")
        self.assertEqual(insnplan.decide([], ["a"], None), "set")
        self.assertEqual(insnplan.decide({"fmt": "hex"}, {"fmt": "enum", "arg": "E"}, {"fmt": "hex"}), "set")
        self.assertEqual(insnplan.decide({"fmt": "dec"}, {"fmt": "enum", "arg": "E"}, {"fmt": "hex"}), "keep")
        self.assertEqual(insnplan.decide("theirs", "mine", None), "keep")


class PlanTest(unittest.TestCase):
    def items(self, *offs):
        return [{"off": off, "kind": "cmt", "text": "c%d" % off} for off in offs]

    def test_exact_keeps_offsets(self):
        old = shape(*[(4 * k, m, o) for k, (m, o) in enumerate(RUN)])
        placed, skipped = insnplan.plan(self.items(0, 8), old, old, True)
        self.assertEqual([(it["off"], off) for it, off in placed], [(0, 0), (8, 8)])
        self.assertEqual(skipped, [])

    def test_changed_maps_runs_and_skips_changed_parts(self):
        old_rows = [(4 * k, m, o) for k, (m, o) in enumerate(RUN)]
        new_rows = [(0, "push", (1,)), (2, "xor", (1, 1))] + [(10 + 4 * k, m, o) for k, (m, o) in enumerate(RUN[:3])] + [(30, "lea", (1, 4)), (36, "ret", ())]
        placed, skipped = insnplan.plan(self.items(4, 12, 20), shape(*old_rows), shape(*new_rows), False)
        self.assertEqual([(it["off"], off) for it, off in placed], [(4, 14)])
        self.assertEqual([(it["off"], why, off) for it, why, off in skipped], [(12, "it is in a changed part of the function", None),
                                                                              (20, "it is in a changed part of the function", None)])

    def test_changed_functions_get_no_operand_formats(self):
        old_rows = [(4 * k, m, o) for k, (m, o) in enumerate(RUN)]
        fmt = {"off": 4, "kind": "opfmt", "opn": 1, "fmt": "enum", "arg": "E"}
        outside = {"off": 12, "kind": "opfmt", "opn": 1, "fmt": "hex"}
        placed, skipped = insnplan.plan([fmt, outside] + self.items(4), shape(*old_rows), shape(*old_rows), False)
        self.assertEqual([(it["kind"], off) for it, off in placed], [("cmt", 4)])
        self.assertEqual([(it["off"], why, off) for it, why, off in skipped], [(4, insnplan.CHANGED_FORMAT, 4), (12, insnplan.CHANGED_FORMAT, 12)])
        placed, skipped = insnplan.plan([fmt], shape(*old_rows), shape(*old_rows), True)
        self.assertEqual((len(placed), skipped), (1, []))

    def test_short_runs_are_not_trusted(self):
        old = shape((0, "mov", (1, 1)), (4, "add", (1, 5)), (8, "ret", ()))
        new = shape((0, "mov", (1, 1)), (4, "add", (1, 5)), (8, "nop", ()), (9, "ret", ()))
        placed, skipped = insnplan.plan(self.items(0), old, new, False)
        self.assertEqual(placed, [])
        self.assertEqual(len(skipped), 1)

    def test_item_off_an_instruction_start_is_skipped(self):
        old = shape(*[(4 * k, m, o) for k, (m, o) in enumerate(RUN)])
        placed, skipped = insnplan.plan(self.items(2), old, old, False)
        self.assertEqual((placed, [why for _it, why, _off in skipped]), ([], ["it is in a changed part of the function"]))

    def test_seq_uses_the_operand_key(self):
        self.assertEqual(insnplan.seq([[0, 4, "mov", [1, 4], None, "k1"]]), [("mov", (1, 4), "k1")])
        self.assertEqual(insnplan.seq([[0, 4, "mov", [1, 4], None]]), [("mov", (1, 4), None)])
        self.assertEqual(insnplan.MIN_RUN, 3)

    def test_look_alike_instruction_is_not_aligned(self):
        rows = [(4 * k, m, o) for k, (m, o) in enumerate(RUN)]
        old = shape(*rows)
        for k, x in enumerate(old["insns"]):
            x.append("key%d" % k)
        new = shape(*rows)
        for k, x in enumerate(new["insns"]):
            x.append("other" if k == 1 else "key%d" % k)
        placed, skipped = insnplan.plan(self.items(4, 12), old, new, False)
        self.assertEqual([(it["off"], off) for it, off in placed], [(12, 12)])
        self.assertEqual([(it["off"], why) for it, why, _off in skipped], [(4, "it is in a changed part of the function")])

    def test_cap(self):
        old = shape(*[(4 * k, m, o) for k, (m, o) in enumerate(RUN)])
        placed, skipped = insnplan.plan(self.items(0), old, old, False, cap=5)
        self.assertEqual(placed, [])
        self.assertIn("more than 5 instructions", skipped[0][1])
        placed, _ = insnplan.plan(self.items(0), old, old, True, cap=5)
        self.assertEqual(len(placed), 1)


if __name__ == "__main__":
    unittest.main()
