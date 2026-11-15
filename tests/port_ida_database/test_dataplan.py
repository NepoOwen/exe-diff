import unittest

import _path  # noqa: F401
import dataplan

OLD = {"S": "struct S\n{\n  int a;\n  E e;\n  T *t;\n};", "E": "enum E\n{\n  A = 1,\n};", "T": "struct T;", "AK::Thing": "struct AK::Thing;"}


class TypeClosureTest(unittest.TestCase):
    def test_type_names(self):
        self.assertEqual(dataplan.type_names("int __fastcall(S *a, AK::Thing *b, int c)"), ["int", "__fastcall", "S", "a", "AK::Thing", "b", "int", "c"])
        self.assertEqual(dataplan.type_names("char[16]"), ["char"])
        self.assertEqual(dataplan.type_names(None), [])

    def test_closure_follows_member_types(self):
        calls = []

        def decl_of(name):
            calls.append(name)
            return OLD.get(name)

        self.assertEqual(dataplan.closure("int __fastcall(S *a, int b)", decl_of), {"S": OLD["S"], "E": OLD["E"], "T": OLD["T"]})
        self.assertEqual(len(calls), len(set(calls)))
        self.assertEqual(dataplan.closure("int", decl_of), {})
        self.assertEqual(dataplan.closure("AK::Thing *", OLD.get), {"AK::Thing": OLD["AK::Thing"]})

    def test_types_problem(self):
        types = {"S": OLD["S"], "E": OLD["E"]}
        self.assertIsNone(dataplan.types_problem(types, OLD.get))
        self.assertIsNone(dataplan.types_problem({}, OLD.get))
        self.assertEqual(dataplan.types_problem(types, {"S": OLD["S"]}.get), "the type E is not in the new database")
        self.assertEqual(dataplan.types_problem(types, dict(OLD, E="enum E\n{\n  A = 2,\n};").get),
                         "the type E in the new database is not the same type as in the old one")
        self.assertEqual(dataplan.types_problem({"S": ""}, {"S": ""}.get), "the type S in the new database is not the same type as in the old one")
        self.assertEqual(dataplan.types_problem(None, OLD.get), "the types it uses were not recorded")

    def test_plain_name(self):
        self.assertTrue(dataplan.plain_name("S"))
        self.assertTrue(dataplan.plain_name("AK::Thing"))
        self.assertTrue(dataplan.plain_name("_x$1"))
        for name in ("std::vector<int>", "Pair<A, B>", "~X", "a b", "1x", ""):
            self.assertFalse(dataplan.plain_name(name), name)

    def test_closure_marks_names_that_are_not_one_token(self):
        odd = ["std::vector<int>", "Pair<A, B>", "Unused<X>"]
        decls = dict(OLD, U="struct U\n{\n  std::vector<int> v;\n  S s;\n};")
        self.assertEqual(dataplan.closure("int __fastcall(U *u)", decls.get, odd), {"U": decls["U"], "S": OLD["S"], "E": OLD["E"], "T": OLD["T"],
                                                                                  "std::vector<int>": None})
        self.assertEqual(dataplan.closure("Pair<A, B> *", decls.get, odd), {"Pair<A, B>": None})
        self.assertEqual(dataplan.closure("int", decls.get, odd), {})
        self.assertEqual(dataplan.closure("std::vector<int> *", decls.get), {})

    def test_types_problem_names_it_cannot_check(self):
        self.assertEqual(dataplan.types_problem({"S": OLD["S"], "Pair<A, B>": None}, OLD.get),
                         "the type Pair<A, B> cannot be checked against the new database: its name is not a plain C name")


class OwnerTest(unittest.TestCase):
    def test_owner_value(self):
        self.assertEqual(dataplan.owner_value("mine", None), "mine")
        self.assertEqual(dataplan.owner_value("mine", "ida"), "mine")
        self.assertIsNone(dataplan.owner_value("ida", "ida"))
        self.assertIsNone(dataplan.owner_value(None, "ida"))
        self.assertIsNone(dataplan.owner_value("", None))

    def test_owner_data(self):
        rec = {"name": "jpt_1", "cmt": "jump table for switch statement", "type": "int"}
        base = {"name": "jpt_1", "cmt": "jump table for switch statement", "type": "int"}
        self.assertIsNone(dataplan.owner_data(rec, base, True))
        rec = {"name": "MyTable", "cmt": "jump table for switch statement", "rptcmt": "r", "type": "int"}
        self.assertEqual(dataplan.owner_data(rec, base, True), {"name": "MyTable", "cmt": None, "rptcmt": "r", "type": None})
        self.assertEqual(dataplan.owner_data({"type": "char[4]"}, base, True), {"name": None, "cmt": None, "rptcmt": None, "type": "char[4]"})
        self.assertIsNone(dataplan.owner_data({"type": "char[4]"}, base, False))
        self.assertEqual(dataplan.owner_data({"cmt": "mine"}, None, False), {"name": None, "cmt": "mine", "rptcmt": None, "type": None})

    def test_ida_values(self):
        owner = {"name": "N", "cmt": "mine", "rptcmt": None, "type": None}
        self.assertEqual(dataplan.ida_values(owner, {"cmt": "ida", "rptcmt": "ida r", "name": "jpt"}), {"cmt": "ida"})
        self.assertEqual(dataplan.ida_values(owner, None), {})
        owner = {"name": None, "cmt": None, "rptcmt": None, "type": "char[4]"}
        self.assertEqual(dataplan.ida_values(owner, {"type": "int", "cmt": "ida"}), {"type": "int"})


class MapTargetTest(unittest.TestCase):
    def targets(self, table):
        return lambda func, off: table.get((func, off), [])

    def test_all_gated_refs_agree(self):
        refs = [[0x1000, 4], [0x2000, 8]]
        got = dataplan.map_target(refs, lambda f: True, self.targets({(0x1000, 4): [0x9000], (0x2000, 8): [0x9000]}))
        self.assertEqual(got, (0x9000, None))

    def test_only_gated_refs_count(self):
        refs = [[0x1000, 4], [0x2000, 8]]
        got = dataplan.map_target(refs, lambda f: f == 0x1000, self.targets({(0x1000, 4): [0x9000], (0x2000, 8): [0x9100]}))
        self.assertEqual(got, (0x9000, None))

    def test_no_gated_ref(self):
        new, why = dataplan.map_target([[0x1000, 4]], lambda f: False, self.targets({}))
        self.assertIsNone(new)
        self.assertEqual(why, "none of its 1 reference(s) is in a function that passed the gate")
        self.assertEqual(dataplan.map_target([], lambda f: True, self.targets({}))[1], "none of its 0 reference(s) is in a function that passed the gate")

    def test_disagreement(self):
        refs = [[0x1000, 4], [0x2000, 8]]
        new, why = dataplan.map_target(refs, lambda f: True, self.targets({(0x1000, 4): [0x9000], (0x2000, 8): [0x9100]}))
        self.assertIsNone(new)
        self.assertEqual(why, "its references lead to different addresses in the new database (0x9000, 0x9100)")

    def test_ambiguous_or_missing_target(self):
        refs = [[0x1000, 4], [0x2000, -8]]
        new, why = dataplan.map_target(refs, lambda f: True, self.targets({(0x1000, 4): [0x9000], (0x2000, -8): [0x9000, 0x9100]}))
        self.assertIsNone(new)
        self.assertEqual(why, "the instruction at old 0x1FF8 has 2 data references in the new database")
        new, why = dataplan.map_target(refs[:1], lambda f: True, self.targets({}))
        self.assertEqual(why, "the instruction at old 0x1004 has 0 data references in the new database")

    def test_cap_refs_keeps_the_first_by_function(self):
        refs = [[0x1000 + 0x10 * k, 4] for k in reversed(range(20))]
        got = dataplan.cap_refs(refs)
        self.assertEqual(dataplan.REF_CAP, 16)
        self.assertEqual(got, [[0x1000 + 0x10 * k, 4] for k in range(16)])
        self.assertEqual(dataplan.cap_refs([[0x2000, 8], [0x1000, 4]]), [[0x1000, 4], [0x2000, 8]])
        self.assertEqual(dataplan.cap_refs([]), [])


class SharedTargetsTest(unittest.TestCase):
    def test_only_addresses_claimed_twice(self):
        mapped = [("a", 0x9000), ("b", 0x9100), ("c", 0x9000), ("d", None), ("e", 0x9200), ("f", 0x9000)]
        self.assertEqual(dataplan.shared_targets(mapped), {0x9000: ["a", "c", "f"]})
        self.assertEqual(dataplan.shared_targets([("a", 0x9000), ("b", None), ("c", None)]), {})

    def test_shared_reason(self):
        self.assertEqual(dataplan.shared_reason(0x9000, ["A at 0x1000", "data at 0x1010"]),
                         "its new address 0x9000 is also claimed by A at 0x1000, data at 0x1010")


class AnnotatedTest(unittest.TestCase):
    def test_has_annotation(self):
        self.assertFalse(dataplan.has_annotation({"shape": {}}))
        self.assertFalse(dataplan.has_annotation({"shape": {}, "name": None, "cmt": None, "rptcmt": None, "folder": None}))
        for key in ("name", "cmt", "rptcmt", "folder", "insn", "proto"):
            self.assertTrue(dataplan.has_annotation({"shape": {}, key: "x" if key != "insn" else [{"off": 0}]}), key)
        self.assertTrue(dataplan.has_annotation({"shape": {}, "hexrays": {"cmts": [{"off": 0, "itp": 74, "text": "x"}]}}))


class DecisionsTest(unittest.TestCase):
    def test_type_action(self):
        self.assertEqual(dataplan.type_action("int", True, "int"), "same")
        self.assertEqual(dataplan.type_action("int", False, "int"), "set")
        self.assertEqual(dataplan.type_action(None, False, "int"), "set")
        self.assertEqual(dataplan.type_action("__int64 __fastcall()", False, "int __fastcall(int a)"), "set")
        self.assertEqual(dataplan.type_action("char *__cdecl(char *)", True, "int __fastcall(int a)"), "keep")
        self.assertEqual(dataplan.type_action("char *__cdecl(char *)", True, "int __fastcall(int a)", "char *__cdecl(char *)"), "set")
        self.assertEqual(dataplan.type_action("char *__cdecl(char *)", True, "int __fastcall(int a)", "void __cdecl()"), "keep")

    def test_name_action(self):
        self.assertEqual(dataplan.name_action("Mine", True, "Mine", 0x10, 0x10), "same")
        self.assertEqual(dataplan.name_action("dword_10", False, "Mine", None, 0x10), "set")
        self.assertEqual(dataplan.name_action("dword_10", False, "Mine", 0x20, 0x10), "in-use")
        self.assertEqual(dataplan.name_action("Theirs", True, "Mine", None, 0x10), "keep")
        self.assertEqual(dataplan.name_action("Theirs", True, "Mine", 0x20, 0x10), "in-use")

    def test_size_problem(self):
        self.assertIsNone(dataplan.size_problem(4, 4))
        self.assertEqual(dataplan.size_problem(4, 1), "the data item in the new database is 1 byte(s), the old one is 4")

    def test_unported_reason(self):
        tail = "; data is only ported through references from functions with a certain match"
        self.assertEqual(dataplan.unported_reason({}), "no instruction references it" + tail)
        self.assertEqual(dataplan.unported_reason({"data": 1, "changed": 2}), "only referenced from changed functions (2), data (1)" + tail)
        self.assertEqual(dataplan.unported_reason({"likely": 3, "unmatched": 1, "code": 2}),
                         "only referenced from functions without a certain match (3), functions with no match (1), code outside functions (2)" + tail)
        self.assertEqual(dataplan.unported_reason({"ambiguous": 1}), "only referenced from instructions that also reference other data (1)" + tail)

    def test_label(self):
        self.assertEqual(dataplan.label("Mine", 0x10), "Mine")
        self.assertEqual(dataplan.label(None, 0x10), "data at 0x10")


if __name__ == "__main__":
    unittest.main()
