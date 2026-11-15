import unittest

import _path  # noqa: F401
import typedecl

ENUM = "enum __bitmask ExedFixEnum\n{\n  EXED_A = 0x1,\n  EXED_B = 0x2,\n};"
STRUCT = "struct ExedFixStruct\n{\n  int a;\n  char b[8];\n  ExedFixEnum e;\n};"
PTR = "typedef ExedFixStruct *PExedFixStruct;"
CYC_A = "struct CycA\n{\n  CycB *b;\n  int x;\n};"
CYC_B = "#pragma pack(push, 8)\nstruct CycB\n{\n  CycA *a;\n};\n#pragma pack(pop)"
PARENT = "struct Parent\n{\n  int k;\n  Child c;\n};"
CHILD = "struct Child\n{\n  Parent *p;\n  int z;\n};"


def t(name, decl):
    return {"name": name, "decl": decl}


def names(types):
    return [x["name"] for x in types]


class TypeDeclTest(unittest.TestCase):
    def test_clean_drops_the_ordinal_comment(self):
        self.assertEqual(typedecl.clean("/* 401 */\r\nstruct A\n{\n  int a;  \n};\n\n"), "struct A\n{\n  int a;\n};")
        self.assertEqual(typedecl.clean(""), "")
        self.assertEqual(typedecl.clean(None), "")

    def test_kinds(self):
        self.assertEqual(typedecl.udt_kind(STRUCT), "struct")
        self.assertEqual(typedecl.udt_kind(CYC_B), "struct")
        self.assertEqual(typedecl.udt_kind("union U\n{\n  int a;\n};"), "union")
        self.assertIsNone(typedecl.udt_kind(ENUM))
        self.assertIsNone(typedecl.udt_kind(PTR))
        self.assertIsNone(typedecl.udt_kind("typedef struct _GUID GUID;"))
        self.assertTrue(typedecl.is_forward("struct A;"))
        self.assertFalse(typedecl.is_forward(STRUCT))
        self.assertFalse(typedecl.is_forward(PTR))

    def test_anonymous(self):
        self.assertTrue(typedecl.anonymous("ExedAnon::$B50FBEEF0F74E18DFCCC9B7A942D2C5D"))
        self.assertTrue(typedecl.anonymous("tagVARIANT::$::$65D6"))
        self.assertFalse(typedecl.anonymous("Exed::Inner"))
        self.assertFalse(typedecl.anonymous("ExedFixStruct"))

    def test_refs(self):
        all_names = {"ExedFixEnum", "ExedFixStruct", "PExedFixStruct", "Exed::Inner"}
        self.assertEqual(typedecl.refs(STRUCT, all_names, "ExedFixStruct"), {"ExedFixEnum"})
        self.assertEqual(typedecl.refs(PTR, all_names, "PExedFixStruct"), {"ExedFixStruct"})
        self.assertEqual(typedecl.refs("struct B { Exed::Inner i; };", all_names, "B"), {"Exed::Inner"})
        self.assertEqual(typedecl.refs(ENUM, all_names, "ExedFixEnum"), set())

    def test_order_puts_used_types_first(self):
        types = [t("ExedFixStruct", STRUCT), t("PExedFixStruct", PTR), t("Other", "struct Other\n{\n  int z;\n};"), t("ExedFixEnum", ENUM)]
        self.assertEqual(names(typedecl.order(types)), ["Other", "ExedFixEnum", "ExedFixStruct", "PExedFixStruct"])

    def test_order_keeps_a_sorted_list(self):
        types = [t("ExedFixEnum", ENUM), t("ExedFixStruct", STRUCT), t("PExedFixStruct", PTR)]
        self.assertEqual(typedecl.order(types), types)
        self.assertEqual(typedecl.order([]), [])

    def test_cycle_through_pointers(self):
        out = typedecl.order([t("CycA", CYC_A), t("CycB", CYC_B)])
        self.assertEqual(names(out), ["CycA", "CycB"])
        self.assertEqual(typedecl.forwards(out), {"CycA": ["struct CycB;"], "CycB": ["struct CycA;"]})

    def test_cycle_breaks_at_a_type_whose_later_uses_can_be_forward_declared(self):
        a = "struct A\n{\n  PB p;\n};"
        pb = "typedef B *PB;"
        b = "struct B\n{\n  A *a;\n};"
        out = typedecl.order([t("A", a), t("PB", pb), t("B", b)])
        self.assertEqual(names(out), ["PB", "A", "B"])
        self.assertEqual(typedecl.forwards(out), {"PB": ["struct B;"], "A": [], "B": ["struct A;"]})

    def test_self_reference_needs_no_forward(self):
        node = [t("Node", "struct Node\n{\n  Node *next;\n};")]
        self.assertEqual(typedecl.order(node), node)
        self.assertEqual(typedecl.forwards(node), {"Node": []})

    def test_uses_tell_by_value_from_pointer(self):
        all_names = {"Child", "Parent", "Fn"}
        decl = "struct Parent\n{\n  Child c;\n  Child *p;\n};"
        self.assertEqual(typedecl.uses(decl, all_names, "Parent"), {"Child": True})
        self.assertEqual(typedecl.uses("struct Parent\n{\n  Child *p;\n  const Child *const q;\n  Child &r;\n};", all_names, "Parent"), {"Child": False})
        self.assertEqual(typedecl.uses("struct Parent\n{\n  Child c[2];\n};", all_names, "Parent"), {"Child": True})
        self.assertEqual(typedecl.uses("typedef int (__fastcall *Fn)(Child c, Parent *p);", all_names, "Fn"), {"Child": False, "Parent": False})
        self.assertEqual(typedecl.uses("struct __cppobj Parent : Child\n{\n  int k;\n};", all_names, "Parent"), {"Child": True})

    def test_by_value_cycle_parent_first(self):
        types = [t("Parent", PARENT), t("Child", CHILD)]
        out = typedecl.order(types)
        self.assertEqual(names(out), ["Child", "Parent"])
        self.assertEqual(typedecl.forwards(out), {"Child": ["struct Parent;"], "Parent": []})
        self.assertEqual(typedecl.needs_complete(out), {"Child": set(), "Parent": {"Child"}})

    def test_by_value_cycle_child_first(self):
        out = typedecl.order([t("Child", CHILD), t("Parent", PARENT)])
        self.assertEqual(names(out), ["Child", "Parent"])
        self.assertEqual(typedecl.forwards(out), {"Child": ["struct Parent;"], "Parent": []})

    def test_by_value_array_cycle(self):
        parent = "struct Parent\n{\n  int k;\n  Child c[4];\n};"
        out = typedecl.order([t("Parent", parent), t("Child", CHILD)])
        self.assertEqual(names(out), ["Child", "Parent"])
        self.assertEqual(typedecl.forwards(out), {"Child": ["struct Parent;"], "Parent": []})

    def test_by_value_through_a_typedef(self):
        parent = "struct Parent\n{\n  ChildT c;\n};"
        child_t = "typedef Child ChildT;"
        types = [t("Parent", parent), t("ChildT", child_t), t("Child", CHILD)]
        out = typedecl.order(types)
        self.assertEqual(names(out), ["ChildT", "Child", "Parent"])
        self.assertEqual(typedecl.forwards(out), {"ChildT": ["struct Child;"], "Child": ["struct Parent;"], "Parent": []})
        self.assertEqual(typedecl.needs_complete(out)["Parent"], {"ChildT", "Child"})

    def test_never_forward_declares_a_by_value_use(self):
        a = "struct A\n{\n  B b;\n};"
        b = "struct B\n{\n  A a;\n};"
        out = typedecl.order([t("A", a), t("B", b)])
        self.assertEqual(sorted(names(out)), ["A", "B"])
        self.assertEqual(typedecl.forwards(out), {"A": [], "B": []})

    def test_forwards_only_for_unions_and_structs_used_by_pointer(self):
        types = [t("ExedFixEnum", ENUM), t("ExedFixStruct", STRUCT), t("PExedFixStruct", PTR)]
        self.assertEqual(typedecl.forwards(types), {"ExedFixEnum": [], "ExedFixStruct": [], "PExedFixStruct": ["struct ExedFixStruct;"]})
        types = [t("S", "struct S\n{\n  U *u;\n  E *e;\n};"), t("U", "union U\n{\n  S *s;\n};"), t("E", "enum E\n{\n  X = 0,\n};")]
        self.assertEqual(typedecl.forwards(types), {"S": ["union U;"], "U": ["struct S;"], "E": []})


if __name__ == "__main__":
    unittest.main()
