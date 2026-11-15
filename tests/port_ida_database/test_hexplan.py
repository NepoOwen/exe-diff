import unittest

import _path  # noqa: F401
import hexplan

OLD_SHAPE = {"frsize": 0x28, "argsize": 0, "insns": [[0, 4, "sub", [1, 5], None], [4, 3, "mov", [1, 4], None], [7, 5, "call", [7], 100],
                                                     [12, 4, "add", [1, 5], None], [16, 1, "retn", [], None]]}
HX = {"cmts": [{"off": 4, "itp": 74, "text": "a comment"}],
      "numforms": [{"off": 0, "opnum": 1, "flags": 0x1100000, "nf_opnum": 1, "props": 1, "serial": 0, "nbytes": 0, "type_name": "", "types": {}}],
      "unions": [{"off": 12, "path": [1]}],
      "labels": [{"num": 6, "name": "done"}],
      "iflags": [{"off": 12, "op": 73, "flags": 1}],
      "lvars": {"stkoff_delta": 0, "ulv_flags": 1, "list": [
          {"loc": ["stk", 0x20], "defoff": 4, "name": "count", "type": None, "cmt": None, "size": -1, "flags": 0},
          {"loc": ["reg", 8], "defoff": 0, "name": None, "type": "PS", "cmt": "the thing", "size": -1, "flags": 0}]},
      "frame": [0x28, 8, 0, 0], "ops": "abc"}


def shape(**changes):
    out = {"frsize": OLD_SHAPE["frsize"], "argsize": OLD_SHAPE["argsize"], "insns": [list(x) for x in OLD_SHAPE["insns"]]}
    for off, x in changes.items():
        out["insns"] = [x if i[0] == int(off[1:]) else i for i in out["insns"]]
    return out


class ItemsTest(unittest.TestCase):
    def test_items_and_counts(self):
        kinds = [k for k, _it in hexplan.items_of(HX)]
        self.assertEqual(kinds, ["cmts", "numforms", "unions", "iflags", "lvars", "lvars"])
        self.assertEqual(hexplan.items_of({}), [])
        self.assertEqual(hexplan.count_text(HX), "1 comment(s), 1 number format(s), 1 union selection(s), 1 label(s), 1 item flag(s), 2 variable setting(s)")
        self.assertEqual(hexplan.count_text({"cmts": [{"off": 0, "itp": 74, "text": "x"}]}), "1 comment(s)")
        self.assertEqual(hexplan.count_text({"labels": [{"num": 1, "name": "a"}]}), "1 label(s)")

    def test_labels_are_only_listed(self):
        self.assertEqual(hexplan.KINDS, ("cmts", "numforms", "unions", "iflags"))
        self.assertNotIn("labels", hexplan.EXACT)
        self.assertEqual(hexplan.labels_text([{"num": 6, "name": "done"}, {"num": 9, "name": "again"}]),
                         "its 2 Hex-Rays label(s) (done, again) are not ported: labels are keyed by the decompiler's label number: not ported")

    def test_keys_values_offsets(self):
        self.assertEqual(hexplan.key_of("cmts", HX["cmts"][0]), (4, 74))
        self.assertEqual(hexplan.value_of("cmts", HX["cmts"][0]), "a comment")
        self.assertEqual(hexplan.key_of("numforms", HX["numforms"][0]), (0, 1))
        self.assertEqual(hexplan.value_of("numforms", HX["numforms"][0]), (0x1100000, 1, 1, 0, 0, ""))
        self.assertEqual(hexplan.key_of("unions", HX["unions"][0]), 12)
        self.assertEqual(hexplan.value_of("unions", HX["unions"][0]), (1,))
        self.assertEqual(hexplan.key_of("iflags", HX["iflags"][0]), (12, 73))
        self.assertEqual(hexplan.key_of("lvars", HX["lvars"]["list"][0]), (("stk", 0x20), 4))
        self.assertEqual(hexplan.value_of("lvars", HX["lvars"]["list"][1]), {"name": None, "type": "PS", "cmt": "the thing", "size": -1, "flags": 0})
        self.assertEqual(hexplan.off_of("cmts", HX["cmts"][0]), 4)
        self.assertEqual(hexplan.off_of("lvars", HX["lvars"]["list"][0]), 4)
        self.assertEqual(hexplan.off_of("lvars", dict(HX["lvars"]["list"][0], defoff=None)), None)

    def test_describe(self):
        self.assertEqual(hexplan.describe("cmts", HX["cmts"][0]), "the Hex-Rays comment at +0x4")
        self.assertEqual(hexplan.describe("numforms", HX["numforms"][0]), "the Hex-Rays number format of operand 1 at +0x0")
        self.assertEqual(hexplan.describe("unions", HX["unions"][0]), "the Hex-Rays union selection at +0xC")
        self.assertEqual(hexplan.describe("iflags", HX["iflags"][0]), "the Hex-Rays item flags at +0xC")
        self.assertEqual(hexplan.describe("lvars", HX["lvars"]["list"][0]), "the Hex-Rays variable count (stack 0x20)")
        self.assertEqual(hexplan.describe("lvars", HX["lvars"]["list"][1]), "the Hex-Rays variable setting for register 8")


class PlaceTest(unittest.TestCase):
    def test_same_shape_places_everything(self):
        old, new = hexplan.insn_map(OLD_SHAPE), hexplan.insn_map(shape())
        for kind, it in hexplan.items_of(HX):
            self.assertIsNone(hexplan.place_problem(kind, it, old, new), (kind, it))

    def test_offset_must_be_the_same_instruction(self):
        old = hexplan.insn_map(OLD_SHAPE)
        new = hexplan.insn_map(shape(o4=[4, 3, "lea", [1, 4], None]))
        self.assertEqual(hexplan.place_problem("cmts", HX["cmts"][0], old, new), "the instruction at +0x4 differs in the new function (old mov, new lea)")
        new = hexplan.insn_map({"insns": [x for x in OLD_SHAPE["insns"] if x[0] != 12]})
        self.assertEqual(hexplan.place_problem("unions", HX["unions"][0], old, new), "+0xC is not an instruction in the new function")
        self.assertEqual(hexplan.place_problem("cmts", dict(HX["cmts"][0], off=5), old, hexplan.insn_map(OLD_SHAPE)),
                         "+0x5 is not an instruction in the new function")
        self.assertEqual(hexplan.place_problem("cmts", dict(HX["cmts"][0], off=5), {}, {5: ("mov", [])}),
                         "+0x5 was not an instruction in the old function")
        self.assertIsNone(hexplan.place_problem("lvars", dict(HX["lvars"]["list"][0], defoff=None), old, {}))
        self.assertEqual(hexplan.place_problem("lvars", dict(HX["lvars"]["list"][0], defoff=6), old, old), "+0x6 is not an instruction in the new function")

    def test_numform_operand_must_exist(self):
        old = hexplan.insn_map(OLD_SHAPE)
        new = hexplan.insn_map(shape(o0=[0, 4, "sub", [1, 1], None]))
        self.assertEqual(hexplan.place_problem("numforms", HX["numforms"][0], old, new), "operand 1 of the instruction at +0x0 differs in the new function")
        self.assertEqual(hexplan.place_problem("numforms", dict(HX["numforms"][0], opnum=3), old, old), "operand 3 of the instruction at +0x0 differs in the new function")

    def test_exact(self):
        self.assertIsNone(hexplan.exact_problem(HX, [0x28, 8, 0, 0], "abc"))
        self.assertEqual(hexplan.exact_problem(HX, [0x30, 8, 0, 0], "abc"), "the stack frame differs in the new function")
        self.assertEqual(hexplan.exact_problem(HX, [0x28, 8, 0, 0], "abd"), "the registers or stack offsets its instructions use differ in the new function")
        self.assertEqual(hexplan.exact_problem({}, [0x28, 8, 0, 0], "abc"), "the stack frame differs in the new function")
        self.assertEqual(hexplan.EXACT, ("unions", "iflags", "lvars"))


class MergeTest(unittest.TestCase):
    def test_merge_adds_and_keeps(self):
        a, b, c = {"off": 1}, {"off": 2}, {"off": 3}
        result, added, notes = hexplan.merge("cmts", {(1, 74): "mine", (9, 74): "other"}, [((1, 74), "theirs", a), ((2, 74), "new", b), ((9, 74), "other", c)])
        self.assertEqual(result, {(1, 74): "mine", (2, 74): "new", (9, 74): "other"})
        self.assertEqual(added, 1)
        self.assertEqual(notes, [(a, "hexrays-differs", "the new function already has another one, kept")])
        result, added, notes = hexplan.merge("cmts", {}, [])
        self.assertEqual((result, added, notes), ({}, 0, []))

    def test_merge_does_not_change_input(self):
        have = {(1, 74): "x"}
        hexplan.merge("cmts", have, [((2, 74), "y", {})])
        self.assertEqual(have, {(1, 74): "x"})


def fields(name=None, type=None, cmt=None, size=-1, flags=0):
    return {"name": name, "type": type, "cmt": cmt, "size": size, "flags": flags}


STK, REG = (("stk", 0x20), 4), (("reg", 8), 0)


class MergeLvarsTest(unittest.TestCase):
    def test_no_existing_settings(self):
        a, b = {"x": 1}, {"x": 2}
        result, changed, notes = hexplan.merge_lvars(None, {"delta": 0, "flags": 1}, [(STK, fields("count"), a), (REG, fields(type="PS", cmt="c"), b)])
        self.assertEqual(result, {"delta": 0, "flags": 1, "items": {STK: fields("count"), REG: fields(type="PS", cmt="c")}})
        self.assertEqual((changed, notes), (2, []))

    def test_existing_fields_are_kept(self):
        a = {"x": 1}
        have = {"delta": 0, "flags": 1, "items": {STK: fields("mine", cmt="my note", flags=2)}}
        result, changed, notes = hexplan.merge_lvars(have, {"delta": 0, "flags": 1}, [(STK, fields("count", type="int", cmt="their note"), a)])
        self.assertEqual(result["items"][STK], fields("mine", type="int", cmt="my note", flags=2))
        self.assertEqual(changed, 1)
        self.assertEqual(notes, [(a, "hexrays-differs", "the new function already has the name mine for it, kept"),
                                 (a, "hexrays-differs", "the new function already has the comment 'my note' for it, kept")])
        self.assertEqual(have["items"][STK], fields("mine", cmt="my note", flags=2))

    def test_equal_settings_change_nothing(self):
        have = {"delta": 0, "flags": 1, "items": {STK: fields("count", type="int")}}
        result, changed, notes = hexplan.merge_lvars(have, {"delta": 0, "flags": 1}, [(STK, fields("count", type="int"), {})])
        self.assertEqual((result, changed, notes), (have, 0, []))

    def test_name_clash_drops_only_the_name(self):
        a, b = {"x": 1}, {"x": 2}
        have = {"delta": 0, "flags": 1, "items": {(("stk", 8), None): fields("count")}}
        result, changed, notes = hexplan.merge_lvars(have, {"delta": 0, "flags": 1}, [(STK, fields("count", cmt="c"), a), (REG, fields("count"), b)])
        self.assertEqual(result["items"][STK], fields(cmt="c"))
        self.assertNotIn(REG, result["items"])
        self.assertEqual(changed, 1)
        self.assertEqual(notes, [(a, "hexrays-skipped", "the name count is already used by another variable in the new function"),
                                 (b, "hexrays-skipped", "the name count is already used by another variable in the new function")])

    def test_name_clash_between_ported_items(self):
        a, b = {"x": 1}, {"x": 2}
        result, changed, notes = hexplan.merge_lvars(None, {"delta": 0, "flags": 1}, [(STK, fields("n"), a), (REG, fields("n", type="int"), b)])
        self.assertEqual(result["items"], {STK: fields("n"), REG: fields(type="int")})
        self.assertEqual([n[0] for n in notes], [b])

    def test_other_stack_base_skips_all(self):
        a = {"x": 1}
        have = {"delta": 8, "flags": 1, "items": {REG: fields("mine")}}
        result, changed, notes = hexplan.merge_lvars(have, {"delta": 0, "flags": 1}, [(STK, fields("count"), a)])
        self.assertEqual((result, changed), (have, 0))
        self.assertEqual(notes, [(a, "hexrays-skipped", "the new function's variable settings use another stack base or flags (delta 0x8, flags 0x1; old delta 0x0, flags 0x1)")])

    def test_existing_header_without_items_skips_all(self):
        a = {"x": 1}
        have = {"delta": 8, "flags": 0, "items": {}}
        result, changed, notes = hexplan.merge_lvars(have, {"delta": 0, "flags": 1}, [(STK, fields("count"), a)])
        self.assertEqual((result, changed), (have, 0))
        self.assertEqual(notes, [(a, "hexrays-skipped", "the new function's variable settings use another stack base or flags (delta 0x8, flags 0x0; old delta 0x0, flags 0x1)")])

    def test_absent_or_equal_header_takes_the_old_header(self):
        result, changed, notes = hexplan.merge_lvars(None, {"delta": 0, "flags": 1}, [(STK, fields("count"), {})])
        self.assertEqual((result["delta"], result["flags"], changed, notes), (0, 1, 1, []))
        result, changed, notes = hexplan.merge_lvars({"delta": 0, "flags": 1, "items": {}}, {"delta": 0, "flags": 1}, [(STK, fields("count"), {})])
        self.assertEqual((result["delta"], result["flags"], changed, notes), (0, 1, 1, []))

    def test_new_items_get_no_size(self):
        result, changed, notes = hexplan.merge_lvars(None, {"delta": 0, "flags": 1}, [(STK, fields("count", type="int", size=8), {}), (REG, fields("n", size=8), {})])
        self.assertEqual(result["items"], {STK: fields("count", type="int"), REG: fields("n")})

    def test_dropped_type_drops_its_size(self):
        self.assertEqual(hexplan.without_type(fields("n", type="PS", cmt="c", size=8, flags=2)), fields("n", cmt="c", flags=2))
        result, changed, notes = hexplan.merge_lvars(None, {"delta": 0, "flags": 1}, [(REG, hexplan.without_type(fields("n", type="PS", size=8)), {})])
        self.assertEqual(result["items"], {REG: fields("n")})

    def test_filled_type_resets_size(self):
        have = {"delta": 0, "flags": 1, "items": {STK: fields(cmt="mine", size=4)}}
        result, changed, notes = hexplan.merge_lvars(have, {"delta": 0, "flags": 1}, [(STK, fields("n", type="int", size=8), {})])
        self.assertEqual(result["items"][STK], fields("n", type="int", cmt="mine"))
        self.assertEqual((changed, notes), (1, []))

    def test_existing_type_keeps_its_size(self):
        have = {"delta": 0, "flags": 1, "items": {STK: fields(type="int", size=4)}}
        result, changed, notes = hexplan.merge_lvars(have, {"delta": 0, "flags": 1}, [(STK, fields("n", type="int", size=8), {})])
        self.assertEqual(result["items"][STK], fields("n", type="int", size=4))
        self.assertEqual(changed, 1)

    def test_empty_item_is_not_added(self):
        result, changed, notes = hexplan.merge_lvars(None, {"delta": 0, "flags": 1}, [(STK, fields(), {})])
        self.assertEqual((result["items"], changed, notes), ({}, 0, []))
        result, changed, notes = hexplan.merge_lvars(None, {"delta": 0, "flags": 1}, [(STK, fields(flags=4), {})])
        self.assertEqual((result["items"], changed), ({STK: fields(flags=4)}, 1))


if __name__ == "__main__":
    unittest.main()
