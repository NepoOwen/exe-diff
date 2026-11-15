import unittest

import _path  # noqa: F401
import align


def shape(*insns, frsize=8, argsize=0):
    return {"frsize": frsize, "argsize": argsize, "insns": [list(i) for i in insns]}


BASE = [
    (0, 1, "push", [1], None),
    (1, 3, "mov", [1, 1], None),
    (4, 5, "call", [7], 0x1000),
    (9, 1, "retn", [], None),
]


class AlignTest(unittest.TestCase):
    def match(self, old, new, mapping=None, paired_new=()):
        mapping = mapping or {}
        return align.shapes_match(old, new, mapping.get, lambda n: n in paired_new)

    def test_identical(self):
        old = shape(*BASE)
        new = shape(*[i[:4] + (0x2000,) if i[2] == "call" else i for i in BASE])
        ok, reason = self.match(old, new, {0x1000: 0x2000}, {0x2000})
        self.assertTrue(ok, reason)

    def test_frame_sizes(self):
        ok, reason = self.match(shape(*BASE[:1], frsize=8), shape(*BASE[:1], frsize=16))
        self.assertFalse(ok)
        self.assertIn("frame", reason)
        ok, reason = self.match(shape(*BASE[:1], argsize=0), shape(*BASE[:1], argsize=8))
        self.assertFalse(ok)

    def test_count(self):
        ok, reason = self.match(shape(*BASE[:2]), shape(*BASE[:3]))
        self.assertFalse(ok)
        self.assertIn("count", reason)

    def test_mnemonic_change_names_offset(self):
        new = [list(i) for i in BASE]
        new[1][2] = "lea"
        ok, reason = self.match(shape(*BASE[:2]), shape(*new[:2]))
        self.assertFalse(ok)
        self.assertIn("0x1", reason)
        self.assertIn("mnemonic", reason)

    def test_size_offset_optypes(self):
        for field, value, word in ((0, 7, "offset"), (1, 9, "size"), (3, [2, 1], "operand")):
            new = [list(i) for i in BASE[:2]]
            new[1][field] = value
            ok, reason = self.match(shape(*BASE[:2]), shape(*new))
            self.assertFalse(ok, word)
            self.assertIn(word, reason)

    def test_call_target_paired_consistently(self):
        old = shape((0, 5, "call", [7], 0x1000))
        new = shape((0, 5, "call", [7], 0x2000))
        self.assertTrue(self.match(old, new, {0x1000: 0x2000}, {0x2000})[0])

    def test_call_target_paired_inconsistently(self):
        old = shape((0, 5, "call", [7], 0x1000))
        new = shape((0, 5, "call", [7], 0x3000))
        ok, reason = self.match(old, new, {0x1000: 0x2000}, {0x2000, 0x3000})
        self.assertFalse(ok)
        self.assertIn("0x0", reason)

    def test_paired_old_target_missing_new_target(self):
        old = shape((0, 5, "call", [7], 0x1000))
        new = shape((0, 5, "call", [7], None))
        self.assertFalse(self.match(old, new, {0x1000: 0x2000})[0])

    def test_unpaired_old_target_unpaired_new_target_passes(self):
        old = shape((0, 5, "call", [7], 0x1000))
        new = shape((0, 5, "call", [7], 0x3000))
        self.assertTrue(self.match(old, new, {}, {0x2000})[0])

    def test_unpaired_old_target_became_paired_new_target(self):
        old = shape((0, 5, "call", [7], 0x1000))
        new = shape((0, 5, "call", [7], 0x2000))
        ok, reason = self.match(old, new, {}, {0x2000})
        self.assertFalse(ok)
        self.assertIn("0x0", reason)

    def test_align_runs(self):
        out = align.align_runs(list("abcXdef"), list("abcYdef"))
        self.assertEqual(out, [(0, 0), (1, 1), (2, 2), (4, 4), (5, 5), (6, 6)])

    def test_align_runs_drops_short(self):
        out = align.align_runs(list("abXcd"), list("abYcd"))
        self.assertEqual(out, [])
        out = align.align_runs(list("abXcd"), list("abYcd"), min_run=2)
        self.assertEqual(out, [(0, 0), (1, 1), (3, 3), (4, 4)])

    def test_align_runs_with_insertion(self):
        out = align.align_runs(list("abcdef"), list("abcQdef"))
        self.assertEqual(out, [(0, 0), (1, 1), (2, 2), (3, 4), (4, 5), (5, 6)])


if __name__ == "__main__":
    unittest.main()
