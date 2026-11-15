import unittest

import _path  # noqa: F401
import pairs

HEADER = "status,name,old_va,new_va,old_size,new_size,method,similarity\n"
OLD_HEADER = "status,name,old_va,new_va,old_size,new_size,similarity\n"


class PairsTest(unittest.TestCase):
    def row(self, line):
        return pairs.parse_map_csv(HEADER + line + "\n")[0]

    def test_parse_header_and_fields(self):
        rows = pairs.parse_map_csv(HEADER + "same,foo,0x140001000,0x140002000,16,16,exact-unique,100\nadded,bar,,0x140003000,,32,,\n")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0], pairs.Row("same", "foo", 0x140001000, 0x140002000, 16, 16, "exact-unique", 100))
        self.assertEqual(rows[1], pairs.Row("added", "bar", None, 0x140003000, None, 32, None, None))

    def test_parse_tolerates_crlf_and_bom(self):
        text = "\ufeff" + (HEADER + "removed,gone,0x140001000,,16,,,\n").replace("\n", "\r\n")
        rows = pairs.parse_map_csv(text)
        self.assertEqual(rows, [pairs.Row("removed", "gone", 0x140001000, None, 16, None, None, None)])

    def test_parse_name_with_comma(self):
        r = self.row("same,operator,,0x1,0x2,4,4,exact-unique,100")
        self.assertEqual(r.name, "operator,")
        self.assertEqual(r.old_va, 1)

    def test_old_header_rejected(self):
        with self.assertRaises(ValueError) as cm:
            pairs.parse_map_csv(OLD_HEADER + "same,foo,0x1,0x2,4,4,100\n")
        self.assertEqual(str(cm.exception), "map.csv is from an older exediff: it has no method column; run exediff again")

    def test_parse_pair_txt(self):
        text = "old_exe=C:\\a=b\\old.exe\r\nold_size=12\nnew_md5=abc\n\n"
        self.assertEqual(pairs.parse_pair_txt(text), {"old_exe": "C:\\a=b\\old.exe", "old_size": "12", "new_md5": "abc"})

    def test_classes(self):
        self.assertEqual(pairs.classify(self.row("same,f,0x1,0x2,4,4,exact-unique,100")), "certain")
        self.assertEqual(pairs.classify(self.row("same,f,0x1,0x2,4,4,refined,100")), "likely")
        self.assertEqual(pairs.classify(self.row("calls_changed,f,0x1,0x2,4,4,exact-group,100")), "likely")
        self.assertEqual(pairs.classify(self.row("changed,f,0x1,0x2,4,4,similar,79")), "below")
        self.assertEqual(pairs.classify(self.row("changed,f,0x1,0x2,4,4,similar,80")), "changed")
        self.assertEqual(pairs.classify(self.row("changed,f,0x1,0x2,4,4,similar,60"), 50), "changed")
        self.assertEqual(pairs.classify(self.row("added,f,,0x2,,4,,")), "unpaired")
        self.assertEqual(pairs.classify(self.row("removed,f,0x1,,4,,,")), "unpaired")

    def test_is_ported(self):
        table = {"certain": (True, True), "changed": (True, True), "likely": (False, True),
                 "below": (False, False), "unpaired": (False, False)}
        for cls, (plain, likely) in table.items():
            self.assertEqual(pairs.is_ported(cls, False), plain, cls)
            self.assertEqual(pairs.is_ported(cls, True), likely, cls)

    def test_build_pairing(self):
        rows = pairs.parse_map_csv(HEADER + "\n".join([
            "same,a,0x10,0x110,4,4,exact-unique,100",
            "changed,b,0x20,0x120,4,4,similar,50",
            "removed,c,0x30,,4,,,",
            "added,d,,0x140,,4,,",
        ]) + "\n")
        p = pairs.build_pairing(rows)
        self.assertEqual(p.new_of(0x10), 0x110)
        self.assertEqual(p.new_of(0x20), 0x120)
        self.assertIsNone(p.new_of(0x30))
        self.assertIsNone(p.new_of(0x99))
        self.assertEqual(p.classes, {0x10: "certain", 0x20: "below"})
        self.assertEqual(p.unpaired_old, {0x30})
        self.assertEqual(p.unpaired_new, {0x140})
        self.assertEqual(set(p.rows), {0x10, 0x20})


if __name__ == "__main__":
    unittest.main()
