import unittest

import _path  # noqa: F401
import pseudo


class PseudoTest(unittest.TestCase):
    def test_addresses_comments_spacing(self):
        a = "int  f() {\n  // note\n  return sub_140001234(1); /* x\n y */\n}\n"
        b = "int f() {\n return   sub_140009999(1);\n}"
        self.assertEqual(pseudo.normalise(a), pseudo.normalise(b))

    def test_address_identifiers(self):
        for prefix in ("sub", "loc", "off", "qword", "dword", "word", "byte", "unk", "asc", "stru", "flt", "dbl",
                       "xmmword", "ymmword", "nullsub", "j_sub", "LABEL"):
            self.assertEqual(pseudo.normalise("x = " + prefix + "_140001234;"), "x = ADDR;", prefix)

    def test_short_hex_suffix_kept(self):
        self.assertEqual(pseudo.normalise("sub_1234(x)"), "sub_1234(x)")
        self.assertEqual(pseudo.normalise("LABEL_12"), "LABEL_12")
        self.assertEqual(pseudo.normalise("sub_12345(x)"), "sub_12345(x)")

    def test_other_names_kept(self):
        self.assertEqual(pseudo.normalise("my_sub_140001234(x)"), "my_sub_140001234(x)")
        self.assertEqual(pseudo.normalise("dword_14000123G"), "dword_14000123G")

    def test_bare_hex_numbers(self):
        self.assertEqual(pseudo.normalise("p = 0x140001234;"), "p = ADDR;")
        self.assertEqual(pseudo.normalise("p = 0x14000123456;"), "p = ADDR;")
        self.assertEqual(pseudo.normalise("p = 0x14000123;"), "p = 0x14000123;")

    def test_differing_constant(self):
        self.assertNotEqual(pseudo.normalise("x = 0x10;"), pseudo.normalise("x = 0x20;"))

    def test_first_difference(self):
        a = "one\ntwo\nthree"
        b = "one\nTWO\nthree"
        self.assertEqual(pseudo.first_difference(a, b), "line 2: 'two' != 'TWO'")
        self.assertIsNone(pseudo.first_difference(a, a))

    def test_first_difference_length(self):
        self.assertEqual(pseudo.first_difference("a\nb", "a"), "line 2: 'b' != ''")

    def test_first_difference_ignores_normalised(self):
        self.assertIsNone(pseudo.first_difference("f(sub_140001234); // a", "f(sub_140009999);"))


if __name__ == "__main__":
    unittest.main()
