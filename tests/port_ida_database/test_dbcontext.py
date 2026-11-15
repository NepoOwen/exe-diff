import os
import struct
import tempfile
import unittest

import _path  # noqa: F401
import dbcontext

OLD = {"tils": ["mssdk64_win7"], "compiler": "Visual C++", "abi": "", "imagebase": 0x140000000, "bitness": 64}


class DifferencesTest(unittest.TestCase):
    def test_same(self):
        self.assertEqual(dbcontext.differences(OLD, dict(OLD)), [])

    def test_til_order_does_not_matter(self):
        old = dict(OLD, tils=["a", "b"])
        self.assertEqual(dbcontext.differences(old, dict(OLD, tils=["b", "a"])), [])

    def test_til_only_in_old(self):
        diffs = dbcontext.differences(dict(OLD, tils=["mssdk64_win7", "ntddk64_win10"]), OLD)
        self.assertEqual([k for k, _t in diffs], ["tils"])
        text = diffs[0][1]
        self.assertIn("type libraries", text)
        self.assertIn("ntddk64_win10", text)
        self.assertNotIn("mssdk64_win7", text)

    def test_til_only_in_new(self):
        diffs = dbcontext.differences(OLD, dict(OLD, tils=["mssdk64_win7", "vc10_64"]))
        self.assertIn("vc10_64", diffs[0][1])

    def test_each_key(self):
        new = {"tils": ["x"], "compiler": "GNU C++", "abi": "sysv", "imagebase": 0x150000000, "bitness": 32}
        diffs = dict(dbcontext.differences(OLD, new))
        self.assertEqual(sorted(diffs), ["abi", "bitness", "compiler", "tils"])
        self.assertIn("Visual C++", diffs["compiler"])
        self.assertIn("GNU C++", diffs["compiler"])
        self.assertIn("64-bit", diffs["bitness"])
        self.assertIn("none", diffs["abi"])

    def test_type_library_first(self):
        new = {"tils": ["x"], "compiler": "GNU C++", "abi": "", "imagebase": 0x150000000, "bitness": 64}
        self.assertEqual([k for k, _t in dbcontext.differences(OLD, new)][0], "tils")

    def test_image_base_is_information_only(self):
        new = dict(OLD, imagebase=0x150000000)
        self.assertEqual(dbcontext.differences(OLD, new), [])
        info = dbcontext.information(OLD, new)
        self.assertEqual(len(info), 1)
        self.assertIn("0x140000000", info[0])
        self.assertIn("0x150000000", info[0])
        self.assertIn("information only", info[0])
        self.assertNotIn("expected", info[0])
        self.assertEqual(dbcontext.information(OLD, dict(OLD)), [])
        self.assertEqual(dbcontext.information({}, OLD), [])

    def test_missing_keys_are_not_compared(self):
        self.assertEqual(dbcontext.differences({}, OLD), [])
        self.assertEqual(dbcontext.differences({"tils": ["a"]}, OLD)[0][0], "tils")

    def test_refusal(self):
        diffs = dbcontext.differences(OLD, dict(OLD, compiler="GNU C++"))
        text = dbcontext.refusal(diffs)
        self.assertIn("-Strict", text)
        self.assertIn("GNU C++", text)


def pe(magic, base, lfanew=0x80, machine=0x8664, chars=0x22):
    data = bytearray(lfanew + 24 + 0x70)
    data[0:2] = b"MZ"
    struct.pack_into("<I", data, 0x3C, lfanew)
    data[lfanew:lfanew + 4] = b"PE\0\0"
    struct.pack_into("<H", data, lfanew + 4, machine)
    struct.pack_into("<H", data, lfanew + 22, chars)
    opt = lfanew + 24
    struct.pack_into("<H", data, opt, magic)
    if magic == 0x20B:
        struct.pack_into("<Q", data, opt + 24, base)
    else:
        struct.pack_into("<I", data, opt + 28, base)
    return bytes(data)


class ImageBaseTest(unittest.TestCase):
    def test_pe32_plus(self):
        self.assertEqual(dbcontext.pe_imagebase(pe(0x20B, 0x140000000)), 0x140000000)

    def test_pe32(self):
        self.assertEqual(dbcontext.pe_imagebase(pe(0x10B, 0x400000)), 0x400000)

    def test_far_header(self):
        self.assertEqual(dbcontext.pe_imagebase(pe(0x20B, 0x180000000, lfanew=0x1100)), 0x180000000)

    def test_not_a_pe(self):
        self.assertIsNone(dbcontext.pe_imagebase(b""))
        self.assertIsNone(dbcontext.pe_imagebase(b"ZM" + bytes(200)))
        good = bytearray(pe(0x20B, 0x140000000))
        good[0x80:0x84] = b"NE\0\0"
        self.assertIsNone(dbcontext.pe_imagebase(bytes(good)))
        self.assertIsNone(dbcontext.pe_imagebase(pe(0x107, 0x400000)))
        self.assertIsNone(dbcontext.pe_imagebase(pe(0x20B, 0x140000000)[:0x80 + 30]))

    def test_exe_imagebase(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.exe")
            with open(path, "wb") as f:
                f.write(pe(0x10B, 0x10000000))
            self.assertEqual(dbcontext.exe_imagebase(path), 0x10000000)
            self.assertIsNone(dbcontext.exe_imagebase(os.path.join(d, "missing.exe")))
        self.assertIsNone(dbcontext.exe_imagebase(""))

    def test_pe_info(self):
        self.assertEqual(dbcontext.pe_info(pe(0x20B, 0x140000000)), {"base": 0x140000000, "magic": 0x20B, "machine": 0x8664, "dll": False})
        self.assertEqual(dbcontext.pe_info(pe(0x10B, 0x400000, machine=0x14C, chars=0x2102)), {"base": 0x400000, "magic": 0x10B, "machine": 0x14C, "dll": True})
        self.assertIsNone(dbcontext.pe_info(b"ZM" + bytes(200)))

    def test_kind_notice(self):
        self.assertIsNone(dbcontext.kind_notice("a.exe", dbcontext.pe_info(pe(0x20B, 0x140000000))))
        self.assertIsNone(dbcontext.kind_notice("a.exe", None))
        text = dbcontext.kind_notice("a.exe", dbcontext.pe_info(pe(0x10B, 0x400000, machine=0x14C)))
        self.assertIn("untested for this kind of file", text)
        self.assertIn("a.exe is a 32-bit file", text)
        text = dbcontext.kind_notice("b.dll", dbcontext.pe_info(pe(0x20B, 0x180000000, chars=0x2022)))
        self.assertIn("b.dll is a DLL", text)
        text = dbcontext.kind_notice("c.exe", dbcontext.pe_info(pe(0x20B, 0x140000000, machine=0xAA64)))
        self.assertIn("c.exe is not an x64 file", text)

    def test_file_md5(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "a.bin")
            with open(path, "wb") as f:
                f.write(b"abc")
            self.assertEqual(dbcontext.file_md5(path), "900150983cd24fb0d6963f7d28e17f72")
            self.assertIsNone(dbcontext.file_md5(os.path.join(d, "missing")))
            self.assertIsNone(dbcontext.file_md5(None))

    def test_exe_paths(self):
        pair = {"new_exe": "C:\\x\\New.exe", "new_work": "C:\\w\\n", "old_exe": "C:\\x\\Old.exe"}
        self.assertEqual(dbcontext.exe_paths(pair, "new"), [os.path.join("C:\\w\\n", "input.exe"), "C:\\x\\New.exe"])
        self.assertEqual(dbcontext.exe_paths(pair, "old"), ["C:\\x\\Old.exe"])

    def test_own_imagebase_checks_the_md5(self):
        with tempfile.TemporaryDirectory() as d:
            work, exe, other = os.path.join(d, "input.exe"), os.path.join(d, "old.exe"), os.path.join(d, "other.exe")
            for path, base in ((work, 0x140000000), (exe, 0x150000000), (other, 0x160000000)):
                with open(path, "wb") as f:
                    f.write(pe(0x20B, base) + path.encode("utf-8"))
            md5 = dbcontext.file_md5(exe)
            base, source = dbcontext.own_imagebase({"imagebase": 0x170000000}, md5, [work, exe])
            self.assertEqual(base, 0x170000000)
            self.assertIn("analysis", source)
            base, source = dbcontext.own_imagebase(None, md5, [work, exe])
            self.assertEqual(base, 0x150000000)
            self.assertIn("old.exe", source)
            base, source = dbcontext.own_imagebase({"imagebase": None}, dbcontext.file_md5(work), [work, exe])
            self.assertEqual(base, 0x140000000)
            self.assertIn("input.exe", source)
            self.assertEqual(dbcontext.own_imagebase(None, md5, [other, os.path.join(d, "gone.exe")]), (None, None))
            self.assertEqual(dbcontext.own_imagebase(None, "", [exe]), (None, None))
            self.assertEqual(dbcontext.checked_pe(md5.upper(), [work, exe]), (exe, dbcontext.pe_info(pe(0x20B, 0x150000000))))
            self.assertEqual(dbcontext.checked_pe(md5, [other]), (None, None))

    def test_rebased(self):
        text = dbcontext.rebased("old", 0x140010000, 0x140000000, "exediff's analysis of it")
        self.assertIn("old database was rebased from 0x140000000 to 0x140010000", text)
        self.assertIn("rebase it back", text)
        self.assertIn("exediff's analysis of it", text)
        self.assertIn("new database", dbcontext.rebased("new", 0xC30000, 0x400000, "the PE header of b.exe"))
        self.assertIsNone(dbcontext.rebased("old", 0x140000000, 0x140000000, "x"))
        self.assertIsNone(dbcontext.rebased("old", 0x140000000, None, None))

    def test_unchecked(self):
        text = dbcontext.unchecked("old", ["C:\\w\\input.exe", "C:\\x\\a.exe"])
        self.assertIn("old database", text)
        self.assertIn("could not be checked", text)
        self.assertIn("C:\\w\\input.exe or C:\\x\\a.exe", text)
        self.assertIn("md5 in pair.txt", text)
        self.assertIn("no exe", dbcontext.unchecked("new", []))


if __name__ == "__main__":
    unittest.main()
