import unittest

import _path  # noqa: F401
import cmts

NOTE = "exediff: changed vs Old.exe (91% similar)"


class CmtsTest(unittest.TestCase):
    def test_changed_note(self):
        self.assertEqual(cmts.changed_note("Old.exe", 91), NOTE)
        self.assertEqual(cmts.changed_note("Old.exe", None), "exediff: changed vs Old.exe (0% similar)")

    def test_strip_notes(self):
        self.assertEqual(cmts.strip_notes(None), "")
        self.assertEqual(cmts.strip_notes("owner text"), "owner text")
        self.assertEqual(cmts.strip_notes("owner\n"), "owner\n")
        self.assertEqual(cmts.strip_notes("owner text\nexediff: changed vs OLDER.exe (50% similar)"), "owner text")
        self.assertEqual(cmts.strip_notes("exediff: changed vs A.exe (50% similar)\nowner\nexediff: one of several identical functions"), "owner")
        self.assertEqual(cmts.strip_notes("exediff: changed vs A.exe (50% similar)"), "")
        self.assertEqual(cmts.strip_notes("see exediff: not a note\n exediff: indented"), "see exediff: not a note\n exediff: indented")

    def test_with_note(self):
        self.assertEqual(cmts.with_note("owner text\nexediff: changed vs OLDER.exe (50% similar)", NOTE), "owner text\n" + NOTE)
        self.assertEqual(cmts.with_note(None, NOTE), NOTE)
        self.assertEqual(cmts.with_note("exediff: changed vs OLDER.exe (50% similar)", NOTE), NOTE)
        self.assertEqual(cmts.with_note("owner", None), "owner")
        self.assertEqual(cmts.with_note("owner\n" + NOTE, None), "owner")

    def test_with_note_twice_does_not_stack(self):
        once = cmts.with_note("owner", NOTE)
        self.assertEqual(cmts.with_note(once, NOTE), once)
        self.assertEqual(once.count("exediff:"), 1)

    def test_decide(self):
        want = "owner\n" + NOTE
        self.assertEqual(cmts.decide(want, want, "owner"), "same")
        self.assertEqual(cmts.decide(None, want, "owner"), "set")
        self.assertEqual(cmts.decide("", want, "owner"), "set")
        self.assertEqual(cmts.decide("exediff: changed vs OLDER.exe (50% similar)", want, "owner"), "set")
        self.assertEqual(cmts.decide("owner", want, "owner"), "set")
        self.assertEqual(cmts.decide("owner\nexediff: changed vs OLDER.exe (50% similar)", want, "owner\nexediff: x"), "set")
        self.assertEqual(cmts.decide("someone else's text", want, "owner"), "keep")
        self.assertEqual(cmts.decide("", "", None), "same")


if __name__ == "__main__":
    unittest.main()
