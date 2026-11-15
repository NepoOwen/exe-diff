import unittest

import _path  # noqa: F401
import portlog

HEADER = "port-ida-database 2026-11-14 10:00\r\nold database: C:\\a\\Summary.i64\r\n\r\n"


def section(text, name):
    lines = text.split("\n")
    start = lines.index(name) + 1
    end = next((i for i in range(start, len(lines)) if lines[i] and not lines[i].startswith(" ")), len(lines))
    return [line for line in lines[start:end] if line]


class PortLogTest(unittest.TestCase):
    def make(self):
        log = portlog.PortLog()
        log.warn("something odd")
        log.ported("names", 3)
        log.ported("names")
        log.ported("comments", 2)
        log.review("names", "name already used: foo", 0x10, 0x110)
        log.review("types", "no declaration for bar")
        return log

    def test_json_round_trip(self):
        log = self.make()
        log.verified(3)
        log.review(portlog.MISMATCH, "f: line 1: 'a' != 'b'", 0x20, 0x120)
        items = log.to_json()
        again = portlog.PortLog.from_json(items)
        self.assertEqual(again.to_json(), items)
        self.assertEqual(again.render(), log.render())

    def test_render_sections_in_order(self):
        text = self.make().render()
        a, b, c = text.index("Summary"), text.index("Warnings"), text.index("Needs review")
        self.assertTrue(a < b < c)
        self.assertIn("names: 4", text)
        self.assertIn("comments: 2", text)
        self.assertIn("something odd", text)
        self.assertIn("name already used: foo", text)
        self.assertIn("0x10", text)
        self.assertIn("0x110", text)
        self.assertIn("names (1)", text)

    def test_summary_counts(self):
        summary = section(self.make().render(), "Summary")
        self.assertEqual(summary, ["  ported: 6", "    comments: 2", "    names: 4", "  listed: 2", "  warnings: 1",
                                   "  mismatches: not checked (run with -Verify to compare the pseudocode)"])

    def test_totals(self):
        log = self.make()
        self.assertEqual(log.totals(), {"ported": 6, "made": 0, "listed": 2, "warnings": 1, "mismatches": None, "compared": None})
        log.verified(5)
        log.review(portlog.MISMATCH, "f: line 2: 'x' != 'y'", 0x20, 0x120)
        self.assertEqual(log.totals(), {"ported": 6, "made": 0, "listed": 2, "warnings": 1, "mismatches": 1, "compared": 5})
        self.assertIn("  mismatches: 1 of 5 compared functions", log.render())

    def test_notes_and_folders_are_not_counted_as_ported(self):
        log = self.make()
        log.ported("changed notes", 2)
        log.ported("likely notes")
        log.ported("folders", 3)
        log.ported("functions in folders", 5)
        self.assertEqual(log.totals()["ported"], 11)
        self.assertEqual(log.totals()["made"], 6)
        summary = section(log.render(), "Summary")
        self.assertEqual(summary[:9], ["  ported: 11", "    comments: 2", "    functions in folders: 5", "    names: 4",
                                       "  made by this script: 6", "    changed notes: 2", "    folders: 3", "    likely notes: 1",
                                       "  listed: 2"])
        self.assertIn("made=6", portlog.summary_file(log, True, []).splitlines())

    def test_warn_first(self):
        log = self.make()
        log.warn("type libraries differ", first=True)
        self.assertEqual(section(log.render(), "Warnings"), ["  type libraries differ", "  something odd"])

    def test_empty_render(self):
        text = portlog.PortLog().render(found=False)
        self.assertIn("Summary", text)
        self.assertIn("Warnings", text)
        self.assertIn("Needs review", text)
        summary = section(text, "Summary")
        self.assertEqual(summary[0], "  ported: 0")
        self.assertIn("the old database has no annotations of yours", summary[1])
        self.assertEqual(section(text, "Needs review"), ["  none"])

    def test_empty_render_without_baseline(self):
        log = portlog.PortLog()
        log.warn("no analysis cache for a.exe")
        summary = section(log.render(found=False, baseline=False), "Summary")
        self.assertEqual(summary[0], "  ported: 0")
        self.assertIn("nothing found that could be told apart from IDA's own", summary[1])
        self.assertNotIn("no annotations of yours", log.render(found=False, baseline=False))
        self.assertIn("no annotations of yours", log.render(found=False, baseline=True))
        lines = portlog.summary_file(log, False, [], baseline=False).splitlines()
        self.assertIn("empty=1", lines)
        self.assertIn("baseline=0", lines)
        self.assertIn("baseline=1", portlog.summary_file(log, False, []).splitlines())

    def test_nothing_ported_but_found(self):
        log = portlog.PortLog()
        log.review("not-ported-below", "f: changed, 50% similar", 0x10, 0x20)
        summary = section(log.render(found=True), "Summary")
        self.assertEqual(summary[0], "  ported: 0")
        self.assertIn("see Needs review", summary[1])

    def test_long_category_gets_a_note(self):
        log = portlog.PortLog()
        for i in range(portlog.LONG + 1):
            log.review("data-not-ported", "d%d: only referenced from data" % i, 0x1000 + i, None)
        log.review("gate-failed", "f: mnemonic differs", 0x10, 0x20)
        lines = section(log.render(), "Needs review")
        self.assertEqual(lines[0], "  data-not-ported (%d)" % (portlog.LONG + 1))
        self.assertTrue(lines[1].startswith("    note: %d entries" % (portlog.LONG + 1)))
        self.assertIn("by hand", lines[1])
        self.assertTrue(lines[2].startswith("    d0: "))
        self.assertIn("[old 0x1000, new -]", lines[2])
        at = lines.index("  gate-failed (1)")
        self.assertFalse(lines[at + 1].startswith("    note:"))

    def test_mismatches_not_listed(self):
        log = self.make()
        log.verified(1)
        log.review(portlog.MISMATCH, "f: line 1: 'a' != 'b'", 0x20, 0x120)
        text = log.render()
        self.assertIn("  listed: 2", text)
        self.assertIn("  pseudo-differs (1)", text)

    def test_from_json_merges(self):
        log = portlog.PortLog.from_json(self.make().to_json())
        log.ported("names", 1)
        self.assertIn("names: 5", log.render())


class ReportTest(unittest.TestCase):
    def test_with_report_replaces_from_summary(self):
        first = HEADER + "Summary\r\n  ported: 0\r\n"
        text = portlog.with_report(first, "Summary\n  ported: 3\n")
        self.assertEqual(text, HEADER + "Summary\r\n  ported: 3\r\n")

    def test_with_report_appends_without_summary(self):
        self.assertEqual(portlog.with_report(HEADER, "Summary\n"), HEADER + "Summary\r\n")

    def test_found(self):
        empty = {"functions": {}, "types": [], "data": [], "folders": []}
        self.assertFalse(portlog.found(empty, portlog.PortLog()))
        self.assertTrue(portlog.found(dict(empty, types=[{"name": "a", "decl": "struct a;"}]), portlog.PortLog()))
        log = portlog.PortLog()
        log.review("not-ported-likely", "f", 1, 2)
        self.assertTrue(portlog.found(empty, log))
        log = portlog.PortLog()
        log.warn("no baseline")
        log.review("no-old-function", "sub_10 is not the start of a function in the old database", 0x10, 0x20)
        self.assertFalse(portlog.found(empty, log))

    def test_summary_file(self):
        log = portlog.PortLog()
        log.ported("names", 2)
        log.warn("type libraries differ: only in the old database: x", first=True)
        text = portlog.summary_file(log, True, ["type libraries differ: only in the old database: x"])
        lines = text.splitlines()
        self.assertIn("ported=2", lines)
        self.assertIn("listed=0", lines)
        self.assertIn("warnings=1", lines)
        self.assertIn("mismatches=", lines)
        self.assertIn("empty=0", lines)
        self.assertIn("context=type libraries differ: only in the old database: x", lines)
        self.assertIn("empty=1", portlog.summary_file(portlog.PortLog(), False, []).splitlines())

    def test_summary_file_one_line_each(self):
        text = portlog.summary_file(portlog.PortLog(), True, ["a\nb"])
        self.assertIn("context=a b", text.splitlines())

    def test_result_text_splits_made(self):
        log = portlog.PortLog()
        self.assertEqual(portlog.result_text(log), "nothing ported")
        log.ported("folders", 3)
        self.assertEqual(portlog.result_text(log), "nothing ported; made by this script: folders 3")
        log.ported("names", 4)
        log.ported("comments", 2)
        log.ported("changed notes")
        self.assertEqual(portlog.result_text(log), "ported comments 2, names 4; made by this script: changed notes 1, folders 3")

    def test_summary_file_warning_lines(self):
        log = portlog.PortLog()
        for i in range(7):
            log.warn("warning %d\nline two" % i)
        lines = portlog.summary_file(log, True, ["warning 0 line two"]).splitlines()
        self.assertEqual([x for x in lines if x.startswith("warning=")], ["warning=warning %d line two" % i for i in range(1, 6)])
        self.assertIn("warnings=7", lines)
        self.assertEqual(portlog.SHOWN, 5)

    def test_summary_file_information(self):
        text = portlog.summary_file(portlog.PortLog(), True, [], info=["the image base differs:\nold 0x1, new 0x2"])
        self.assertIn("info=the image base differs: old 0x1, new 0x2", text.splitlines())
        self.assertIn("warnings=0", text.splitlines())


if __name__ == "__main__":
    unittest.main()
