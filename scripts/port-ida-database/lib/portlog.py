MISMATCH = "pseudo-differs"
LONG = 20
NOT_ANNOTATIONS = ("no-old-function",)
NO_ANNOTATIONS = "the old database has no annotations of yours: it only holds what IDA made itself"
NO_BASELINE_EMPTY = ("nothing found that could be told apart from IDA's own (without the analysis cache, instruction data, "
                     "prototypes and data items are not looked at)")
TOOL_MADE = ("changed notes", "likely notes", "folders")
MADE = "made by this script"
NOTHING_PORTED = "nothing was ported: see Needs review"
NOT_CHECKED = "not checked (run with -Verify to compare the pseudocode)"
SHOWN = 5

NOTES = {
    "not-ported-unpaired": "the functions are gone or have no pair in the new exe; port them by hand if you still need them",
    "not-ported-below": "pass a lower -MinSimilarity to port these, or port them by hand",
    "not-ported-likely": "pass -IncludeLikely to port these, or port them by hand",
    "gate-failed": "the code of these functions changed shape; their names and comments were ported, check the rest by hand",
    "data-not-ported": "data only reached from data or from changed functions is never ported; port them by hand if you need them",
    "insn-skipped": "these are in changed code; port them by hand where they still apply",
    "insn-not-ported": "port them by hand where they still apply",
    "proto-not-ported": "prototypes go to certain functions only; set them by hand where they still apply",
    "hexrays-not-ported": "Hex-Rays edits go to certain functions only; redo them by hand where they still apply",
    MISMATCH: "expected where the code really changed; check the functions that should be the same by hand",
}
DEFAULT_NOTE = "check them by hand"


def _addr(value):
    return "0x%X" % value if value is not None else "-"


class PortLog:
    def __init__(self):
        self.warnings = []
        self.counts = {}
        self.reviews = []
        self.compared = None

    def warn(self, msg, first=False):
        if first:
            self.warnings.insert(0, msg)
        else:
            self.warnings.append(msg)

    def ported(self, kind, n=1):
        self.counts[kind] = self.counts.get(kind, 0) + n

    def review(self, category, text, old=None, new=None):
        self.reviews.append({"category": category, "text": text, "old": old, "new": new})

    def verified(self, n):
        self.compared = n

    def to_json(self):
        items = [{"k": "warn", "text": w} for w in self.warnings]
        items += [{"k": "ported", "kind": k, "n": n} for k, n in self.counts.items()]
        items += [dict(r, k="review") for r in self.reviews]
        if self.compared is not None:
            items.append({"k": "verified", "n": self.compared})
        return items

    @classmethod
    def from_json(cls, items):
        log = cls()
        for item in items:
            k = item["k"]
            if k == "warn":
                log.warn(item["text"])
            elif k == "ported":
                log.ported(item["kind"], item["n"])
            elif k == "review":
                log.review(item["category"], item["text"], item.get("old"), item.get("new"))
            elif k == "verified":
                log.verified(item["n"])
        return log

    def totals(self):
        mismatches = sum(1 for r in self.reviews if r["category"] == MISMATCH)
        made = sum(n for k, n in self.counts.items() if k in TOOL_MADE)
        return {"ported": sum(self.counts.values()) - made, "made": made, "listed": len(self.reviews) - mismatches,
                "warnings": len(self.warnings), "mismatches": mismatches if self.compared is not None else None, "compared": self.compared}

    def render(self, found=True, baseline=True):
        t = self.totals()
        out = ["Summary", "  ported: %d" % t["ported"]]
        if t["ported"]:
            out += ["    %s: %d" % (k, n) for k, n in sorted(self.counts.items()) if n and k not in TOOL_MADE]
        elif found:
            out.append("  " + NOTHING_PORTED)
        else:
            out.append("  " + (NO_ANNOTATIONS if baseline else NO_BASELINE_EMPTY))
        if t["made"]:
            out.append("  %s: %d" % (MADE, t["made"]))
            out += ["    %s: %d" % (k, n) for k, n in sorted(self.counts.items()) if n and k in TOOL_MADE]
        out.append("  listed: %d" % t["listed"])
        out.append("  warnings: %d" % t["warnings"])
        if t["mismatches"] is None:
            out.append("  mismatches: " + NOT_CHECKED)
        else:
            out.append("  mismatches: %d of %d compared functions" % (t["mismatches"], t["compared"]))
        out += ["", "Warnings"]
        out += ["  " + w for w in self.warnings] or ["  none"]
        out += ["", "Needs review"]
        if not self.reviews:
            out.append("  none")
        groups = {}
        for r in self.reviews:
            groups.setdefault(r["category"], []).append(r)
        for category, entries in groups.items():
            out.append("  %s (%d)" % (category, len(entries)))
            if len(entries) > LONG:
                out.append("    note: %d entries; %s" % (len(entries), NOTES.get(category, DEFAULT_NOTE)))
            for r in entries:
                where = ""
                if r["old"] is not None or r["new"] is not None:
                    where = " [old %s, new %s]" % (_addr(r["old"]), _addr(r["new"]))
                out.append("    %s%s" % (r["text"], where))
        return "\n".join(out) + "\n"


def found(dump, log):
    if any(dump.get(key) for key in ("functions", "types", "data", "folders")):
        return True
    return any(r["category"] not in NOT_ANNOTATIONS for r in log.reviews)


def with_report(text, report):
    report = report.replace("\r\n", "\n").replace("\n", "\r\n")
    at = 0
    for line in text.splitlines(keepends=True):
        if line.rstrip("\r\n") == "Summary":
            return text[:at] + report
        at += len(line)
    return text + report


def result_text(log):
    ported = ["%s %d" % (k, n) for k, n in sorted(log.counts.items()) if n and k not in TOOL_MADE]
    made = ["%s %d" % (k, n) for k, n in sorted(log.counts.items()) if n and k in TOOL_MADE]
    text = "ported " + ", ".join(ported) if ported else "nothing ported"
    if made:
        text += "; %s: %s" % (MADE, ", ".join(made))
    return text


def one_line(text):
    return " ".join(text.split())


def summary_file(log, found_any, context, info=(), baseline=True):
    t = log.totals()
    lines = ["ported=%d" % t["ported"], "made=%d" % t["made"], "listed=%d" % t["listed"], "warnings=%d" % t["warnings"],
             "mismatches=%s" % ("" if t["mismatches"] is None else t["mismatches"]),
             "compared=%s" % ("" if t["compared"] is None else t["compared"]),
             "empty=%d" % (0 if found_any else 1), "baseline=%d" % (1 if baseline else 0)]
    shown = set(one_line(c) for c in context)
    lines += ["context=" + one_line(c) for c in context]
    lines += ["warning=" + w for w in [one_line(w) for w in log.warnings if one_line(w) not in shown][:SHOWN]]
    lines += ["info=" + one_line(c) for c in info]
    return "\n".join(lines) + "\n"
