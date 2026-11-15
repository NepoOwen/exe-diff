import json
import os
import re
import sys
import traceback

import ida_bytes
import ida_dirtree
import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_lines
import ida_nalt
import ida_name
import ida_pro
import ida_segment
import ida_typeinf
import ida_ua
import idautils
import idc

LIB = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts", "port-ida-database", "lib"))
if LIB not in sys.path:
    sys.path.insert(0, LIB)

import dataplan  # noqa: E402
import feat_hexrays  # noqa: E402
import feat_protos  # noqa: E402
import hexplan  # noqa: E402
import portlog  # noqa: E402

lines = []
MODE = os.environ.get("EXEDFIX_MODE", "check")
PREFIX = MODE + "-" if MODE in ("again", "variant", "verify", "empty") else ""
# frame member types are not ported: Hex-Rays retyped the renamed stack variable's frame member in the saved old fixture.
# Ignores only a first difference that is the declaration of the same exedfix_stk_N variable on both sides (type or array
# size differs). It does not cover a use of the variable, another variable, or any later line: verify reports the first
# differing line only, so a real difference further down in such a function goes unseen by this check.
STACK_DECL = re.compile(r"line \d+: '[A-Za-z_][\w *]* \**(exedfix_stk_\d+)(?:\[\d+\])?;' != '[A-Za-z_][\w *]* \**\1(?:\[\d+\])?;'")


def check(name, ok, why=""):
    name = PREFIX + name
    lines.append("CHECK ok %s" % name if ok else "CHECK FAIL %s: %s" % (name, why))


def check_all(name, problems):
    check(name, not problems, "; ".join(problems[:6]) + (" (+%d more)" % (len(problems) - 6) if len(problems) > 6 else ""))


def nonuser_typed():
    n = 0
    for i in range(ida_funcs.get_func_qty()):
        ea = ida_funcs.getn_func(i).start_ea
        t = ida_typeinf.tinfo_t()
        if ida_nalt.get_tinfo(t, ea) and not ida_nalt.is_userti(ea):
            n += 1
    return n


def count_mode():
    with open(os.environ["EXEDFIX_COUNT"], "w", encoding="utf-8") as f:
        f.write("%d\n%d\n" % (ida_funcs.get_func_qty(), nonuser_typed()))


def load_fixture():
    with open(os.environ["EXEDFIX_FIXTURE"], "r", encoding="utf-8") as f:
        return json.load(f)


def read_log():
    path = os.environ.get("EXEDFIX_LOG", "")
    if not path or not os.path.exists(path):
        return ""
    with open(path, "r", encoding="utf-8") as f:
        return f.read()


def review_part(log):
    at = log.find("\nNeeds review")
    return log[at:] if at >= 0 else ""


def user_named(ea):
    return ida_bytes.has_user_name(ida_bytes.get_flags(ea))


def func_cmt(ea, rpt):
    f = ida_funcs.get_func(ea)
    return (ida_funcs.get_func_cmt(f, rpt) or "") if f is not None else None


def func_path(dt, ea):
    c = dt.find_entry(ida_dirtree.direntry_t(ea, False))
    return dt.get_abspath(c) if c.valid() else None


def listdir(dt, path):
    ff = ida_dirtree.dirtree_iterator_t()
    out = []
    ok = dt.findfirst(ff, path.rstrip("/") + "/*")
    while ok:
        out.append(dt.get_abspath(ff.cursor))
        ok = dt.findnext(ff)
    return sorted(out)


def tree(dt, path):
    out = []
    for p in listdir(dt, path):
        out.append(p)
        if dt.isdir(p):
            out += tree(dt, p)
    return out


def note_of(fixture, it):
    return "exediff: changed vs %s (%d%% similar)" % (fixture["old_exe_name"], it["similarity"])


def want_cmt(fixture, it):
    if it["kind"] != "changed":
        return it["cmt"] or ""
    return (it["cmt"] + "\n" if it["cmt"] else "") + note_of(fixture, it)


def check_ported(fixture, dt, items):
    names, cmts, notes, folders = [], [], [], []
    for it in items:
        ea, name = it["new_ea"], it["name"]
        have = ida_name.get_name(ea)
        if have != name or not user_named(ea):
            names.append("%s at 0x%X is %s" % (name, ea, have))
        cmt, rpt = func_cmt(ea, False), func_cmt(ea, True)
        if cmt is None:
            cmts.append("0x%X is not a function" % ea)
            continue
        want = want_cmt(fixture, it)
        if it["kind"] == "changed":
            if cmt != want or cmt.count("exediff:") != 1 or "OLDER.exe" in cmt:
                notes.append("%s comment %r, want %r" % (name, cmt, want))
        elif cmt != want:
            cmts.append("%s comment %r, want %r" % (name, cmt, want))
        if rpt != (it["rptcmt"] or ""):
            cmts.append("%s repeatable comment %r, want %r" % (name, rpt, it["rptcmt"]))
        if it["folder"]:
            path = func_path(dt, ea)
            if path != it["folder"] + "/" + name:
                folders.append("%s is at %s" % (name, path))
    check_all("names", names)
    check_all("comments", cmts)
    check_all("changed-note", notes)
    return folders


def check_folders(dt, folders):
    if not dt.isdir("/ExedFix"):
        folders.append("no /ExedFix")
    if not dt.isdir("/ExedFix/Sub"):
        folders.append("no /ExedFix/Sub")
    elif dt.get_dir_size(dt.resolve_path("/ExedFix/Sub").idx) != 0:
        folders.append("/ExedFix/Sub is not empty: %s" % listdir(dt, "/ExedFix/Sub"))
    same = listdir(dt, "/ExedFix/Same") if dt.isdir("/ExedFix/Same") else None
    if same is None or len(same) != 5:
        folders.append("/ExedFix/Same holds %s" % same)
    check_all("folders", folders)


def check_not_ported(items, log):
    bad = []
    for it in items:
        ea, name = it["new_ea"], it["name"]
        if user_named(ea) or ida_name.get_name(ea) == name:
            bad.append("0x%X is named %s" % (ea, ida_name.get_name(ea)))
        if ida_name.get_name_ea(ida_idaapi.BADADDR, name) != ida_idaapi.BADADDR:
            bad.append("%s is used at 0x%X" % (name, ida_name.get_name_ea(ida_idaapi.BADADDR, name)))
    check_all("not-ported", bad)
    reviews = review_part(log)
    missing = [it["name"] for it in items if it["name"] not in reviews]
    check_all("not-ported-listed", ["%s is not under Needs review" % n for n in missing] + ([] if log else ["no log"]))


def check_no_suffix(items):
    bad = []
    for it in items:
        for suffix in ("_0", "_1", "_2"):
            if ida_name.get_name_ea(ida_idaapi.BADADDR, it["name"] + suffix) != ida_idaapi.BADADDR:
                bad.append(it["name"] + suffix)
    check_all("no-suffix", bad)


def review_entries(log):
    out = {}
    category = None
    for line in review_part(log).splitlines():
        if line.startswith("    note: "):
            continue
        if line.startswith("    ") and category:
            out[category].append(line.strip())
        elif line.startswith("  ") and line.strip() != "none":
            category = line.strip().rsplit(" (", 1)[0]
            out.setdefault(category, [])
    return out


def data_ref_funcs(fixture):
    return {r[0] for d in fixture.get("data", []) if d["role"] != "changed" for r in d["refs"]}


def check_owner_only(fixture, log):
    with open(os.environ["EXEDFIX_DUMP"], "r", encoding="utf-8") as f:
        dump = json.load(f)
    bad = []
    refs = data_ref_funcs(fixture)
    for key, entry in dump["functions"].items():
        name = entry.get("name")
        if not name and set(entry) <= {"shape"} and int(key) in refs:
            continue
        if not name or not name.startswith("ExedFix_"):
            bad.append("0x%X has name %r" % (int(key), name))
        for kind in ("cmt", "rptcmt"):
            if "Alternative name is" in (entry.get(kind) or ""):
                bad.append("0x%X %s %r" % (int(key), kind, entry[kind][:40]))
    check_all("dump-owner-only", bad if dump["functions"] else ["the dump has no functions"])
    bad = []
    for category, entries in review_entries(log).items():
        if category.startswith("not-ported-"):
            bad += ["%s: %s" % (category, e[:60]) for e in entries if not e.startswith("ExedFix_")]
    check_all("reviews-owner-only", bad if log else ["no log"])


def local_types():
    til = ida_typeinf.get_idati()
    out = {}
    for o in range(1, ida_typeinf.get_ordinal_limit(til)):
        n = ida_typeinf.get_numbered_type_name(til, o)
        if n:
            out[n] = o
    return out


def named_type(name):
    t = ida_typeinf.tinfo_t()
    return t if t.get_named_type(ida_typeinf.get_idati(), name) and not t.is_forward_decl() else None


def members(t):
    udt = ida_typeinf.udt_type_data_t()
    if not t.get_udt_details(udt):
        return None
    return [(m.name, m.offset // 8, str(m.type)) for m in udt]


def check_struct(bad, name, want):
    t = named_type(name)
    if t is None or not t.is_struct():
        bad.append("no struct %s" % name)
    elif members(t) != want:
        bad.append("%s members %s, want %s" % (name, members(t), want))


def check_types(log):
    bad = []
    check_struct(bad, "ExedFixStruct", [("a", 0, "int"), ("b", 4, "char[8]"), ("e", 12, "ExedFixEnum")])
    check_struct(bad, "ExedFixCycA", [("b", 0, "ExedFixCycB *"), ("x", 8, "int")])
    check_struct(bad, "ExedFixCycB", [("a", 0, "ExedFixCycA *"), ("y", 8, "int")])
    check_struct(bad, "ExedFixParent", [("k", 0, "int"), ("c", 8, "ExedFixChild")])
    check_struct(bad, "ExedFixChild", [("p", 0, "ExedFixParent *"), ("z", 8, "int")])
    for name, size in (("ExedFixParent", 24), ("ExedFixChild", 16)):
        t = named_type(name)
        if t is not None and t.get_size() != size:
            bad.append("%s is %d bytes, want %d" % (name, t.get_size(), size))
    e = named_type("ExedFixEnum")
    if e is None or not e.is_enum():
        bad.append("no enum ExedFixEnum")
    else:
        ed = ida_typeinf.enum_type_data_t()
        e.get_enum_details(ed)
        values = sorted((m.name, m.value) for m in ed)
        if values != [("EXED_A", 1), ("EXED_B", 2)]:
            bad.append("ExedFixEnum values %s" % values)
    p = named_type("PExedFixStruct")
    if p is None or not p.is_typedef() or not p.is_ptr() or str(p.get_pointed_object()) != "ExedFixStruct":
        bad.append("PExedFixStruct is %s" % (p.dstr() if p is not None else None))
    check_all("types", bad)
    entries = review_entries(log)
    bad = ["%s: %s" % (c, e[:60]) for c in ("type-differs", "type-failed") for e in entries.get(c, [])]
    check_all("type-reviews", bad if log else ["no log"])
    names = local_types()
    check_all("type-no-suffix", sorted(n for n in names if (n.startswith("ExedFix") or n.startswith("PExedFix")) and n.rsplit("_", 1)[-1].isdigit()))
    fwd = []
    for n in sorted(names):
        t = ida_typeinf.tinfo_t()
        if (n.startswith("ExedFix") or n.startswith("PExedFix")) and t.get_named_type(ida_typeinf.get_idati(), n) and t.is_forward_decl():
            fwd.append("%s is an empty forward declaration" % n)
    check_all("type-no-forward", fwd)


def check_dump_types(fixture):
    with open(os.environ["EXEDFIX_DUMP"], "r", encoding="utf-8") as f:
        dump = json.load(f)
    names = [t.get("name") for t in dump.get("types", [])]
    bad = []
    want = fixture["types"] + fixture.get("decompiler_types", [])
    if sorted(names) != sorted(want):
        bad.append("the dump has the types %s, want only %s" % (names[:8] + (["..."] if len(names) > 8 else []), want))
    elif not (names.index("ExedFixEnum") < names.index("ExedFixStruct") < names.index("PExedFixStruct")
              and names.index("ExedFixChild") < names.index("ExedFixParent")):
        bad.append("the dump order %s puts a type before one it uses" % names)
    check_all("dump-types", bad)


def extra_lines(ea, base):
    out = []
    while True:
        line = ida_lines.get_extra_cmt(ea, base + len(out))
        if line is None:
            return out
        out.append(line)


def op_state(ea, n):
    fl = ida_bytes.get_flags(ea)
    if not ida_bytes.is_defarg(fl, n):
        return None
    if ida_bytes.is_enum(fl, n):
        tid, _serial = ida_bytes.get_enum_id(ea, n)
        return "enum:%s" % ida_typeinf.get_tid_name(tid)
    if ida_bytes.is_char(fl, n):
        return "char"
    if ida_bytes.is_numop(fl, n):
        return {16: "hex", 10: "dec", 8: "oct", 2: "bin"}.get(ida_bytes.get_radix(fl, n), "num")
    return "other"


def insn_state(ea):
    return {"cmt": ida_bytes.get_cmt(ea, False), "rpt": ida_bytes.get_cmt(ea, True), "ant": extra_lines(ea, ida_lines.E_PREV),
            "post": extra_lines(ea, ida_lines.E_NEXT), "ops": [op_state(ea, n) for n in range(3)]}


def has_item(ea, e):
    kind = e["kind"]
    if kind in ("cmt", "rpt"):
        return (ida_bytes.get_cmt(ea, kind == "rpt") or "") == e["text"]
    if kind in ("ant", "post"):
        return extra_lines(ea, ida_lines.E_PREV if kind == "ant" else ida_lines.E_NEXT) == e["lines"]
    return op_state(ea, e["opn"]) == ("enum:" + e["arg"] if e["fmt"] == "enum" else e["fmt"])


def entry_ea(e):
    return e["new_start"] + e["new_off"]


def listed(entries, e):
    return any("old 0x%X" % e["old_ea"] in x for x in entries)


def check_insn(fixture, log):
    entries = fixture.get("insn", [])
    reviews = review_entries(log)
    gate_failed, skipped = reviews.get("gate-failed", []), reviews.get("insn-skipped", [])
    bad = []
    for e in entries:
        if e["expect"] == "present" and not has_item(entry_ea(e), e):
            bad.append("%s %s +0x%X at 0x%X: %s" % (e["func"], e["kind"], e["off"], entry_ea(e), insn_state(entry_ea(e))))
    check_all("insn-items", bad if entries else ["the fixture has no instruction items"])
    e = next((e for e in entries if e["role"] == "enum"), None)
    text = ida_lines.tag_remove(ida_ua.print_operand(entry_ea(e), e["opn"]) or "") if e else ""
    check("insn-enum", "EXED_A" in text or "EXED_B" in text, "the enum operand prints %r" % text)
    bad = []
    run = next((e for e in entries if e["role"] == "run"), None)
    region = next((e for e in entries if e["role"] == "region"), None)
    if run is None or region is None:
        bad.append("the fixture has no changed-function comments")
    else:
        if not has_item(entry_ea(run), run):
            bad.append("the comment in the identical run is not at 0x%X: %s" % (entry_ea(run), insn_state(entry_ea(run))))
        landed = [ea for ea in idautils.FuncItems(region["new_start"]) if region["text"] in (ida_bytes.get_cmt(ea, False) or "")]
        if landed:
            bad.append("the comment in the changed region landed at %s" % ["0x%X" % ea for ea in landed])
        if not listed(skipped, region):
            bad.append("the comment in the changed region (old 0x%X) is not listed under insn-skipped" % region["old_ea"])
    check_all("insn-changed", bad)
    bad = []
    runfmt = next((e for e in entries if e["role"] == "runfmt"), None)
    if runfmt is None:
        bad.append("the fixture has no operand format in a changed function")
    else:
        if has_item(entry_ea(runfmt), runfmt):
            bad.append("the hex format landed at 0x%X in a changed function: %s" % (entry_ea(runfmt), insn_state(entry_ea(runfmt))))
        if not listed(skipped, runfmt):
            bad.append("the operand format in the changed function (old 0x%X) is not listed under insn-skipped" % runfmt["old_ea"])
    check_all("insn-changed-format", bad)
    calls =next((e for e in entries if e["role"] == "calls"), None)
    if calls is None:
        check("insn-gate-calls", True)
    else:
        check("insn-gate-calls", has_item(entry_ea(calls), calls) or any(calls["func"] in x for x in gate_failed),
              "%s is neither ported nor listed with gate-failed" % calls["func"])
    bad = ["insn-differs: " + x[:80] for x in reviews.get("insn-differs", [])]
    certain = {e["func"] for e in entries if e["role"] in ("cmts", "fmt", "enum", "gate")}
    bad += ["gate-failed: " + x[:80] for x in gate_failed if any(x.startswith(f + ":") for f in certain)]
    allowed = [e for e in entries if e["role"] in ("region", "calls", "runfmt")]
    bad += ["insn-skipped: " + x[:80] for x in skipped if not any(("old 0x%X" % e["old_ea"]) in x for e in allowed)]
    check_all("insn-reviews", bad if log else ["no log"])


def check_dump_insn(fixture):
    with open(os.environ["EXEDFIX_DUMP"], "r", encoding="utf-8") as f:
        dump = json.load(f)
    entries = fixture.get("insn", [])
    want = sorted((e["old_start"], e["off"], e["kind"], e.get("opn")) for e in entries)
    have, bad = [], []
    refs = data_ref_funcs(fixture)
    for key, entry in dump["functions"].items():
        for it in entry.get("insn", []):
            have.append((int(key), it["off"], it["kind"], it.get("opn")))
        if entry.get("insn") and not all(k in entry.get("shape", {}) for k in ("frsize", "argsize", "insns")):
            bad.append("0x%X has instruction items but no shape" % int(key))
        if "shape" in entry and not (entry.get("name") or "").startswith("ExedFix_") and int(key) not in refs:
            bad.append("0x%X has a shape but is not a fixture function" % int(key))
    if sorted(have) != want:
        bad.append("the dump has the instruction items %s, want %s" % (sorted(have)[:8], want[:8]))
    e = next((e for e in entries if e["role"] == "enum"), None)
    item = next((it for it in dump["functions"].get(str(e["old_start"]), {}).get("insn", []) if it["kind"] == "opfmt"), None) if e else None
    if item is None or (item.get("ida") or {}).get("fmt") != "hex":
        bad.append("the enum item %s does not carry IDA's own hex format as ida" % item)
    check_all("dump-insn", bad)


def printed_type(ea):
    t = ida_typeinf.tinfo_t()
    if not ida_nalt.get_tinfo(t, ea):
        return None
    return ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, t, "", "")


def follow(ref):
    t = sorted({x for x in idautils.DataRefsFrom(ref[2] + ref[1]) if ida_segment.getseg(x) is not None})
    return t[0] if len(t) == 1 else None


def data_state(ea):
    if ea is None:
        return None
    return {"name": ida_name.get_name(ea), "user": user_named(ea), "cmt": ida_bytes.get_cmt(ea, False), "type": printed_type(ea),
            "userti": ida_nalt.is_userti(ea), "size": ida_bytes.get_item_size(ea)}


def data_problems(d, ea, name=None):
    s = data_state(ea)
    bad = []
    if s["name"] != (name or d["name"]) or not s["user"]:
        bad.append("name %s" % s["name"])
    if s["cmt"] != d["cmt"]:
        bad.append("comment %r" % s["cmt"])
    if s["type"] != d["type"] or not s["userti"]:
        bad.append("type %s (user %s)" % (s["type"], s["userti"]))
    if s["size"] != d["size"]:
        bad.append("size %d" % s["size"])
    return ["%s at 0x%X: %s" % (d["name"], ea, ", ".join(bad))] if bad else []


def check_protos(fixture, log):
    protos = fixture.get("protos", [])
    bad = []
    for p in protos:
        have = printed_type(p["new_ea"])
        if have != p["proto"] or not ida_nalt.is_userti(p["new_ea"]):
            bad.append("%s at 0x%X has the prototype %s (user %s), want %s" % (p["func"], p["new_ea"], have, ida_nalt.is_userti(p["new_ea"]), p["proto"]))
    check_all("protos", bad if protos else ["the fixture has no prototypes"])


def check_data(fixture, log):
    entries = fixture.get("data", [])
    reviews = review_entries(log)
    bad = [] if entries else ["the fixture has no data items"]
    for d in entries:
        if d["role"] == "changed":
            continue
        ea = follow(d["refs"][0])
        if ea is None or ea != d["new_ea"]:
            bad.append("%s: the reference at 0x%X+0x%X leads to %s, the fixture expects 0x%X" % (d["name"], d["refs"][0][2], d["refs"][0][1],
                                                                                            "0x%X" % ea if ea is not None else None, d["new_ea"]))
            continue
        bad += data_problems(d, ea)
    check_all("data-items", bad)
    bad = []
    changed = next((d for d in entries if d["role"] == "changed"), None)
    if changed is None:
        bad.append("the fixture has no changed-only data item")
    else:
        at = ida_name.get_name_ea(ida_idaapi.BADADDR, changed["name"])
        if at != ida_idaapi.BADADDR:
            bad.append("%s is used at 0x%X" % (changed["name"], at))
        if not any(x.startswith(changed["name"] + ":") for x in reviews.get("data-not-ported", [])):
            bad.append("%s is not listed under data-not-ported" % changed["name"])
    check_all("data-changed-only", bad)
    extra = fixture.get("extra_data", [])
    bad = [] if len(extra) == 2 else ["the fixture has %d extra data items, want an undefined byte and data inside a function" % len(extra)]
    for d in extra:
        at = ida_name.get_name_ea(ida_idaapi.BADADDR, d["name"])
        if at != ida_idaapi.BADADDR:
            bad.append("%s is used at 0x%X" % (d["name"], at))
        if not listed_as(reviews, "data-not-ported", d["name"], "not ported (name, comment): " + d["why"]):
            bad.append("%s is not listed under data-not-ported with %r" % (d["name"], d["why"]))
    check_all("data-extra-listed", bad)
    bad = []
    allowed = [d["name"] for d in extra] + ([changed["name"]] if changed else [])
    for c in ("proto-not-ported", "proto-skipped", "proto-failed", "proto-differs", "data-skipped", "data-differs", "data-not-ported"):
        bad += ["%s: %s" % (c, x[:80]) for x in reviews.get(c, []) if not (c == "data-not-ported" and any(x.startswith(n + ":") for n in allowed))]
    check_all("proto-data-reviews", bad if log else ["no log"])


def check_dump_protos_data(fixture):
    with open(os.environ["EXEDFIX_DUMP"], "r", encoding="utf-8") as f:
        dump = json.load(f)
    want = sorted((p["old_ea"], p["proto"]) for p in fixture.get("protos", []))
    have = sorted((int(k), e["proto"]) for k, e in dump["functions"].items() if e.get("proto"))
    bad = [] if have == want else ["the dump has the prototypes %s, want %s" % (["0x%X %s" % x for x in have[:6]], ["0x%X %s" % x for x in want])]
    check_all("dump-protos", bad)
    want = sorted((d["old_ea"], d["name"], d["cmt"], d["type"]) for d in fixture.get("data", []) if d["role"] != "changed")
    have = sorted((d.get("ea"), d.get("name"), d.get("cmt"), d.get("type")) for d in dump.get("data", []))
    bad = [] if have == want else ["the dump has the data items %s, want %s" % (have[:6], want)]
    for d in dump.get("data", []):
        refs = d.get("refs") or []
        if not refs:
            bad.append("%s has no references" % d.get("name"))
        if len(refs) > dataplan.REF_CAP or refs != sorted(refs):
            bad.append("%s has %d references, unsorted or over the cap of %d" % (d.get("name"), len(refs), dataplan.REF_CAP))
    check_all("dump-data", bad)
    with open(os.environ["EXEDFIX_DUMP"], "r", encoding="utf-8") as f:
        raw = f.read()
    bad = [] if "\n" not in raw.strip() and ", " not in raw[:200] else ["the dump is not compact JSON: it starts %r" % raw[:80]]
    bad += ["0x%X carries union_types in its Hex-Rays data" % int(k) for k, e in dump["functions"].items() if "union_types" in (e.get("hexrays") or {})]
    bad += ["0x%X carries labels in its Hex-Rays data" % int(k) for k, e in dump["functions"].items() if "labels" in (e.get("hexrays") or {})]
    if not isinstance(dump.get("union_types", {}), dict) or not isinstance(dump.get("notices", []), list):
        bad.append("the dump has union_types %r and notices %r" % (type(dump.get("union_types")), type(dump.get("notices"))))
    check_all("dump-compact", bad)


def hx_pairs(m, kind):
    out = []
    if m is None:
        return out
    p = getattr(ida_hexrays, "user_%s_begin" % kind)(m)
    while p != getattr(ida_hexrays, "user_%s_end" % kind)(m):
        out.append((getattr(ida_hexrays, "user_%s_first" % kind)(p), getattr(ida_hexrays, "user_%s_second" % kind)(p)))
        p = getattr(ida_hexrays, "user_%s_next" % kind)(p)
    return out


def hx_lvars(ea):
    lv = ida_hexrays.lvar_uservec_t()
    if not ida_hexrays.restore_user_lvar_settings(lv, ea):
        return None
    items = []
    for s in lv.lvvec:
        loc = s.ll.location
        items.append({"loc": ["stk", loc.stkoff()] if loc.is_stkoff() else ["reg", loc.reg1()] if loc.is_reg1() else None,
                      "defoff": None if s.ll.defea == ida_idaapi.BADADDR else s.ll.defea - ea, "name": s.name or None,
                      "type": None if s.type.empty() else ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, s.type, "", ""), "cmt": s.cmt or None,
                      "size": int(s.size)})
    return {"delta": lv.stkoff_delta, "flags": lv.ulv_flags, "items": sorted(items, key=lambda x: json.dumps(x))}


def hx_state(ea):
    if not ida_hexrays.init_hexrays_plugin():
        return "no Hex-Rays"
    return {"cmts": sorted([k.ea - ea, int(k.itp), str(v)] for k, v in hx_pairs(ida_hexrays.restore_user_cmts(ea), "cmts")),
            "numforms": sorted([k.ea - ea, k.opnum, v.flags] for k, v in hx_pairs(ida_hexrays.restore_user_numforms(ea), "numforms")),
            "unions": sorted([k - ea, list(v)] for k, v in hx_pairs(ida_hexrays.restore_user_unions(ea), "unions")),
            "labels": sorted([k, str(v)] for k, v in hx_pairs(ida_hexrays.restore_user_labels(ea, None), "labels")),
            "iflags": sorted([k.ea - ea, k.op, v] for k, v in hx_pairs(ida_hexrays.restore_user_iflags(ea), "iflags")),
            "lvars": hx_lvars(ea)}


def hx_empty(state):
    return isinstance(state, dict) and not any(state[k] for k in state)


def lvar_problems(h, state, want_items):
    have = (state["lvars"] or {}).get("items", []) if isinstance(state, dict) else []
    bad = []
    for it in want_items:
        got = next((x for x in have if x["loc"] == it["loc"] and x["defoff"] == it["defoff"]), None)
        if got is None or any(got[k] != it[k] for k in ("name", "type", "cmt")) or got.get("size", -1) != -1:
            bad.append("%s: the Hex-Rays variable %s is %s" % (h["func"], it, got))
    return bad


def check_hexrays(fixture, log):
    entries = fixture.get("hexrays", [])
    by_cat = review_entries(log)
    bad = [] if entries else ["the fixture has no Hex-Rays data"]
    for h in entries:
        if h["expect"] != "ported":
            continue
        state = hx_state(h["new_ea"])
        if not isinstance(state, dict):
            bad.append(state)
            continue
        missing = [c for c in h["cmts"] if c not in state["cmts"]]
        if missing:
            bad.append("%s: the Hex-Rays comments %s are not at 0x%X+off, it has %s" % (h["func"], missing, h["new_ea"], state["cmts"]))
        bad += lvar_problems(h, state, h["lvars"])
        lv = state["lvars"]
        if h["lvars"] and lv is not None and (lv["delta"], lv["flags"]) != (h["delta"], h["ulv_flags"]):
            bad.append("%s: the Hex-Rays variable settings have delta %s flags %s, want %s %s" % (h["func"], lv["delta"], lv["flags"], h["delta"], h["ulv_flags"]))
    check_all("hexrays-ported", bad)
    bad = []
    for h in entries:
        if h["expect"] != "absent":
            continue
        state = hx_state(h["new_ea"])
        if not hx_empty(state):
            bad.append("%s at 0x%X has Hex-Rays data %s" % (h["func"], h["new_ea"], state))
        if not listed_as(by_cat, "hexrays-not-ported", h["func"]):
            bad.append("%s is not listed under hexrays-not-ported" % h["func"])
    check_all("hexrays-changed-none", bad if any(h["expect"] == "absent" for h in entries) else ["the fixture has no changed function with Hex-Rays data"])
    h = next((h for h in entries if h["role"] == "label"), None)
    bad = [] if h else ["the fixture has no Hex-Rays label (no certain function with a goto label was found)"]
    if h:
        state = hx_state(h["new_ea"])
        if not isinstance(state, dict) or state["labels"]:
            bad.append("%s at 0x%X has the Hex-Rays labels %s" % (h["func"], h["new_ea"], state if not isinstance(state, dict) else state["labels"]))
        if not listed_as(by_cat, "hexrays-not-ported", h["func"], h["labels"][0][1]) or not listed_as(by_cat, "hexrays-not-ported", h["func"], "label number"):
            bad.append("%s is not listed under hexrays-not-ported with its label %s and the reason" % (h["func"], h["labels"][0][1]))
    check_all("hexrays-labels-listed", bad)
    absent = [h["func"] for h in entries if h["expect"] in ("absent", "listed")]
    bad = ["%s: %s" % (c, x[:80]) for c in ("hexrays-skipped", "hexrays-differs", "hexrays-failed") for x in by_cat.get(c, [])]
    bad += ["hexrays-not-ported: " + x[:80] for x in by_cat.get("hexrays-not-ported", []) if not any(x.startswith(f + ":") for f in absent)]
    bad += ["warning: " + w for w in warnings_of(log) if "Hex-Rays" in w]
    check_all("hexrays-reviews", bad if log else ["no log"])


def warnings_of(log):
    at, end = log.find("\nWarnings"), log.find("\nNeeds review")
    if at < 0:
        return []
    return [x.strip() for x in log[at:end if end > at else None].splitlines()[2:] if x.strip() and x.strip() != "none"]


def summary_part(log):
    at, end = log.find("\nSummary"), log.find("\nWarnings")
    return log[at:end] if 0 <= at < end else ""


def summary_value(log, key):
    m = re.search(r"(?m)^  %s: (.*)$" % key, summary_part(log))
    return m.group(1).strip() if m else None


TOOL_MADE = ("changed notes", "likely notes", "folders")


def summary_kinds(log, key):
    out, inside = {}, False
    for line in summary_part(log).splitlines():
        if line.startswith("  ") and not line.startswith("    "):
            inside = line.startswith("  %s: " % key)
        elif inside:
            m = re.match(r"^    ([^:]+): (\d+)$", line)
            if m:
                out[m.group(1)] = int(m.group(2))
    return out


def check_report(log, mismatches):
    bad = [] if log else ["no log"]
    kinds = summary_kinds(log, "ported")
    ported = summary_value(log, "ported")
    if ported != str(sum(kinds.values())) or not kinds:
        bad.append("ported is %r, the kinds below it add up to %d" % (ported, sum(kinds.values())))
    made_by = sorted(k for k in kinds if k in TOOL_MADE)
    if made_by:
        bad.append("ported counts %s, which the script makes itself" % made_by)
    made = summary_kinds(log, "made by this script")
    if str(sum(made.values())) != (summary_value(log, "made by this script") or "0") or any(k not in TOOL_MADE for k in made):
        bad.append("made by this script is %r with %s below it" % (summary_value(log, "made by this script"), made))
    entries = review_entries(log)
    listed = sum(len(v) for k, v in entries.items() if k != "pseudo-differs")
    if summary_value(log, "listed") != str(listed):
        bad.append("listed is %r, Needs review has %d entries" % (summary_value(log, "listed"), listed))
    if summary_value(log, "warnings") != str(len(warnings_of(log))):
        bad.append("warnings is %r, Warnings has %d" % (summary_value(log, "warnings"), len(warnings_of(log))))
    have = summary_value(log, "mismatches") or ""
    if mismatches is None and not have.startswith("not checked"):
        bad.append("mismatches is %r, want 'not checked'" % have)
    if mismatches is not None:
        m = re.match(r"(\d+) of (\d+) ", have)
        if not m or int(m.group(1)) != len(entries.get("pseudo-differs", [])) or int(m.group(2)) != mismatches:
            bad.append("mismatches is %r, want %d pseudo-differs entries of %d compared" % (have, len(entries.get("pseudo-differs", [])), mismatches))
    check_all("report-summary", bad)


def load_dump():
    with open(os.environ["EXEDFIX_DUMP"], "r", encoding="utf-8") as f:
        return json.load(f)


def pseudo_wanted(dump):
    return sorted(int(k) for k, e in dump["functions"].items() if e.get("hexrays") or e.get("proto"))


def check_dump_pseudo(verify):
    dump = load_dump()
    have = sorted(int(k) for k, e in dump["functions"].items() if "pseudo" in e)
    want = pseudo_wanted(dump) if verify else []
    bad = [] if have == want else ["the dump has pseudocode for %s, want %s" % (["0x%X" % x for x in have], ["0x%X" % x for x in want])]
    for k in have:
        text = dump["functions"][str(k)]["pseudo"]
        if not isinstance(text, str) or "{" not in text:
            bad.append("0x%X has the pseudocode %r" % (k, text if not isinstance(text, str) else text[:60]))
    if verify and not want:
        bad.append("the dump has no function with Hex-Rays data or a prototype")
    check_all("dump-pseudo", bad)
    return len(want)


def verify_mode():
    count_checks()
    fixture = load_fixture()
    log = read_log()
    compared = check_dump_pseudo(True)
    by_cat = review_entries(log)
    bad = [] if log else ["no log"]
    for h in fixture.get("hexrays", []):
        if h["expect"] != "ported":
            continue
        for cat in ("pseudo-differs", "pseudo-not-checked"):
            bad += ["%s: %s" % (cat, x[:120]) for x in by_cat.get(cat, []) if x.startswith(h["func"] + ":") and not STACK_DECL.search(x)]
    check_all("pseudo-same", bad)
    check_report(log, compared)


def empty_mode():
    count_checks()
    log = read_log()
    dump = load_dump()
    bad = [] if log else ["no log"]
    if summary_value(log, "ported") != "0":
        bad.append("ported is %r" % summary_value(log, "ported"))
    if "no annotations of yours" not in summary_part(log):
        bad.append("the Summary does not say that the old database has no annotations of yours: %r" % summary_part(log)[:300])
    listed = [k for k in review_entries(log) if k != "no-old-function"]
    if listed:
        bad.append("Needs review lists %s" % sorted(listed))
    for key in ("functions", "types", "data", "folders"):
        if dump.get(key):
            bad.append("the dump has %d %s" % (len(dump[key]), key))
    check_all("report", bad)


def count_checks(nonuser=True):
    with open(os.environ["EXEDFIX_COUNT"], "r", encoding="utf-8") as f:
        want, want_nonuser = [int(x) for x in f.read().split()]
    have = ida_funcs.get_func_qty()
    check("output-opens", have == want and have > 0, "%d functions, the cached analysed database has %d" % (have, want))
    if nonuser:
        have_nonuser = nonuser_typed()
        check("nonuser-types", have_nonuser == want_nonuser, "%d functions have a type that is not a user type, the cached analysed database has %d" % (
            have_nonuser, want_nonuser))


def check_dump_hexrays(fixture):
    with open(os.environ["EXEDFIX_DUMP"], "r", encoding="utf-8") as f:
        dump = json.load(f)
    want = sorted(h["old_ea"] for h in fixture.get("hexrays", []) if h["expect"] == "ported")
    have = sorted(int(k) for k, e in dump["functions"].items() if e.get("hexrays"))
    bad = [] if have == want else ["the dump has Hex-Rays data for %s, want %s" % (["0x%X" % x for x in have], ["0x%X" % x for x in want])]
    for k in have:
        if "shape" not in dump["functions"][str(k)]:
            bad.append("0x%X has Hex-Rays data but no shape" % k)
    check_all("dump-hexrays", bad)


def variant_hexrays(fixture, by_cat):
    by_role = {h["role"]: h for h in fixture.get("hexrays", [])}
    v = fixture["variant"].get("hexrays", {})
    h = by_role.get("gate")
    bad = [] if h else ["the fixture has no Hex-Rays data on the gate function"]
    if h:
        state = hx_state(h["new_ea"])
        if not hx_empty(state):
            bad.append("%s at 0x%X has Hex-Rays data %s although its gate failed" % (h["func"], h["new_ea"], state))
        if not listed_as(by_cat, "hexrays-skipped", h["func"], "gate-failed"):
            bad.append("%s is not listed under hexrays-skipped with gate-failed" % h["func"])
    check_all("hexrays-gate", bad)
    h = by_role.get("ptr")
    bad = [] if h and v else ["the fixture has no variant Hex-Rays data"]
    if h and v:
        state = hx_state(h["new_ea"])
        off, itp, _text = h["cmts"][0]
        if not isinstance(state, dict) or state["cmts"] != [[off, itp, v["cmt"]]]:
            bad.append("%s: the Hex-Rays comments are %s, want the variant's own %r kept" % (h["func"], state if not isinstance(state, dict) else state["cmts"], v["cmt"]))
        stk = next(it for it in h["lvars"] if it["loc"][0] == "stk")
        bad += lvar_problems(h, state, [dict(stk, name=v["name"])])
        if not listed_as(by_cat, "hexrays-differs", h["func"], "comment"):
            bad.append("%s: the kept comment is not listed under hexrays-differs" % h["func"])
        if not listed_as(by_cat, "hexrays-differs", h["func"], v["name"]):
            bad.append("%s: the kept variable name is not listed under hexrays-differs" % h["func"])
    check_all("hexrays-keep", bad)
    bad = []
    for role in ("ptr", "enum"):
        h = by_role.get(role)
        if h is None:
            bad.append("the fixture has no Hex-Rays role %s" % role)
            continue
        state = hx_state(h["new_ea"])
        typed = next(it for it in h["lvars"] if it["type"])
        want = dict(typed, type=None)
        if role == "enum" and v.get("lvar_func") == h["func"]:
            want["cmt"] = v["lvar_cmt"]
        bad += lvar_problems(h, state, [want])
        if not listed_as(by_cat, "hexrays-skipped", h["func"], "ExedFixEnum"):
            bad.append("%s: the dropped type %s is not listed under hexrays-skipped naming ExedFixEnum" % (h["func"], typed["type"]))
    check_all("hexrays-type-dropped", bad)
    h = by_role.get("enum")
    bad = [] if h else ["the fixture has no Hex-Rays role enum"]
    if h:
        state = hx_state(h["new_ea"])
        if not isinstance(state, dict) or any(c not in state["cmts"] for c in h["cmts"]):
            bad.append("%s: the Hex-Rays comments are %s, want %s" % (h["func"], state if not isinstance(state, dict) else state["cmts"], h["cmts"]))
        bad += lvar_problems(h, state, [it for it in h["lvars"] if not it["type"]])
    check_all("hexrays-others", bad)
    h = by_role.get("enum")
    bad = [] if h and v.get("lvar_func") == h["func"] else ["the fixture has no variant Hex-Rays variable comment on the enum function"]
    if not bad:
        reg = next(it for it in h["lvars"] if it["loc"][0] == "reg")
        state = hx_state(h["new_ea"])
        if not reg["name"]:
            bad.append("%s: the old register variable has no name to fill in" % h["func"])
        bad += lvar_problems(h, state, [dict(reg, type=None, cmt=v["lvar_cmt"])])
        if not listed_as(by_cat, "hexrays-differs", h["func"], v["lvar_cmt"]):
            bad.append("%s: the kept variable comment is not listed under hexrays-differs" % h["func"])
    check_all("hexrays-fill", bad)
    h = by_role.get("fill")
    bad = [] if h and v.get("fill_func") == h["func"] else ["the fixture has no variant Hex-Rays variable comment on the fill function"]
    if not bad:
        reg = next(it for it in h["lvars"] if it["loc"][0] == "reg")
        state = hx_state(h["new_ea"])
        if not reg["type"]:
            bad.append("%s: the old register variable has no type to fill in" % h["func"])
        bad += lvar_problems(h, state, [dict(reg, cmt=v["fill_cmt"])] + [it for it in h["lvars"] if it["loc"][0] != "reg"])
        if not listed_as(by_cat, "hexrays-differs", h["func"], v["fill_cmt"]):
            bad.append("%s: the kept variable comment is not listed under hexrays-differs" % h["func"])
        bad += ["%s: %s" % (c, x[:100]) for c in ("hexrays-skipped", "hexrays-failed") for x in by_cat.get(c, []) if x.startswith(h["func"] + ":")]
    check_all("hexrays-fill-type", bad)


def snapshot(fixture, dt):
    funcs = {}
    for it in fixture["items"]:
        ea = it["new_ea"]
        funcs["0x%X" % ea] = [ida_name.get_name(ea), user_named(ea), func_cmt(ea, False), func_cmt(ea, True), func_path(dt, ea)]
    insn = {"0x%X" % entry_ea(e): insn_state(entry_ea(e)) for e in fixture.get("insn", [])}
    for p in fixture.get("protos", []):
        insn["proto 0x%X" % p["new_ea"]] = [printed_type(p["new_ea"]), ida_nalt.is_userti(p["new_ea"])]
    for d in fixture.get("data", []):
        insn["data %s" % d["name"]] = [data_state(d["new_ea"]), ida_name.get_name_ea(ida_idaapi.BADADDR, d["name"])]
    for h in fixture.get("hexrays", []):
        insn["hexrays %s" % h["func"]] = hx_state(h["new_ea"])
    return {"functions": funcs, "folders": tree(dt, "/ExedFix") if dt.isdir("/ExedFix") else None,
            "type_count": ida_typeinf.get_ordinal_count(ida_typeinf.get_idati()), "types": sorted(local_types()), "insn": insn}


def check_mode():
    count_checks()
    fixture = load_fixture()
    log = read_log()
    dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    items = fixture["items"]
    folders = check_ported(fixture, dt, [it for it in items if it["expect"] == "ported"])
    check_folders(dt, folders)
    check_not_ported([it for it in items if it["expect"] == "not-ported"], log)
    check_no_suffix(items)
    check_owner_only(fixture, log)
    check_types(log)
    check_dump_types(fixture)
    check_insn(fixture, log)
    check_dump_insn(fixture)
    check_protos(fixture, log)
    check_data(fixture, log)
    check_dump_protos_data(fixture)
    check_hexrays(fixture, log)
    check_dump_hexrays(fixture)
    check_dump_pseudo(False)
    check_report(log, None)
    snap = snapshot(fixture, dt)
    path = os.environ["EXEDFIX_SNAPSHOT"]
    if MODE == "again":
        with open(path, "r", encoding="utf-8") as f:
            before = json.load(f)
        diff = ["%s: %s -> %s" % (k, before["functions"].get(k), v) for k, v in snap["functions"].items() if before["functions"].get(k) != v]
        if before["folders"] != snap["folders"]:
            diff.append("folders %s -> %s" % (before["folders"], snap["folders"]))
        diff += ["%s: %s -> %s" % (k, before.get("insn", {}).get(k), v) for k, v in snap["insn"].items() if before.get("insn", {}).get(k) != v]
        check_all("unchanged", diff)
        diff = []
        if before.get("type_count") != snap["type_count"]:
            diff.append("%s local types, %d after the second apply" % (before.get("type_count"), snap["type_count"]))
        added = sorted(set(snap["types"]) - set(before.get("types", [])))
        if added:
            diff.append("new local types %s" % added[:8])
        check_all("type-count", diff)
    else:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=1)
    if MODE == "check":
        check_rollback(fixture)
        check_hexrays_rollback(fixture)
        check_lvar_size(fixture)


ROLLBACK_DECLS = {"guessed function": "int __fastcall __exed(int a, __int64 b);", "untyped function": "int __fastcall __exed(int a, __int64 b);",
                  "owner prototype": "__int64 __fastcall __exed(__int64 a1);", "untyped dword": "float __exed;",
                  "untyped oword": "ExedFixStruct __exed;", "guessed qword": "__int64 __exed;"}


def type_state(ea):
    return [printed_type(ea), ida_nalt.is_userti(ea), ida_bytes.get_flags(ea) & ida_bytes.DT_TYPE, ida_bytes.get_item_size(ea),
            ida_name.get_name(ea), ida_bytes.get_cmt(ea, False)]


def rollback_targets(fixture):
    out = {}
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if f.tailqty:
            continue
        typed = printed_type(f.start_ea)
        if typed and not ida_nalt.is_userti(f.start_ea):
            out.setdefault("guessed function", f.start_ea)
        elif typed is None:
            out.setdefault("untyped function", f.start_ea)
        if len(out) == 2:
            break
    p = next((p for p in fixture.get("protos", []) if p["role"] != "gate"), None)
    if p:
        out["owner prototype"] = p["new_ea"]
    for n in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(n)
        if ida_segment.get_segm_name(seg) not in (".data", ".rdata"):
            continue
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            fl = ida_bytes.get_flags(ea)
            if ida_bytes.is_code(fl) or ida_bytes.has_user_name(fl) or ida_funcs.get_func(ea) is not None:
                continue
            typed, size = printed_type(ea), ida_bytes.get_item_size(ea)
            if typed is None and ida_bytes.is_dword(fl):
                out.setdefault("untyped dword", ea)
            elif typed is None and ida_bytes.is_oword(fl):
                out.setdefault("untyped oword", ea)
            elif typed and size == 8 and not ida_nalt.is_userti(ea):
                out.setdefault("guessed qword", ea)
            if len(out) == len(ROLLBACK_DECLS):
                return out
    return out


class FakeCtx:
    def __init__(self):
        self.log = portlog.PortLog()


def rejected_apply(ea, decl, size):
    t = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(t, None, decl, ida_typeinf.PT_SIL) is None:
        return None, ["cannot parse %s" % decl], None
    want = ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, t, "", "")
    seen = []
    ctx = FakeCtx()
    saved = feat_protos.kept
    feat_protos.kept = lambda at, w, s: seen.append(printed_type(at)) or False
    try:
        why = feat_protos.set_type(ctx, ea, want, decl, dataplan.closure(want, feat_protos.type_decl_of), size)
    finally:
        feat_protos.kept = saved
    bad = [] if seen == [want] else ["the type %s was not applied before the rejection (seen %s)" % (want, seen)]
    return why, bad, ctx


def check_rollback(fixture):
    targets = rollback_targets(fixture)
    bad = ["no %s to roll back" % k for k in ROLLBACK_DECLS if k not in targets]
    for what, ea in sorted(targets.items()):
        size = None if ida_funcs.get_func(ea) is not None else ida_bytes.get_item_size(ea)
        before = type_state(ea)
        why, problems, ctx = rejected_apply(ea, ROLLBACK_DECLS[what], size)
        bad += ["%s at 0x%X: %s" % (what, ea, p) for p in problems]
        if why != "IDA did not keep it":
            bad.append("%s at 0x%X: set_type said %r" % (what, ea, why))
        after = type_state(ea)
        if after != before:
            bad.append("%s at 0x%X is %s after the rollback, was %s" % (what, ea, after, before))
        if ctx is not None and ctx.log.warnings:
            bad.append("%s at 0x%X warned %s" % (what, ea, ctx.log.warnings))
    check_all("type-rollback", bad)
    bad = []
    ea = targets.get("untyped dword")
    if ea is not None:
        saved = feat_protos.restore
        feat_protos.restore = lambda at, snap: False
        try:
            why, problems, ctx = rejected_apply(ea, ROLLBACK_DECLS["untyped dword"], ida_bytes.get_item_size(ea))
        finally:
            feat_protos.restore = saved
        bad += problems
        if not why or "could not be restored" not in why:
            bad.append("set_type said %r" % why)
        if ctx is None or not any(("0x%X" % ea) in w and "could not be restored" in w for w in ctx.log.warnings):
            bad.append("no warning names 0x%X: %s" % (ea, ctx.log.warnings if ctx else None))
    else:
        bad.append("no untyped dword")
    check_all("type-rollback-warns", bad)


def failing_once(real, at, fake):
    calls = []

    def f(*args):
        calls.append(1)
        return fake if len(calls) in at else real(*args)
    return f


def hexrays_rollback_case(h, kind, patch, restore_ok):
    old, new = h["old_ea"], h["new_ea"]
    ctx = FakeCtx()
    if kind == "cmts":
        it = {"off": h["cmts"][0][0], "itp": ida_hexrays.ITP_BLOCK1, "text": "ExedFix rollback comment"}
        before = feat_hexrays.read_cmts(new)
        saved = feat_hexrays.READERS["cmts"]
        feat_hexrays.READERS["cmts"] = patch(saved)
        try:
            feat_hexrays.write_kind(ctx, h["func"], old, new, "cmts", [it])
        finally:
            feat_hexrays.READERS["cmts"] = saved
        after = feat_hexrays.read_cmts(new)
    else:
        stk = next(x for x in h["lvars"] if x["loc"][0] == "stk")
        it = {"loc": stk["loc"], "defoff": None, "name": "exedfix_rollback", "type": None, "cmt": None, "size": -1, "flags": 0}
        hx = {"lvars": {"stkoff_delta": h["delta"], "ulv_flags": h["ulv_flags"], "list": [it]}}
        before = feat_hexrays.read_lvars(new)
        saved = feat_hexrays.same_lvars
        feat_hexrays.same_lvars = patch(saved)
        try:
            feat_hexrays.write_lvars(ctx, h["func"], old, new, hx, [it])
        finally:
            feat_hexrays.same_lvars = saved
        after = feat_hexrays.read_lvars(new)
    bad = []
    if restore_ok and after != before:
        bad.append("%s %s are %s after the rollback, were %s" % (h["func"], kind, after, before))
    want = "the earlier ones were restored" if restore_ok else "could not be restored"
    if not any(h["func"] in w and want in w for w in ctx.log.warnings):
        bad.append("%s %s: no warning naming the function with %r: %s" % (h["func"], kind, want, ctx.log.warnings))
    if not any(r["category"] == "hexrays-failed" for r in ctx.log.reviews):
        bad.append("%s %s: nothing listed under hexrays-failed" % (h["func"], kind))
    return bad


def check_hexrays_rollback(fixture):
    h = next((h for h in fixture.get("hexrays", []) if h["role"] == "ptr"), None)
    if h is None or not ida_hexrays.init_hexrays_plugin():
        check_all("hexrays-rollback", ["the fixture has no Hex-Rays function or Hex-Rays is not available"])
        return
    bad = hexrays_rollback_case(h, "cmts", lambda real: failing_once(real, {2}, {}), True)
    bad += hexrays_rollback_case(h, "lvars", lambda real: failing_once(real, {1}, False), True)
    check_all("hexrays-rollback", bad)
    bad = hexrays_rollback_case(h, "cmts", lambda real: failing_once(real, {2, 3}, {}), False)
    check_all("hexrays-rollback-warns", bad)


def lvar_container(ea, items, delta, flags):
    lv = ida_hexrays.lvar_uservec_t()
    for key, fields in items:
        lv.lvvec.push_back(feat_hexrays.new_saved_info(ea, key, fields, {}))
    lv.stkoff_delta = delta
    lv.ulv_flags = flags
    return lv


def lvar_size_case(h, name, existing, it):
    new = h["new_ea"]
    ida_hexrays.save_user_lvar_settings(new, lvar_container(new, existing, h["delta"], h["ulv_flags"]))
    ctx = FakeCtx()
    hx = {"lvars": {"stkoff_delta": h["delta"], "ulv_flags": h["ulv_flags"], "list": [it]}}
    feat_hexrays.write_lvars(ctx, h["func"], h["old_ea"], new, hx, [it])
    got = (feat_hexrays.read_lvars(new) or {"items": {}})["items"].get(hexplan.key_of("lvars", it))
    return ctx, got


def check_lvar_size(fixture):
    h = next((h for h in fixture.get("hexrays", []) if h["role"] == "fill"), None)
    if h is None or not ida_hexrays.init_hexrays_plugin():
        check_all("hexrays-lvar-size", ["the fixture has no Hex-Rays fill function or Hex-Rays is not available"])
        return
    new = h["new_ea"]
    original = feat_hexrays.stored_lvars(new)
    reg = next(x for x in h["lvars"] if x["loc"][0] == "reg")
    key = hexplan.key_of("lvars", reg)
    tif = feat_hexrays.parse("char *__exed;")
    typ, decl = feat_hexrays.text_of(tif), feat_hexrays.decl_text(tif)
    base = {"loc": reg["loc"], "defoff": reg["defoff"], "cmt": None, "size": 8, "flags": 0}
    cases = [
        ("dropped type", [], dict(base, name="exedfix_size_drop", type="ExedFixSizeMissing *", decl="ExedFixSizeMissing *__exed;",
                                  types={"ExedFixSizeMissing": "struct ExedFixSizeMissing { int a; };"}),
         {"name": "exedfix_size_drop", "type": None, "cmt": None}, "hexrays-skipped"),
        ("new typed variable", [], dict(base, name="exedfix_size_new", type=typ, decl=decl, types={}),
         {"name": "exedfix_size_new", "type": typ, "cmt": None}, None),
        ("type filled in", [(key, {"name": None, "type": None, "cmt": "exedfix size note", "size": -1, "flags": 0})],
         dict(base, name=None, type=typ, decl=decl, types={}, cmt="exedfix other note"),
         {"name": None, "type": typ, "cmt": "exedfix size note"}, "hexrays-differs"),
    ]
    bad = []
    try:
        for what, existing, it, want, listed in cases:
            ctx, got = lvar_size_case(h, what, existing, it)
            if got is None or any(got[k] != v for k, v in want.items()) or got["size"] != -1:
                bad.append("%s: the variable is %s, want %s with size -1" % (what, got, want))
            if ctx.log.warnings or any(r["category"] == "hexrays-failed" for r in ctx.log.reviews):
                bad.append("%s: %s %s" % (what, ctx.log.warnings, [r for r in ctx.log.reviews if r["category"] == "hexrays-failed"][:2]))
            if listed and not any(r["category"] == listed for r in ctx.log.reviews):
                bad.append("%s: nothing listed under %s" % (what, listed))
    finally:
        ida_hexrays.save_user_lvar_settings(new, original if original is not None else ida_hexrays.lvar_uservec_t())
    check_all("hexrays-lvar-size", bad)


def variant_mode():
    fixture = load_fixture()
    log = read_log()
    reviews = review_part(log)
    by_kind = {it["kind"]: it for it in fixture["items"]}
    clash, nofunc = by_kind["clash"], by_kind["nofunc"]
    other = fixture["variant"]["clash_other"]
    bad = []
    if ida_name.get_name(other) != "ExedFix_Clash":
        bad.append("0x%X lost ExedFix_Clash, it is %s" % (other, ida_name.get_name(other)))
    have = ida_name.get_name(clash["new_ea"])
    if have.startswith("ExedFix_Clash") or user_named(clash["new_ea"]):
        bad.append("the ported function 0x%X is named %s" % (clash["new_ea"], have))
    if "name-in-use" not in reviews or "ExedFix_Clash" not in reviews:
        bad.append("no name-in-use review for ExedFix_Clash")
    check_all("name-in-use", bad)
    bad = []
    f = ida_funcs.get_func(nofunc["new_ea"])
    if f is not None and f.start_ea == nofunc["new_ea"]:
        bad.append("0x%X is a function again" % nofunc["new_ea"])
    if user_named(nofunc["new_ea"]) or ida_name.get_name(nofunc["new_ea"]) == "ExedFix_NoFunc":
        bad.append("0x%X is named %s" % (nofunc["new_ea"], ida_name.get_name(nofunc["new_ea"])))
    if "no-new-function" not in reviews or "ExedFix_NoFunc" not in reviews:
        bad.append("no no-new-function review for ExedFix_NoFunc")
    check_all("no-new-function", bad)
    same = [it for it in fixture["items"] if it["kind"] == "same"]
    wrong = ["%s at 0x%X is %s" % (it["name"], it["new_ea"], ida_name.get_name(it["new_ea"])) for it in same if ida_name.get_name(it["new_ea"]) != it["name"]]
    check_all("others-ported", wrong)
    entries = fixture.get("insn", [])
    by_cat = review_entries(log)
    gate = [e for e in entries if e["role"] == "gate"]
    bad = [] if gate else ["the fixture has no gate function"]
    if gate and not any(x.startswith(gate[0]["func"] + ":") for x in by_cat.get("gate-failed", [])):
        bad.append("no gate-failed review for %s" % gate[0]["func"])
    for e in gate:
        if has_item(entry_ea(e), e):
            bad.append("%s %s landed at 0x%X: %s" % (e["func"], e["kind"], entry_ea(e), insn_state(entry_ea(e))))
        if not listed(by_cat.get("insn-skipped", []), e):
            bad.append("%s %s (old 0x%X) is not listed under insn-skipped" % (e["func"], e["kind"], e["old_ea"]))
    check_all("gate-failed", bad)
    enum = [e for e in entries if e["role"] == "enum"]
    bad = [] if enum else ["the fixture has no enum operand"]
    for e in enum:
        text = ida_lines.tag_remove(ida_ua.print_operand(entry_ea(e), e["opn"]) or "")
        if has_item(entry_ea(e), e) or "EXED_" in text:
            bad.append("the enum format landed at 0x%X although ExedFixEnum differs in the new database: %r %s" % (entry_ea(e), text, insn_state(entry_ea(e))))
        if not listed(by_cat.get("insn-skipped", []), e):
            bad.append("the enum format (old 0x%X) is not listed under insn-skipped" % e["old_ea"])
    if "ExedFixEnum" not in " ".join(by_cat.get("type-differs", [])):
        bad.append("no type-differs review for ExedFixEnum")
    check_all("enum-differs", bad)
    bad = ["%s %s at 0x%X: %s" % (e["func"], e["kind"], entry_ea(e), insn_state(entry_ea(e)))
           for e in entries if e["role"] in ("cmts", "fmt") and not has_item(entry_ea(e), e)]
    check_all("insn-others", bad if entries else ["the fixture has no instruction items"])
    run = next((e for e in entries if e["role"] == "run"), None)
    look = fixture["variant"].get("lookalike")
    bad = [] if run and look else ["the fixture has no look-alike instruction (no register-only patch in an identical run was found)"]
    if run and look:
        if has_item(entry_ea(run), run):
            bad.append("the run comment landed at 0x%X on the look-alike %r (was %r)" % (entry_ea(run), look[4], look[3]))
        landed = [ea for ea in idautils.FuncItems(run["new_start"]) if run["text"] in (ida_bytes.get_cmt(ea, False) or "")]
        if landed:
            bad.append("the run comment landed at %s" % ["0x%X" % ea for ea in landed])
        if not listed(by_cat.get("insn-skipped", []), run):
            bad.append("the run comment (old 0x%X) is not listed under insn-skipped" % run["old_ea"])
    check_all("insn-lookalike", bad)
    variant_protos_data(fixture, by_cat)
    variant_hexrays(fixture, by_cat)
    check_report(log, None)


def listed_as(by_cat, category, name, text=""):
    return any(x.startswith(name + ":") and text in x for x in by_cat.get(category, []))


REASONS = {"multi": "its references lead to different addresses in the new database",
           "ambig": "data references in the new database",
           "size": "the data item in the new database is 1 byte(s), the old one is 4"}


def not_applied(d, ea=None):
    ea = d["new_ea"] if ea is None else ea
    bad = []
    at = ida_name.get_name_ea(ida_idaapi.BADADDR, d["name"])
    if at != ida_idaapi.BADADDR:
        bad.append("%s was applied at 0x%X" % (d["name"], at))
    if ida_bytes.get_cmt(ea, False) == d["cmt"]:
        bad.append("the comment of %s was applied at 0x%X" % (d["name"], ea))
    return bad


def variant_protos_data(fixture, by_cat):
    protos = fixture.get("protos", [])
    gate = next((p for p in protos if p["role"] == "gate"), None)
    bad = [] if gate else ["the fixture has no prototype on the gate function"]
    if gate:
        if printed_type(gate["new_ea"]) == gate["proto"]:
            bad.append("the prototype landed on %s although its gate failed" % gate["func"])
        if not listed_as(by_cat, "proto-skipped", gate["func"]):
            bad.append("%s is not listed under proto-skipped" % gate["func"])
    bad += ["%s at 0x%X has the prototype %s" % (p["func"], p["new_ea"], printed_type(p["new_ea"]))
            for p in protos if p["role"] != "gate" and printed_type(p["new_ea"]) != p["proto"]]
    check_all("proto-gate", bad)
    by_role = {d["role"]: d for d in fixture.get("data", [])}
    for role in ("multi", "ambig", "size"):
        d = by_role.get(role)
        bad = [] if d else ["the fixture has no %s data item" % role]
        if d:
            bad += not_applied(d)
            if not listed_as(by_cat, "data-skipped", d["name"], REASONS[role]):
                bad.append("%s is not listed under data-skipped with %r" % (d["name"], REASONS[role]))
        check_all("data-" + role, bad)
    a, b = by_role.get("dupa"), by_role.get("dupb")
    bad = [] if a and b else ["the fixture has no dupa/dupb data items"]
    if a and b:
        why = "its new address 0x%X is also claimed by" % a["new_ea"]
        for d in (a, b):
            bad += not_applied(d, a["new_ea"])
            if not listed_as(by_cat, "data-skipped", d["name"], why):
                bad.append("%s is not listed under data-skipped with %r" % (d["name"], why))
    check_all("data-dup", bad)
    d = by_role.get("gatedata")
    bad = [] if d else ["the fixture has no gatedata data item"]
    if d:
        func = d["refs"][0][0]
        bad += not_applied(d)
        if not listed_as(by_cat, "data-skipped", d["name"], "is in a function that passed the gate"):
            bad.append("%s is not listed under data-skipped with the gate reason" % d["name"])
        for cat in ("gate-failed", "no-new-function"):
            bad += ["%s names the data-only function 0x%X: %s" % (cat, func, x[:80]) for x in by_cat.get(cat, []) if "[old 0x%X," % func in x]
    check_all("data-gate-quiet", bad)
    d = by_role.get("named")
    bad = [] if d else ["the fixture has no named data item"]
    if d:
        name = fixture["variant"]["data"]["named"]
        at = ida_name.get_name_ea(ida_idaapi.BADADDR, d["name"])
        if at != ida_idaapi.BADADDR:
            bad.append("%s was applied at 0x%X" % (d["name"], at))
        bad += data_problems(d, d["new_ea"], name)
        if not listed_as(by_cat, "data-differs", d["name"]):
            bad.append("%s is not listed under data-differs" % d["name"])
    check_all("data-keep-name", bad)
    d = by_role.get("struct")
    bad = [] if d else ["the fixture has no struct data item"]
    if d:
        if printed_type(d["new_ea"]) == d["type"]:
            bad.append("%s got the type %s although ExedFixEnum differs" % (d["name"], d["type"]))
        if ida_name.get_name(d["new_ea"]) != d["name"]:
            bad.append("%s is not named at 0x%X: %s" % (d["name"], d["new_ea"], ida_name.get_name(d["new_ea"])))
        if not listed_as(by_cat, "data-skipped", d["name"]):
            bad.append("%s is not listed under data-skipped" % d["name"])
    check_all("data-struct-enum-differs", bad)
    d = by_role.get("plain")
    check_all("data-others", data_problems(d, d["new_ea"]) if d else ["the fixture has no plain data item"])


try:
    if MODE == "count":
        count_mode()
    elif MODE == "variant":
        variant_mode()
    elif MODE == "verify":
        verify_mode()
    elif MODE == "empty":
        empty_mode()
    else:
        check_mode()
except Exception:
    check("check_output", False, traceback.format_exc().strip().replace("\n", " | "))
finally:
    if lines:
        with open(os.environ["EXEDFIX_CHECK"], "a", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    idc.process_config_line("ABANDON_DATABASE=YES")
    ida_pro.qexit(0)
