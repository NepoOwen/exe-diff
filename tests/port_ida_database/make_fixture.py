import json
import os
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
import ida_xref
import idautils
import idc

LIB = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "scripts", "port-ida-database", "lib"))
if LIB not in sys.path:
    sys.path.insert(0, LIB)

SN = ida_name.SN_NOWARN | ida_name.SN_NOCHECK
OLDER_NOTE = "exediff: changed vs OLDER.exe (50% similar)"
TYPE_STEPS = [
    "struct ExedFixStruct;",
    "typedef ExedFixStruct *PExedFixStruct;",
    "struct ExedFixCycB;",
    "struct ExedFixCycA { ExedFixCycB *b; int x; };",
    "enum ExedFixEnum { EXED_A = 1, EXED_B = 2 };",
    "struct ExedFixStruct { int a; char b[8]; ExedFixEnum e; };",
    "struct ExedFixCycB { ExedFixCycA *a; int y; };",
    "struct ExedFixParent;",
    "struct ExedFixChild { ExedFixParent *p; int z; };",
    "struct ExedFixParent { int k; ExedFixChild c; };",
]
TYPES = ["ExedFixEnum", "ExedFixStruct", "PExedFixStruct", "ExedFixCycA", "ExedFixCycB", "ExedFixParent", "ExedFixChild"]
INSN_MIN = 6
SAVE = True
VARIANT_ENUM = "enum ExedFixEnum { EXED_X = 1, EXED_Y = 2, EXED_Z = 4 };"
PROTO = "int __fastcall(int a, __int64 b)"
PROTO_DECL = "int __fastcall __exed(int a, __int64 b);"
DATA_ROLES = ["plain", "multi", "ambig", "size", "named", "dupa", "dupb", "gatedata"]
VARIANT_DATA_NAME = "ExedVariant_DataName"
HEX_ROLES = [("ptr", "ExedFix_Hex_0", 8, "PExedFixStruct"), ("enum", "ExedFix_Hex_1", 4, "ExedFixEnum"), ("fill", "ExedFix_Hex_2", 8, "char *")]
VARIANT_HEX_CMT = "ExedFix variant Hex-Rays comment"
VARIANT_HEX_NAME = "exedfix_variant_stk"
VARIANT_HEX_LVCMT = "ExedFix variant Hex-Rays variable comment"
VARIANT_HEX_FILLCMT = "ExedFix variant Hex-Rays comment on an untyped variable"
LABEL_NAME = "exedfix_label"
EXTRA_TIL = "ntddk64_win10"
REBASE_DELTA = 0x10000
REG_OPS = {b + k for b in range(0x00, 0x40, 0x08) for k in range(4)} | set(range(0x84, 0x8C)) | {0x8D}
PREFIXES = {0x66, 0x67, 0xF2, 0xF3, 0x2E, 0x3E, 0x26, 0x64, 0x65, 0x36}


def read(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.read()


def func_start(ea):
    f = ida_funcs.get_func(ea)
    return f if f is not None and f.start_ea == ea else None


def usable(row):
    if row.new_va is None or not row.name.startswith("sub_"):
        return False
    return func_start(row.old_va) is not None and not ida_bytes.has_user_name(ida_bytes.get_flags(row.old_va))


def pick(rows, test, n):
    out = [r for r in rows if test(r)][:n]
    if len(out) < n:
        raise RuntimeError("map.csv has only %d usable rows for a fixture group that needs %d" % (len(out), n))
    return out


def item(kind, row, name, expect, **extra):
    d = {"kind": kind, "name": name, "old_ea": row.old_va, "new_ea": row.new_va, "similarity": row.similarity, "expect": expect,
         "cmt": None, "rptcmt": None, "folder": None}
    d.update(extra)
    return d


def set_name(ea, name):
    if not ida_name.set_name(ea, name, SN):
        raise RuntimeError("cannot name 0x%X %s" % (ea, name))


def set_cmt(ea, text, rpt):
    if not ida_funcs.set_func_cmt(ida_funcs.get_func(ea), text, rpt):
        raise RuntimeError("cannot comment 0x%X" % ea)


def move(dt, ea, folder):
    c = dt.find_entry(ida_dirtree.direntry_t(ea, False))
    path = dt.get_abspath(c)
    err = dt.rename(path, folder + "/" + path.rsplit("/", 1)[1])
    if err != ida_dirtree.DTE_OK:
        raise RuntimeError("cannot move %s to %s: %s" % (path, folder, dt.errstr(err)))


def make_types():
    til = ida_typeinf.get_idati()
    for text in TYPE_STEPS:
        errors = ida_typeinf.parse_decls(til, text, None, ida_typeinf.HTI_DCL)
        if errors:
            raise RuntimeError("%d error(s) parsing %s" % (errors, text))
    for name in TYPES:
        t = ida_typeinf.tinfo_t()
        if not t.get_named_type(til, name) or t.is_forward_decl():
            raise RuntimeError("the local type %s was not made" % name)


def decode(ea):
    insn = ida_ua.insn_t()
    return insn if ida_ua.decode_insn(insn, ea) else None


def optypes(insn):
    out = []
    for op in insn.ops:
        if op.type == ida_ua.o_void:
            break
        out.append(op.type)
    return out


def op_key(insn):
    import feat_insn

    return feat_insn.op_key(insn)


def insns(start):
    out = []
    for ea in sorted(set(idautils.FuncItems(start))):
        insn = decode(ea)
        out.append({"ea": ea, "off": ea - start, "mnem": insn.get_canon_mnem() if insn else "", "ops": optypes(insn) if insn else [],
                    "key": op_key(insn) if insn else None})
    return out


def seq(items):
    return [(i["mnem"], tuple(i["ops"]), i["key"]) for i in items]


def reg_patch(ea):
    insn = decode(ea)
    if insn is None:
        return None
    at = ea
    while at < ea + insn.size - 1 and (ida_bytes.get_byte(at) in PREFIXES or 0x40 <= ida_bytes.get_byte(at) <= 0x4F):
        at += 1
    if ida_bytes.get_byte(at) not in REG_OPS or at + 1 >= ea + insn.size:
        return None
    m = at + 1
    b = ida_bytes.get_byte(m)
    if not ida_bytes.patch_byte(m, b ^ 0x08):
        return None
    after = decode(ea)
    ok = (after is not None and after.size == insn.size and after.get_canon_mnem() == insn.get_canon_mnem() and optypes(after) == optypes(insn)
          and op_key(after) != op_key(insn))
    ida_bytes.patch_byte(m, b)
    return m - ea if ok else None


def free(ea):
    fl = ida_bytes.get_flags(ea)
    return not ida_bytes.has_cmt(fl) and not ida_bytes.has_extra_cmts(fl)


def plain_imms(ea):
    insn = decode(ea)
    fl = ida_bytes.get_flags(ea)
    if insn is None:
        return []
    return [(n, op.value) for n, op in enumerate(insn.ops[k] for k in range(len(optypes(insn)))) if op.type == ida_ua.o_imm and not ida_bytes.is_defarg(fl, n)]


def ida_hex_imm(ea, values):
    insn = decode(ea)
    fl = ida_bytes.get_flags(ea)
    if insn is None:
        return None
    for n, op in enumerate(insn.ops[k] for k in range(len(optypes(insn)))):
        if op.type == ida_ua.o_imm and op.value in values and ida_bytes.is_defarg(fl, n) and ida_bytes.is_numop(fl, n) and ida_bytes.get_radix(fl, n) == 16:
            return n
    return None


def calls_a_function(its):
    for i in its:
        insn = decode(i["ea"])
        if insn is not None and insn.get_canon_mnem() == "call" and insn.ops[0].type == ida_ua.o_near and func_start(insn.ops[0].addr):
            return True
    return False


def gate_patch(ea):
    insn = decode(ea)
    if insn is None or not free(ea) or optypes(insn) != [ida_ua.o_reg, ida_ua.o_imm] or insn.ops[0].reg == 4:
        return None
    if ida_bytes.is_defarg(ida_bytes.get_flags(ea), 1):
        return None
    at = ea
    while ida_bytes.get_byte(at) == 0x66 or 0x40 <= ida_bytes.get_byte(at) <= 0x4F:
        at += 1
    if ida_bytes.get_byte(at) not in (0x81, 0x83) or (ida_bytes.get_byte(at + 1) & 0xC0) != 0xC0:
        return None
    return at + 1 - ea


def role_cmts(its):
    if not calls_a_function(its) or not all(free(i["ea"]) for i in its[1:5]):
        return None
    return [(its[1], {"kind": "cmt", "text": "ExedFix insn comment\nsecond line"}),
            (its[2], {"kind": "rpt", "text": "ExedFix insn repeatable comment"}),
            (its[3], {"kind": "ant", "lines": ["ExedFix anterior 1", "ExedFix anterior 2"]}),
            (its[4], {"kind": "post", "lines": ["ExedFix posterior"]})]


def role_fmt(its):
    imms = [(i, n, v) for i in its for n, v in plain_imms(i["ea"])]
    if len({i["ea"] for i, _n, _v in imms}) < 2:
        return None
    first = imms[0]
    rest = [x for x in imms if x[0]["ea"] != first[0]["ea"]]
    second = next((x for x in rest if 0x20 <= x[2] < 0x7F), rest[0])
    return [(first[0], {"kind": "opfmt", "opn": first[1], "fmt": "hex", "arg": None}),
            (second[0], {"kind": "opfmt", "opn": second[1], "fmt": "char", "arg": None})]


def role_enum(its):
    for i in its:
        n = ida_hex_imm(i["ea"], (1, 2))
        if n is not None:
            return [(i, {"kind": "opfmt", "opn": n, "fmt": "enum", "arg": "ExedFixEnum"})]
    return None


def role_gate(its):
    for i in its:
        at = gate_patch(i["ea"])
        if at is not None:
            return [(i, {"kind": "cmt", "text": "ExedFix gate comment", "patch_at": at, "modrm": ida_bytes.get_byte(i["ea"] + at)}),
                    (i, {"kind": "opfmt", "opn": 1, "fmt": "dec", "arg": None})]
    return None


ROLES = [("cmts", "ExedFix_Insn_Cmts", role_cmts), ("fmt", "ExedFix_Insn_Fmt", role_fmt), ("enum", "ExedFix_Insn_Enum", role_enum),
         ("gate", "ExedFix_Insn_Gate", role_gate)]


def pick_insn_funcs(cands):
    chosen = {}
    for r in cands:
        if len(chosen) == len(ROLES):
            break
        its = insns(r.old_va)
        if len(its) < INSN_MIN:
            continue
        for role, name, test in ROLES:
            if role in chosen:
                continue
            spec = test(its)
            if spec:
                chosen[role] = (r, name, spec)
                break
    missing = [role for role, _n, _t in ROLES if role not in chosen]
    if missing:
        raise RuntimeError("no same/exact-unique function fits the instruction fixture roles %s" % missing)
    return [(role,) + chosen[role] for role, _n, _t in ROLES]


def runs_of(pairs):
    runs, cur = [], []
    for p in pairs:
        if cur and p == (cur[-1][0] + 1, cur[-1][1] + 1):
            cur.append(p)
        else:
            if cur:
                runs.append(cur)
            cur = [p]
    if cur:
        runs.append(cur)
    return runs


def layout(old_va, new_shapes):
    import align

    new = new_shapes.get(str(old_va))
    if not new:
        return None
    old = insns(old_va)
    new_items = [{"off": x[0], "mnem": x[1], "ops": x[2], "key": x[3], "patch": x[4]} for x in new]
    if max(len(old), len(new_items)) > 4000:
        return None
    return old, new_items, align.align_runs(seq(old), seq(new_items))


def has_region(old_va, new_shapes):
    got = layout(old_va, new_shapes)
    return got is not None and len({k for k, _j in got[2]}) < len(got[0])


def pick_high(rows, new_shapes):
    cands = [r for r in rows if r.status == "changed" and (r.similarity or 0) >= 90]
    high = cands[:10]
    if len(high) == 10 and not any(has_region(r.old_va, new_shapes) for r in high):
        extra = next((r for r in cands[10:] if has_region(r.old_va, new_shapes)), None)
        if extra is not None:
            high[-1] = extra
    return pick(high, lambda r: True, 10)


def lookalike_unmapped(old, new_items, k, j):
    import align

    news = seq(new_items)
    news[j] = (news[j][0], news[j][1], "patched")
    return k not in dict(align.align_runs(seq(old), news))


def run_pick(it, old, new_items, pairs):
    longest = max(runs_of(pairs), key=len, default=[])
    if len(longest) < 6:
        return None
    mid = len(longest) // 2
    for n in sorted(range(1, len(longest) - 1), key=lambda n: abs(n - mid)):
        k, j = longest[n]
        if free(old[k]["ea"]) and new_items[j]["patch"] is not None and lookalike_unmapped(old, new_items, k, j):
            return it, old[k], new_items[j]["off"], new_items[j]["patch"]
    k, j = longest[mid]
    return (it, old[k], new_items[j]["off"], None) if free(old[k]["ea"]) else None


def pick_changed(high_items, new_shapes):
    run_picks, region_picks, fmt_picks = [], [], []
    for it in high_items:
        got = layout(it["old_ea"], new_shapes)
        if got is None:
            continue
        old, new_items, pairs = got
        run = run_pick(it, old, new_items, pairs)
        if run is not None:
            run_picks.append(run)
        for k, j in pairs:
            imms = plain_imms(old[k]["ea"])
            if imms:
                fmt_picks.append((it, old[k], new_items[j]["off"], imms[0][0]))
                break
        mapped = {k for k, _j in pairs}
        gap = [k for k in range(len(old)) if k not in mapped and free(old[k]["ea"])]
        if gap:
            region_picks.append((it, old[gap[len(gap) // 2]], None))
    if not fmt_picks:
        raise RuntimeError("no changed function has a plain immediate operand inside an identical run")
    for region in region_picks:
        others = [r for r in run_picks if r[0] is not region[0]]
        run = next((r for r in others if r[3] is not None), others[0] if others else None)
        if run is not None:
            return run, region, fmt_picks[0]
    raise RuntimeError("no two changed functions, one with a long identical run (%d found) and another with a changed region (%d found)" % (
        len(run_picks), len(region_picks)))


def set_insn_item(ea, spec):
    kind = spec["kind"]
    if kind in ("cmt", "rpt"):
        ok = ida_bytes.set_cmt(ea, spec["text"], kind == "rpt")
    elif kind in ("ant", "post"):
        base = ida_lines.E_PREV if kind == "ant" else ida_lines.E_NEXT
        ok = all(ida_lines.update_extra_cmt(ea, base + k, line) is not False for k, line in enumerate(spec["lines"]))
    else:
        n, fmt = spec["opn"], spec["fmt"]
        if fmt == "enum":
            ok = ida_bytes.op_enum(ea, n, ida_typeinf.get_named_type_tid(spec["arg"]), 0)
        else:
            ok = {"hex": ida_bytes.op_hex, "dec": ida_bytes.op_dec, "char": ida_bytes.op_chr}[fmt](ea, n)
    if not ok:
        raise RuntimeError("cannot set %s at 0x%X" % (spec, ea))


def insn_entry(role, name, start, new_start, insn, spec, expect, new_off=None):
    d = {"role": role, "func": name, "old_start": start, "new_start": new_start, "off": insn["off"], "old_ea": insn["ea"],
         "new_off": insn["off"] if new_off is None else new_off, "expect": expect}
    d.update(spec)
    return d


def make_insn(rows, used, items, new_shapes):
    cands = [r for r in rows if r.status == "same" and r.method == "exact-unique" and r.old_va not in used]
    entries = []
    for role, r, name, specs in pick_insn_funcs(cands):
        items.append(item("insn", r, name, "ported"))
        for insn, s in specs:
            entries.append(insn_entry(role, name, r.old_va, r.new_va, insn, s, "present"))
    calls = next((r for r in rows if r.status == "calls_changed" and r.method == "exact-unique" and r.old_va not in used
                  and len(insns(r.old_va)) >= INSN_MIN and free(insns(r.old_va)[2]["ea"])), None)
    if calls is not None:
        items.append(item("insn", calls, "ExedFix_Insn_Calls", "ported"))
        entries.append(insn_entry("calls", "ExedFix_Insn_Calls", calls.old_va, calls.new_va, insns(calls.old_va)[2],
                                  {"kind": "cmt", "text": "ExedFix calls_changed comment"}, "either"))
    high = [it for it in items if it["kind"] == "changed"]
    (run_it, run_insn, run_new_off, look_at), (region_it, region_insn, _n), (fmt_it, fmt_insn, fmt_new_off, fmt_opn) = pick_changed(high, new_shapes)
    spec = {"kind": "cmt", "text": "ExedFix comment in an identical run"}
    if look_at is not None:
        spec["look_at"] = look_at
    entries.append(insn_entry("run", run_it["name"], run_it["old_ea"], run_it["new_ea"], run_insn, spec, "present", run_new_off))
    entries.append(insn_entry("runfmt", fmt_it["name"], fmt_it["old_ea"], fmt_it["new_ea"], fmt_insn,
                              {"kind": "opfmt", "opn": fmt_opn, "fmt": "hex", "arg": None}, "absent", fmt_new_off))
    entries.append(insn_entry("region", region_it["name"], region_it["old_ea"], region_it["new_ea"], region_insn,
                              {"kind": "cmt", "text": "ExedFix comment in a changed region"}, "absent"))
    return entries


def single_dref(ea):
    t = sorted(set(idautils.DataRefsFrom(ea)))
    return t[0] if len(t) == 1 else None


def has_ti(ea):
    return bool(ida_nalt.get_aflags(ea) & ida_nalt.AFL_TI)


def target_info(t):
    fl = ida_bytes.get_flags(t)
    return [ida_bytes.get_item_head(t) == t, ida_bytes.get_item_size(t), ida_bytes.has_user_name(fl), ida_funcs.get_func(t) is not None, has_ti(t),
            ida_bytes.has_cmt(fl)]


def new_data(rows):
    refs, info = {}, {}
    for r in rows:
        if r.status != "same" or r.method != "exact-unique" or r.old_va is None or r.new_va is None:
            continue
        f = func_start(r.new_va)
        if f is None or f.tailqty:
            continue
        out = {}
        for ea in idautils.FuncItems(r.new_va):
            t = single_dref(ea)
            if t is not None:
                out[str(ea - r.new_va)] = t
                info.setdefault(str(t), target_info(t))
        if out:
            refs[str(r.old_va)] = out
    return {"refs": refs, "info": info}


def new_shapes_pass(path):
    import pairs

    out = {}
    rows = pairs.parse_map_csv(read(os.environ["PORTDB_MAP"]))
    for r in rows:
        if r.status == "changed" and r.old_va is not None and r.new_va is not None and func_start(r.new_va):
            high = (r.similarity or 0) >= 90
            out[str(r.old_va)] = [[i["off"], i["mnem"], i["ops"], i["key"], reg_patch(i["ea"]) if high else None] for i in insns(r.new_va)]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(out, f)
    with open(os.environ["EXEDFIX_NEWDATA"], "w", encoding="utf-8") as f:
        json.dump(new_data(rows), f)


def data_segments():
    for s in idautils.Segments():
        seg = ida_segment.getseg(s)
        if ida_segment.get_segm_name(seg) in (".data", ".rdata"):
            yield seg


def code_refs(ea):
    out = {}
    for x in idautils.XrefsTo(ea, 0):
        f = ida_funcs.get_func(x.frm)
        if x.iscode or f is None:
            return None
        out[x.frm] = f.start_ea
    return sorted((start, frm - start, frm) for frm, start in out.items())


def pick_data(all_rows, used, newdata):
    certain = {r.old_va: r.new_va for r in all_rows if r.status == "same" and r.method == "exact-unique" and r.old_va not in used and r.new_va is not None}
    changed = {r.old_va for r in all_rows if r.status == "changed" and (r.similarity or 0) >= 80 and r.old_va not in used}
    chosen, extra, taken = {}, {}, set()
    for seg in data_segments():
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            if len(chosen) == len(DATA_ROLES) and "changed" in extra and "struct" in extra:
                return chosen, extra
            fl = ida_bytes.get_flags(ea)
            size = ida_bytes.get_item_size(ea)
            if size not in (4, 16) or ida_bytes.has_user_name(fl) or ida_bytes.has_cmt(fl) or has_ti(ea) or ida_funcs.get_func(ea) is not None:
                continue
            refs = code_refs(ea)
            if not refs:
                continue
            funcs = {r[0] for r in refs}
            if funcs <= changed:
                extra.setdefault("changed", {"old_ea": ea, "size": size, "refs": [[s, off, None] for s, off, _frm in refs]})
                continue
            if not funcs <= set(certain) or funcs & taken or any(func_start(s).tailqty for s in funcs) or any(single_dref(frm) != ea for _s, _off, frm in refs):
                continue
            news = {newdata["refs"].get(str(s), {}).get(str(off)) for s, off, _frm in refs}
            if len(news) != 1 or None in news:
                continue
            t = news.pop()
            inf = newdata["info"][str(t)]
            if not inf[0] or inf[1] != size or any(inf[2:]):
                continue
            d = {"old_ea": ea, "new_ea": t, "size": size, "refs": [[s, off, certain[s]] for s, off, _frm in refs]}
            role = None
            if size == 16:
                role = "struct" if "struct" not in extra else None
            elif len(refs) >= 2 and "multi" not in chosen:
                role = "multi"
            else:
                role = next((r for r in DATA_ROLES if r != "multi" and r not in chosen and (r != "gatedata" or len(funcs) == 1)), None)
            if role == "struct":
                extra["struct"] = d
            elif role is not None:
                chosen[role] = d
            if role is not None:
                taken |= funcs
    missing = [r for r in DATA_ROLES if r not in chosen] + [r for r in ("changed", "struct") if r not in extra]
    if missing:
        raise RuntimeError("no data items fit the data fixture roles %s" % missing)
    return chosen, extra


def make_data(all_rows, used, newdata):
    chosen, extra = pick_data(all_rows, used, newdata)
    out = []
    for role in DATA_ROLES + ["struct"]:
        d = chosen.get(role) or extra.get(role)
        if d is None:
            continue
        typ = "ExedFixStruct" if d["size"] == 16 else "int"
        out.append(dict(d, role=role, name="ExedFix_Data_" + role.capitalize(), cmt="ExedFix data comment %s\nsecond line" % role, type=typ))
    c = extra["changed"]
    out.append(dict(c, role="changed", name="ExedFix_Data_Changed", new_ea=None, cmt=None, type=None))
    return out


def set_type(ea, decl):
    t = ida_typeinf.tinfo_t()
    if ida_typeinf.parse_decl(t, None, decl, ida_typeinf.PT_SIL) is None or not ida_typeinf.apply_tinfo(ea, t, ida_typeinf.TINFO_DEFINITE):
        raise RuntimeError("cannot give 0x%X the type %s" % (ea, decl))
    if not ida_nalt.is_userti(ea):
        raise RuntimeError("the type at 0x%X is not a user type" % ea)


def annotate_data(entries):
    for d in entries:
        size = ida_bytes.get_item_size(d["old_ea"])
        set_name(d["old_ea"], d["name"])
        if d["cmt"] and not ida_bytes.set_cmt(d["old_ea"], d["cmt"], False):
            raise RuntimeError("cannot comment 0x%X" % d["old_ea"])
        if d["type"]:
            set_type(d["old_ea"], "%s __exed;" % d["type"])
            if ida_bytes.get_item_size(d["old_ea"]) != size:
                raise RuntimeError("the type %s changed the size of 0x%X" % (d["type"], d["old_ea"]))


def pick_protos(rows, used):
    cands = [r for r in rows if r.status == "same" and r.method == "exact-unique" and r.old_va not in used and func_start(r.old_va).tailqty == 0
             and not has_ti(r.old_va) and len(insns(r.old_va)) >= INSN_MIN]
    return pick(cands, lambda r: True, 2)


def local_type_names():
    til = ida_typeinf.get_idati()
    return {n for n in (ida_typeinf.get_numbered_type_name(til, o) for o in range(1, ida_typeinf.get_ordinal_limit(til))) if n}


class StmtFinder(ida_hexrays.ctree_visitor_t):
    def __init__(self, heads):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.heads = heads
        self.ea = None

    def visit_insn(self, i):
        if i.op == ida_hexrays.cit_expr and i.ea in self.heads and self.ea is None:
            self.ea = i.ea
        return 0


def has_thunk(ea):
    for x in idautils.CodeRefsTo(ea, 0):
        g = ida_funcs.get_func(x)
        if g is not None and g.flags & ida_funcs.FUNC_THUNK:
            return True
    return False


def hex_candidate(r, width):
    f = func_start(r.old_va)
    if f is None or f.tailqty or f.end_ea - f.start_ea < 80 or has_thunk(r.old_va):
        return None
    cf = ida_hexrays.decompile(r.old_va)
    if cf is None:
        return None
    heads = set(idautils.FuncItems(r.old_va))
    lvs = [v for v in cf.get_lvars() if not v.is_arg_var and v.defea in heads]
    stk = [v for v in lvs if v.is_stk_var()]
    reg = [v for v in lvs if v.is_reg1() and v.width == width]
    finder = StmtFinder(heads)
    finder.apply_to(cf.body, None)
    if not stk or not reg or finder.ea is None:
        return None
    return cf, stk[0], reg[0], finder.ea


class LabelFinder(ida_hexrays.ctree_visitor_t):
    def __init__(self):
        ida_hexrays.ctree_visitor_t.__init__(self, ida_hexrays.CV_FAST)
        self.num = None

    def visit_insn(self, i):
        if i.label_num >= 0 and self.num is None:
            self.num = i.label_num
        return 0


def pick_label(rows, used):
    for r in [r for r in rows if r.status == "same" and r.method == "exact-unique" and r.old_va not in used][:400]:
        f = func_start(r.old_va)
        if f is None or f.tailqty or has_thunk(r.old_va) or f.end_ea - f.start_ea > 0x2000:
            continue
        cf = ida_hexrays.decompile(r.old_va)
        if cf is None:
            continue
        finder = LabelFinder()
        finder.apply_to(cf.body, None)
        if finder.num is not None:
            return r, finder.num
    return None


def stored_labels(ea):
    m = ida_hexrays.restore_user_labels(ea, None)
    out = []
    if m is not None:
        p = ida_hexrays.user_labels_begin(m)
        while p != ida_hexrays.user_labels_end(m):
            out.append([int(ida_hexrays.user_labels_first(p)), str(ida_hexrays.user_labels_second(p))])
            p = ida_hexrays.user_labels_next(p)
    return out


def make_label(r, num):
    m = ida_hexrays.user_labels_new()
    ida_hexrays.user_labels_insert(m, num, LABEL_NAME)
    ida_hexrays.save_user_labels(r.old_va, m)
    have = stored_labels(r.old_va)
    if have != [[num, LABEL_NAME]]:
        raise RuntimeError("the Hex-Rays label of 0x%X is stored as %s" % (r.old_va, have))
    d = hex_entry("label", "ExedFix_Hex_Label", r.old_va, r.new_va, "listed")
    d.update(cmts=[], lvars=[], labels=have)
    return d


def pick_extra_data(used):
    out = []
    for seg in data_segments():
        if ida_segment.get_segm_name(seg) != ".rdata":
            continue
        ea = seg.start_ea
        while not out:
            ea = ida_bytes.next_unknown(ea, seg.end_ea)
            if ea == ida_idaapi.BADADDR or ea >= seg.end_ea:
                break
            fl = ida_bytes.get_flags(ea)
            if ida_bytes.is_unknown(fl) and not ida_bytes.has_any_name(fl) and not ida_bytes.has_cmt(fl):
                out.append({"role": "unk", "name": "ExedFix_Unk", "old_ea": ea, "cmt": "ExedFix comment on undefined bytes",
                            "why": "it is on undefined bytes"})
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        if f.start_ea in used or len(out) == 2:
            continue
        for ea in idautils.Heads(f.start_ea, f.end_ea):
            fl = ida_bytes.get_flags(ea)
            if ida_bytes.is_data(fl) and ida_funcs.get_fchunk(ea) is not None and not ida_bytes.has_user_name(fl) and not ida_bytes.has_cmt(fl):
                out.append({"role": "infunc", "name": "ExedFix_InFunc", "old_ea": ea, "cmt": "ExedFix comment on data inside a function",
                            "why": "it is data inside a function"})
                break
    if [d["role"] for d in out] != ["unk", "infunc"]:
        raise RuntimeError("no undefined byte in .rdata or no data inside a function for the extra data items: %s" % out)
    return out


def annotate_extra(entries):
    for d in entries:
        set_name(d["old_ea"], d["name"])
        if not ida_bytes.set_cmt(d["old_ea"], d["cmt"], False):
            raise RuntimeError("cannot comment 0x%X" % d["old_ea"])
    fl = ida_bytes.get_flags(entries[0]["old_ea"])
    if not ida_bytes.is_unknown(fl) or not ida_bytes.has_user_name(fl):
        raise RuntimeError("0x%X is no longer an undefined byte with a user name" % entries[0]["old_ea"])


def lvar_loc(loc):
    return ["stk", loc.stkoff()] if loc.is_stkoff() else ["reg", loc.reg1()] if loc.is_reg1() else None


def stored_lvars(ea):
    lv = ida_hexrays.lvar_uservec_t()
    if not ida_hexrays.restore_user_lvar_settings(lv, ea):
        return None
    items = []
    for s in lv.lvvec:
        items.append({"loc": lvar_loc(s.ll.location), "defoff": None if s.ll.defea == ida_idaapi.BADADDR else s.ll.defea - ea, "name": s.name or None,
                      "type": None if s.type.empty() else ida_typeinf.print_tinfo("", 0, 0, ida_typeinf.PRTYPE_1LINE, s.type, "", ""), "cmt": s.cmt or None})
    return {"delta": lv.stkoff_delta, "flags": lv.ulv_flags, "items": items}


def modify_lvar(ea, lvar, mli, name=None, decl=None, cmt=None):
    s = ida_hexrays.lvar_saved_info_t()
    s.ll = lvar
    if name:
        s.name = name
    if decl:
        t = ida_typeinf.tinfo_t()
        if ida_typeinf.parse_decl(t, None, decl, ida_typeinf.PT_SIL) is None:
            raise RuntimeError("cannot parse %s" % decl)
        s.type = t
    if cmt:
        s.cmt = cmt
    if not ida_hexrays.modify_user_lvar_info(ea, mli, s):
        raise RuntimeError("cannot change a Hex-Rays variable of 0x%X" % ea)


def save_cmts(ea, cmts):
    c = ida_hexrays.user_cmts_new()
    for off, itp, text in cmts:
        tl = ida_hexrays.treeloc_t()
        tl.ea = ea + off
        tl.itp = itp
        ida_hexrays.user_cmts_insert(c, tl, ida_hexrays.citem_cmt_t(text))
    ida_hexrays.save_user_cmts(ea, c)


def stored_cmts(ea):
    c = ida_hexrays.restore_user_cmts(ea)
    out = []
    if c is not None:
        p = ida_hexrays.user_cmts_begin(c)
        while p != ida_hexrays.user_cmts_end(c):
            k = ida_hexrays.user_cmts_first(p)
            out.append([k.ea - ea, int(k.itp), str(ida_hexrays.user_cmts_second(p))])
            p = ida_hexrays.user_cmts_next(p)
    return out


def pick_hex(rows, used):
    cands = [r for r in rows if r.status == "same" and r.method == "exact-unique" and r.old_va not in used]
    chosen, taken = [], set()
    for role, name, width, typ in HEX_ROLES:
        for r in cands:
            if r.old_va in taken:
                continue
            got = hex_candidate(r, width)
            if got is not None:
                chosen.append((role, name, typ, r, got))
                taken.add(r.old_va)
                break
        else:
            raise RuntimeError("no same/exact-unique function fits the Hex-Rays fixture role %s" % role)
    return chosen


def hex_entry(role, name, old_ea, new_ea, expect):
    return {"role": role, "func": name, "old_ea": old_ea, "new_ea": new_ea, "expect": expect}


def make_hex(chosen, gate_item, changed_item):
    out = []
    for i, (role, name, typ, r, (cf, stk, reg, stmt)) in enumerate(chosen):
        ea = r.old_va
        tl = ida_hexrays.treeloc_t()
        tl.ea = stmt
        tl.itp = ida_hexrays.ITP_SEMI
        cf.set_user_cmt(tl, "ExedFix Hex-Rays comment %d" % i)
        cf.save_user_cmts()
        modify_lvar(ea, stk, ida_hexrays.MLI_NAME, name="exedfix_stk_%d" % i)
        if role == "enum":
            modify_lvar(ea, reg, ida_hexrays.MLI_NAME, name="exedfix_enum_%d" % i)
        modify_lvar(ea, reg, ida_hexrays.MLI_TYPE | ida_hexrays.MLI_CMT, decl="%s __exed;" % typ, cmt="ExedFix Hex-Rays variable comment %d" % i)
        d = hex_entry(role, name, r.old_va, r.new_va, "ported")
        lv = stored_lvars(ea)
        if lv is None or len(lv["items"]) != 2 or any(it["loc"] is None for it in lv["items"]):
            raise RuntimeError("the Hex-Rays variables of 0x%X are stored as %s" % (ea, lv))
        d.update(cmts=stored_cmts(ea), lvars=lv["items"], delta=lv["delta"], ulv_flags=lv["flags"], typ=typ)
        typed = [it for it in d["lvars"] if it["type"]]
        if len(d["cmts"]) != 1 or len(typed) != 1 or typed[0]["type"] != typ or typed[0]["cmt"] is None:
            raise RuntimeError("the Hex-Rays data of 0x%X is stored as %s" % (ea, d))
        out.append(d)
    for role, it, text in (("gate", gate_item, "ExedFix Hex-Rays gate comment"), ("changed", changed_item, "ExedFix Hex-Rays comment in a changed function")):
        heads = insns(it["old_ea"])
        save_cmts(it["old_ea"], [[heads[1]["off"], ida_hexrays.ITP_SEMI, text]])
        d = hex_entry(role, it["name"], it["old_ea"], it["new_ea"], "ported" if role == "gate" else "absent")
        d.update(cmts=stored_cmts(it["old_ea"]), lvars=[])
        if len(d["cmts"]) != 1:
            raise RuntimeError("the Hex-Rays comment of 0x%X is stored as %s" % (it["old_ea"], d["cmts"]))
        out.append(d)
    return out


def old_pass(path):
    import idautil2
    import pairs

    all_rows = sorted((r for r in pairs.parse_map_csv(read(os.environ["PORTDB_MAP"])) if r.old_va is not None), key=lambda r: r.old_va)
    rows = [r for r in all_rows if usable(r)]
    pair = pairs.parse_pair_txt(read(os.environ["PORTDB_PAIR"]))
    same = pick(rows, lambda r: r.status == "same" and r.method == "exact-unique", 48)
    with open(os.environ["EXEDFIX_NEWSHAPES"], "r", encoding="utf-8") as f:
        new_shapes = json.load(f)
    high = pick_high(rows, new_shapes)
    low = pick(rows, lambda r: r.status == "changed" and (r.similarity or 0) < 80, 5)
    group = pick(rows, lambda r: r.status == "same" and r.method == "exact-group", 3)

    items = []
    for i, r in enumerate(same[:40]):
        cmt = "ExedFix regular comment %d\nsecond line" % i if i < 10 else None
        rpt = "ExedFix repeatable comment %d" % i if 10 <= i < 20 else None
        items.append(item("same", r, "ExedFix_Same_%d" % i, "ported", cmt=cmt, rptcmt=rpt, folder="/ExedFix/Same" if i < 5 else None))
    items.append(item("clash", same[40], "ExedFix_Clash", "ported"))
    items.append(item("nofunc", same[41], "ExedFix_NoFunc", "ported"))
    for i, r in enumerate(high):
        extra = {"cmt": "owner text", "old_cmt": "owner text\n" + OLDER_NOTE} if i == 0 else {}
        items.append(item("changed", r, "ExedFix_Changed_%d" % i, "ported", **extra))
    for i, r in enumerate(low):
        items.append(item("below", r, "ExedFix_Below_%d" % i, "not-ported"))
    for i, r in enumerate(group):
        items.append(item("group", r, "ExedFix_Group_%d" % i, "not-ported"))
    used = {it["old_ea"] for it in items} | {r.old_va for r in same}
    insn_entries = make_insn(rows, used, items, new_shapes)
    used |= {it["old_ea"] for it in items}
    protos = []
    for i, r in enumerate(pick_protos(rows, used)):
        items.append(item("proto", r, "ExedFix_Proto_%d" % i, "ported"))
        protos.append({"role": "same", "func": "ExedFix_Proto_%d" % i, "old_ea": r.old_va, "new_ea": r.new_va, "proto": PROTO})
    gate_item = next(it for it in items if it["name"] == "ExedFix_Insn_Gate")
    protos.append({"role": "gate", "func": gate_item["name"], "old_ea": gate_item["old_ea"], "new_ea": gate_item["new_ea"], "proto": PROTO})
    used |= {it["old_ea"] for it in items}
    with open(os.environ["EXEDFIX_NEWDATA"], "r", encoding="utf-8") as f:
        data_entries = make_data(all_rows, used, json.load(f))
    used |= {r[0] for d in data_entries for r in d["refs"]}
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("the Hex-Rays decompiler is not available")
    types_before = local_type_names()
    hex_chosen = pick_hex(rows, used)
    used |= {r.old_va for _role, _n, _t, r, _g in hex_chosen}
    label_pick = pick_label(rows, used)
    decompiler_types = sorted(local_type_names() - types_before)
    for role, name, _typ, r, _got in hex_chosen:
        items.append(item("hex", r, name, "ported"))
    if label_pick is not None:
        items.append(item("hex", label_pick[0], "ExedFix_Hex_Label", "ported"))
    used |= {it["old_ea"] for it in items}
    extra_data = pick_extra_data(used)

    dt = ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)
    for folder in ("/ExedFix/Sub", "/ExedFix/Same"):
        err = dt.mkdir(folder)
        if err != ida_dirtree.DTE_OK:
            raise RuntimeError("mkdir %s: %s" % (folder, dt.errstr(err)))
    for it in items:
        set_name(it["old_ea"], it["name"])
        cmt = it.get("old_cmt", it["cmt"])
        if cmt:
            set_cmt(it["old_ea"], cmt, False)
        if it["rptcmt"]:
            set_cmt(it["old_ea"], it["rptcmt"], True)
        if it["folder"]:
            move(dt, it["old_ea"], it["folder"])
    make_types()
    for e in insn_entries:
        set_insn_item(e["old_ea"], e)
    for p in protos:
        set_type(p["old_ea"], PROTO_DECL)
    annotate_data(data_entries)
    hex_entries = make_hex(hex_chosen, gate_item, next(it for it in items if it["name"] == "ExedFix_Changed_1"))
    if label_pick is not None:
        hex_entries.append(make_label(*label_pick))
    annotate_extra(extra_data)

    fixture = {"version": 1, "old_md5": idautil2.old_md5_hex(), "old_exe_name": os.path.basename(pair.get("old_exe", "").strip().replace("\\", "/")),
               "clash_candidates": [r.new_va for r in same[42:]], "items": items, "types": TYPES, "insn": insn_entries, "protos": protos,
               "data": data_entries, "extra_data": extra_data, "hexrays": hex_entries, "decompiler_types": decompiler_types}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=1)


def variant_data(fixture):
    by_role = {d["role"]: d for d in fixture.get("data", [])}
    out = {}
    d = by_role["multi"]
    frm = d["refs"][0][2] + d["refs"][0][1]
    other = ida_bytes.next_head(d["new_ea"], ida_idaapi.BADADDR)
    ida_xref.del_dref(frm, d["new_ea"])
    ida_xref.add_dref(frm, other, ida_xref.dr_R | ida_xref.XREF_USER)
    if sorted(set(idautils.DataRefsFrom(frm))) != [other]:
        raise RuntimeError("cannot point 0x%X at 0x%X" % (frm, other))
    out["multi"] = [frm, other]
    d = by_role["ambig"]
    frm = d["refs"][0][2] + d["refs"][0][1]
    other = ida_bytes.next_head(d["new_ea"], ida_idaapi.BADADDR)
    ida_xref.add_dref(frm, other, ida_xref.dr_R | ida_xref.XREF_USER)
    if len(set(idautils.DataRefsFrom(frm))) != 2:
        raise RuntimeError("cannot add a second data reference at 0x%X" % frm)
    out["ambig"] = [frm, other]
    d = by_role["size"]
    if not ida_bytes.del_items(d["new_ea"], 0, d["size"]) or not ida_bytes.create_byte(d["new_ea"], 1) or ida_bytes.get_item_size(d["new_ea"]) != 1:
        raise RuntimeError("cannot make 0x%X a byte" % d["new_ea"])
    out["size"] = 1
    d = by_role["named"]
    set_name(d["new_ea"], VARIANT_DATA_NAME)
    out["named"] = VARIANT_DATA_NAME
    a, b = by_role["dupa"], by_role["dupb"]
    for _s, off, new_func in b["refs"]:
        frm = new_func + off
        ida_xref.del_dref(frm, b["new_ea"])
        ida_xref.add_dref(frm, a["new_ea"], ida_xref.dr_R | ida_xref.XREF_USER)
        if sorted(set(idautils.DataRefsFrom(frm))) != [a["new_ea"]]:
            raise RuntimeError("cannot point 0x%X at 0x%X" % (frm, a["new_ea"]))
    out["dup"] = a["new_ea"]
    d = by_role["gatedata"]
    out["gatedata"] = break_gate(d["refs"][0][2], {new_func + off for _s, off, new_func in d["refs"]})
    return out


def break_gate(start, keep):
    for ea in sorted(set(idautils.FuncItems(start))):
        before = decode(ea)
        if ea in keep or before is None:
            continue
        for k in range(1, before.size):
            b = ida_bytes.get_byte(ea + k)
            if not ida_bytes.patch_byte(ea + k, b ^ 0x08):
                continue
            after = decode(ea)
            if after is not None and after.size == before.size and after.get_canon_mnem() != before.get_canon_mnem():
                return [start, ea + k, b, before.get_canon_mnem(), after.get_canon_mnem()]
            ida_bytes.patch_byte(ea + k, b)
    raise RuntimeError("cannot change a mnemonic in the function at 0x%X" % start)


def variant_hex(fixture):
    if not ida_hexrays.init_hexrays_plugin():
        raise RuntimeError("the Hex-Rays decompiler is not available")
    d = next(h for h in fixture["hexrays"] if h["role"] == "ptr")
    ea = d["new_ea"]
    off, itp, _text = d["cmts"][0]
    save_cmts(ea, [[off, itp, VARIANT_HEX_CMT]])
    stk = next(it for it in d["lvars"] if it["loc"][0] == "stk")
    save_lvar(ea, d, stk, name=VARIANT_HEX_NAME)
    have = stored_lvars(ea)
    if stored_cmts(ea) != [[off, itp, VARIANT_HEX_CMT]] or have is None or [it["name"] for it in have["items"]] != [VARIANT_HEX_NAME]:
        raise RuntimeError("cannot give 0x%X its own Hex-Rays data: %s %s" % (ea, stored_cmts(ea), have))
    out = {"func": d["func"], "cmt": VARIANT_HEX_CMT, "name": VARIANT_HEX_NAME}
    for role, cmt, fk, ck in (("enum", VARIANT_HEX_LVCMT, "lvar_func", "lvar_cmt"), ("fill", VARIANT_HEX_FILLCMT, "fill_func", "fill_cmt")):
        e = next(h for h in fixture["hexrays"] if h["role"] == role)
        reg = next(it for it in e["lvars"] if it["loc"][0] == "reg")
        save_lvar(e["new_ea"], e, reg, cmt=cmt)
        have = stored_lvars(e["new_ea"])
        if have is None or [(it["name"], it["type"], it["cmt"]) for it in have["items"]] != [(None, None, cmt)]:
            raise RuntimeError("cannot give 0x%X its own Hex-Rays variable comment: %s" % (e["new_ea"], have))
        out[fk], out[ck] = e["func"], cmt
    return out


def save_lvar(ea, d, it, name=None, cmt=None):
    lv = ida_hexrays.lvar_uservec_t()
    s = ida_hexrays.lvar_saved_info_t()
    loc = ida_hexrays.lvar_locator_t()
    vd = ida_hexrays.vdloc_t()
    if it["loc"][0] == "stk":
        vd.set_stkoff(it["loc"][1])
    else:
        vd.set_reg1(it["loc"][1])
    loc.location = vd
    loc.defea = ida_idaapi.BADADDR if it["defoff"] is None else ea + it["defoff"]
    s.ll = loc
    if name:
        s.name = name
    if cmt:
        s.cmt = cmt
    lv.lvvec.push_back(s)
    lv.stkoff_delta = d["delta"]
    lv.ulv_flags = d["ulv_flags"]
    ida_hexrays.save_user_lvar_settings(ea, lv)


def disasm(ea):
    return ida_lines.tag_remove(ida_lines.generate_disasm_line(ea, 0) or "")


def variant_lookalike(fixture):
    run = next((e for e in fixture["insn"] if e["role"] == "run" and "look_at" in e), None)
    if run is None:
        return None
    ea = run["new_start"] + run["new_off"]
    before, text = decode(ea), disasm(ea)
    at = ea + run["look_at"]
    b = ida_bytes.get_byte(at)
    if before is None or not ida_bytes.patch_byte(at, b ^ 0x08):
        raise RuntimeError("cannot patch 0x%X" % at)
    after = decode(ea)
    if (after is None or after.size != before.size or after.get_canon_mnem() != before.get_canon_mnem() or optypes(after) != optypes(before)
            or op_key(after) == op_key(before)):
        raise RuntimeError("the patch at 0x%X did not change a register only: %s -> %s" % (at, text, disasm(ea)))
    return [at, b, b ^ 0x08, text, disasm(ea)]


def variant_pass(path):
    with open(path, "r", encoding="utf-8") as f:
        fixture = json.load(f)
    other = next((ea for ea in fixture["clash_candidates"] if func_start(ea) and not ida_bytes.has_user_name(ida_bytes.get_flags(ea))), None)
    if other is None:
        raise RuntimeError("no function in the new database to give the name ExedFix_Clash")
    set_name(other, "ExedFix_Clash")
    nofunc = next(it for it in fixture["items"] if it["kind"] == "nofunc")
    if not func_start(nofunc["new_ea"]) or not ida_funcs.del_func(nofunc["new_ea"]):
        raise RuntimeError("cannot delete the function at 0x%X" % nofunc["new_ea"])
    gate = next(e for e in fixture["insn"] if e["role"] == "gate" and "patch_at" in e)
    ea = gate["new_start"] + gate["off"]
    before = decode(ea)
    at = ea + gate["patch_at"]
    old_byte = ida_bytes.get_byte(at)
    if before is None or old_byte != gate["modrm"] or not ida_bytes.patch_byte(at, old_byte ^ 0x08):
        raise RuntimeError("cannot patch 0x%X" % at)
    after = decode(ea)
    if after is None or after.size != before.size or after.get_canon_mnem() == before.get_canon_mnem():
        raise RuntimeError("the patch at 0x%X did not change the mnemonic only" % at)
    lookalike = variant_lookalike(fixture)
    til = ida_typeinf.get_idati()
    if ida_typeinf.parse_decls(til, VARIANT_ENUM, None, ida_typeinf.HTI_DCL) != 0 or ida_typeinf.get_named_type_tid("ExedFixEnum") == ida_idaapi.BADADDR:
        raise RuntimeError("cannot declare the conflicting ExedFixEnum in the variant")
    fixture["variant"] = {"clash_other": other, "gate_patch": [at, old_byte, old_byte ^ 0x08, before.get_canon_mnem(), after.get_canon_mnem()],
                          "enum": VARIANT_ENUM, "data": variant_data(fixture), "hexrays": variant_hex(fixture), "lookalike": lookalike}
    with open(path, "w", encoding="utf-8") as f:
        json.dump(fixture, f, indent=1)


def empty_pass():
    import ida_auto

    ida_auto.auto_wait()
    named = [ea for ea, name in idautils.Names() if name.startswith("ExedFix")]
    if named:
        raise RuntimeError("the empty copy has fixture names at %s" % ["0x%X" % ea for ea in named[:4]])


def til_pass():
    til = ida_typeinf.get_idati()
    if any(til.base(i).name == EXTRA_TIL for i in range(til.nbases)):
        raise RuntimeError("%s is already loaded" % EXTRA_TIL)
    if ida_typeinf.add_til(EXTRA_TIL, ida_typeinf.ADDTIL_DEFAULT) != ida_typeinf.ADDTIL_OK:
        raise RuntimeError("cannot load the type library %s" % EXTRA_TIL)


def rebase_pass():
    # the copy only: shift the whole program by less than its code size, like a debugger session under ASLR
    import ida_auto

    ida_auto.auto_wait()
    before = ida_nalt.get_imagebase()
    code = ida_segment.rebase_program(REBASE_DELTA, ida_segment.MSF_FIXONCE)
    if code != ida_segment.MOVE_SEGM_OK:
        raise RuntimeError("rebase_program by 0x%X failed with %d" % (REBASE_DELTA, code))
    ida_auto.auto_wait()
    if ida_nalt.get_imagebase() != before + REBASE_DELTA:
        raise RuntimeError("the image base is 0x%X after the rebase, want 0x%X" % (ida_nalt.get_imagebase(), before + REBASE_DELTA))


def main():
    global SAVE
    path = os.environ["EXEDFIX_FIXTURE"]
    if "--new-shapes" in idc.ARGV[1:]:
        SAVE = False
        new_shapes_pass(os.environ["EXEDFIX_NEWSHAPES"])
    elif "--rebase" in idc.ARGV[1:]:
        rebase_pass()
    elif "--empty" in idc.ARGV[1:]:
        empty_pass()
    elif "--add-til" in idc.ARGV[1:]:
        til_pass()
    elif "--new-variant" in idc.ARGV[1:]:
        variant_pass(path)
    else:
        old_pass(path)
    return 0


code = 2
try:
    code = main()
except Exception:
    traceback.print_exc()
    with open(os.environ.get("EXEDFIX_FIXTURE", "fixture.json") + ".error.txt", "w", encoding="utf-8") as f:
        f.write(traceback.format_exc())
finally:
    try:
        import idautil2
        idautil2.finish(code, save=SAVE)
    except Exception:
        idc.process_config_line("ABANDON_DATABASE=YES")
        ida_pro.qexit(2)
