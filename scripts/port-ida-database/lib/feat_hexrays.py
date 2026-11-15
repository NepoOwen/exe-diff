import hashlib
import json

import ida_funcs
import ida_hexrays
import ida_idaapi
import ida_pro
import ida_typeinf
import ida_ua

import dataplan
import feat_insn
import hexplan
from feat_names import func_at, label, user_name, why_not
from feat_protos import decl_text, parse, text_of, type_closure, type_decl_of

BADADDR = ida_idaapi.BADADDR
NO_HEXRAYS = "the Hex-Rays decompiler is not available: Hex-Rays comments, variable settings and other decompiler data are not %s"
GATE_FAILED = "the function's instructions differ in the new database (gate-failed)"


def available():
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def ch(x):
    return ord(x) if isinstance(x, str) else int(x)


def set_char(obj, attr, value):
    try:
        setattr(obj, attr, value)
    except TypeError:
        setattr(obj, attr, chr(value))


def pairs_of(m, kind):
    out = []
    if m is None:
        return out
    begin, end = getattr(ida_hexrays, "user_%s_begin" % kind), getattr(ida_hexrays, "user_%s_end" % kind)
    first, second, nxt = (getattr(ida_hexrays, "user_%s_%s" % (kind, x)) for x in ("first", "second", "next"))
    p = begin(m)
    while p != end(m):
        out.append((first(p), second(p)))
        p = nxt(p)
    return out


def read_cmts(ea):
    return {(k.ea - ea, int(k.itp)): str(v) for k, v in pairs_of(ida_hexrays.restore_user_cmts(ea), "cmts")}


def read_numforms(ea):
    return {(k.ea - ea, int(k.opnum)): (int(v.flags), ch(v.opnum), ch(v.props), ch(v.serial), ch(v.org_nbytes), v.type_name or "")
            for k, v in pairs_of(ida_hexrays.restore_user_numforms(ea), "numforms")}


def read_unions(ea):
    return {k - ea: tuple(int(x) for x in v) for k, v in pairs_of(ida_hexrays.restore_user_unions(ea), "unions")}


def read_labels(ea):
    return {int(k): str(v) for k, v in pairs_of(ida_hexrays.restore_user_labels(ea, None), "labels")}


def read_iflags(ea):
    return {(k.ea - ea, int(k.op)): int(v) for k, v in pairs_of(ida_hexrays.restore_user_iflags(ea), "iflags")}


READERS = {"cmts": read_cmts, "numforms": read_numforms, "unions": read_unions, "iflags": read_iflags}


def save_cmts(ea, d):
    c = ida_hexrays.user_cmts_new()
    for (off, itp), text in d.items():
        tl = ida_hexrays.treeloc_t()
        tl.ea = ea + off
        tl.itp = itp
        ida_hexrays.user_cmts_insert(c, tl, ida_hexrays.citem_cmt_t(text))
    ida_hexrays.save_user_cmts(ea, c)


def save_numforms(ea, d):
    c = ida_hexrays.user_numforms_new()
    for (off, opnum), (flags, nf_opnum, props, serial, nbytes, type_name) in d.items():
        nf = ida_hexrays.number_format_t(nf_opnum)
        nf.flags = flags
        for attr, value in (("props", props), ("serial", serial), ("org_nbytes", nbytes)):
            set_char(nf, attr, value)
        nf.type_name = type_name
        ida_hexrays.user_numforms_insert(c, ida_hexrays.operand_locator_t(ea + off, opnum), nf)
    ida_hexrays.save_user_numforms(ea, c)


def save_unions(ea, d):
    c = ida_hexrays.user_unions_new()
    for off, path in d.items():
        iv = ida_pro.intvec_t()
        for x in path:
            iv.push_back(x)
        ida_hexrays.user_unions_insert(c, ea + off, iv)
    ida_hexrays.save_user_unions(ea, c)


def save_iflags(ea, d):
    c = ida_hexrays.user_iflags_new()
    for (off, op), flags in d.items():
        ida_hexrays.user_iflags_insert(c, ida_hexrays.citem_locator_t(ea + off, op), flags)
    ida_hexrays.save_user_iflags(ea, c)


SAVERS = {"cmts": save_cmts, "numforms": save_numforms, "unions": save_unions, "iflags": save_iflags}


def loc_of(location):
    if location.is_stkoff():
        return ["stk", int(location.stkoff())]
    if location.is_reg1():
        return ["reg", int(location.reg1())]
    return None


def lvar_key(s, ea, other):
    loc = loc_of(s.ll.location)
    if loc is None:
        return ("other", other), None
    return tuple(loc), None if s.ll.defea == BADADDR else s.ll.defea - ea


def lvar_fields(s):
    return {"name": s.name or None, "type": None if s.type.empty() else text_of(s.type), "cmt": s.cmt or None, "size": int(s.size), "flags": int(s.flags)}


def mappings(lv):
    n, p = 0, ida_hexrays.lvar_mapping_begin(lv.lmaps)
    while p != ida_hexrays.lvar_mapping_end(lv.lmaps):
        n += 1
        p = ida_hexrays.lvar_mapping_next(p)
    return n


def stored_lvars(ea):
    lv = ida_hexrays.lvar_uservec_t()
    return lv if ida_hexrays.restore_user_lvar_settings(lv, ea) else None


def read_lvars(ea):
    lv = stored_lvars(ea)
    if lv is None:
        return None
    items, other = {}, 0
    for s in lv.lvvec:
        key = lvar_key(s, ea, other)
        if key[0][0] == "other":
            other += 1
        items[key] = lvar_fields(s)
    return {"delta": int(lv.stkoff_delta), "flags": int(lv.ulv_flags), "items": items}


def frame_of(f):
    return [int(f.frsize), int(f.frregs), int(f.argsize), int(f.fpd)]


def op_row(op, f):
    row = [ch(op.type), ch(op.dtype)]
    if op.type in (ida_ua.o_reg, ida_ua.o_phrase, ida_ua.o_displ):
        row.append(int(op.reg))
    if op.type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
        row += [ch(op.specflag1), ch(op.specflag2)]
    if op.type in (ida_ua.o_phrase, ida_ua.o_displ):
        row.append(int(op.addr))
    if op.type in (ida_ua.o_near, ida_ua.o_far):
        g = ida_funcs.get_func(op.addr)
        row.append(op.addr - f.start_ea if g is not None and g.start_ea == f.start_ea else None)
    return row


def ops_of(f):
    insn = ida_ua.insn_t()
    out = []
    for ea in feat_insn.items_of(f):
        if ida_ua.decode_insn(insn, ea) <= 0:
            out.append([ea - f.start_ea])
            continue
        ops = []
        for k in range(8):
            if insn.ops[k].type == ida_ua.o_void:
                break
            ops.append(op_row(insn.ops[k], f))
        out.append([ea - f.start_ea, insn.get_canon_mnem(), ops])
    return hashlib.sha1(json.dumps(out).encode("utf-8")).hexdigest()


def union_types():
    til = ida_typeinf.get_idati()
    out = {}
    for o in range(1, ida_typeinf.get_ordinal_limit(til)):
        name = ida_typeinf.get_numbered_type_name(til, o)
        t = ida_typeinf.tinfo_t()
        if name and t.get_numbered_type(til, o) and t.is_union():
            out.update(type_closure(name))
    return out


def export_lvars(ctx, ea, what, new):
    lv = stored_lvars(ea)
    if lv is None:
        return None
    out, other = [], 0
    for s in lv.lvvec:
        loc = loc_of(s.ll.location)
        if loc is None:
            other += 1
            continue
        it = dict(lvar_fields(s), loc=loc, defoff=None if s.ll.defea == BADADDR else s.ll.defea - ea)
        if it["type"]:
            it.update(decl=decl_text(s.type), types=type_closure(it["type"]))
        out.append(it)
    if other:
        ctx.log.review("hexrays-not-ported", "%s: %d Hex-Rays variable setting(s) at a location other than one stack slot or one register are not ported" % (
            what, other), ea, new)
    maps = mappings(lv)
    if maps:
        ctx.log.review("hexrays-not-ported", "%s: its %d Hex-Rays variable mapping(s) (merged variables) are not ported" % (what, maps), ea, new)
    if not out:
        return None
    return {"stkoff_delta": int(lv.stkoff_delta), "ulv_flags": int(lv.ulv_flags), "list": out}


def read_old(ea):
    hx = {}
    cmts = read_cmts(ea)
    if cmts:
        hx["cmts"] = [{"off": off, "itp": itp, "text": text} for (off, itp), text in sorted(cmts.items())]
    nfs = read_numforms(ea)
    if nfs:
        hx["numforms"] = [{"off": off, "opnum": opnum, "flags": v[0], "nf_opnum": v[1], "props": v[2], "serial": v[3], "nbytes": v[4], "type_name": v[5],
                           "types": type_closure(v[5]) if v[5] else {}} for (off, opnum), v in sorted(nfs.items())]
    unions = read_unions(ea)
    if unions:
        hx["unions"] = [{"off": off, "path": list(path)} for off, path in sorted(unions.items())]
    labels = read_labels(ea)
    if labels:
        hx["labels"] = [{"num": num, "name": name} for num, name in sorted(labels.items())]
    iflags = read_iflags(ea)
    if iflags:
        hx["iflags"] = [{"off": off, "op": op, "flags": flags} for (off, op), flags in sorted(iflags.items())]
    return hx


def why_not_certain(ctx, old, cls):
    if cls == "likely":
        return "one of several identical functions, Hex-Rays data is only ported to functions with a certain match"
    if cls == "changed":
        return "changed, %d%% similar; Hex-Rays data is only ported to functions with a certain match" % (ctx.pairing.rows[old].similarity or 0)
    return why_not(ctx, old)[1]


def export(ctx, dump):
    if not available():
        ctx.log.warn(NO_HEXRAYS % "read from the old database")
        return
    funcs, unions_read = dump["functions"], False
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        old = f.start_ea
        new = ctx.pairing.new_of(old)
        cls = ctx.pairing.classes.get(old)
        hx = read_old(old)
        what = label(ctx, old, ctx.owner_name(old, user_name(old)))
        if cls != "certain":
            lv = stored_lvars(old)
            if lv is not None and lv.lvvec.size():
                hx["lvars"] = {"list": [None] * lv.lvvec.size()}
            if hx:
                ctx.log.review("hexrays-not-ported", "%s: its Hex-Rays data (%s) is not ported: %s" % (
                    what, hexplan.count_text(hx), why_not_certain(ctx, old, cls)), old, new)
            continue
        labels = hx.pop("labels", None)
        if labels:
            ctx.log.review("hexrays-not-ported", "%s: %s" % (what, hexplan.labels_text(labels)), old, new)
        lvars = export_lvars(ctx, old, what, new)
        if lvars:
            hx["lvars"] = lvars
        if not hx:
            continue
        if hx.get("unions") and not unions_read:
            dump["union_types"], unions_read = union_types(), True
        hx["frame"] = frame_of(f)
        hx["ops"] = ops_of(f)
        funcs.setdefault(str(old), {})["hexrays"] = hx
        ctx.shape_wanted.add(old)


def review(ctx, what, old, new, kind, it, why, category="hexrays-skipped"):
    off = hexplan.off_of(kind, it) or 0
    text = "%s: %s: %s" % (what, hexplan.describe(kind, it), why) if category == "hexrays-differs" else "%s: %s is not ported: %s" % (
        what, hexplan.describe(kind, it), why)
    ctx.log.review(category, text, old + off, new + off if new is not None else None)


def skip_all(ctx, what, old, new, hx, why):
    for kind, it in hexplan.items_of(hx):
        review(ctx, what, old, new, kind, it, why)


def item_type_problem(kind, it, unions):
    if kind == "numforms" and it.get("type_name"):
        return dataplan.types_problem(it.get("types"), type_decl_of)
    if kind == "unions":
        return unions()
    return None


def lvar_type_problem(it):
    problem = dataplan.types_problem(it.get("types"), type_decl_of)
    if problem:
        return problem
    tif = parse(it.get("decl"))
    if tif is None:
        return "IDA cannot parse %s in the new database" % (it.get("decl") or "it")
    got = text_of(tif)
    return None if got == it["type"] else "it reads as %s in the new database" % got


def write_kind(ctx, what, old, new, kind, items):
    have = READERS[kind](new)
    want = [(hexplan.key_of(kind, it), hexplan.value_of(kind, it), it) for it in items]
    result, added, notes = hexplan.merge(kind, have, want)
    for it, category, why in notes:
        review(ctx, what, old, new, kind, it, why, category)
    if not added:
        return
    SAVERS[kind](new, result)
    if READERS[kind](new) == result:
        ctx.log.ported(hexplan.COUNTERS[kind], added)
        return
    SAVERS[kind](new, have)
    restored = READERS[kind](new) == have
    warn_failed(ctx, what, old, new, kind, [it for key, _v, it in want if key not in have and key in result], restored)


def warn_failed(ctx, what, old, new, kind, items, restored):
    ctx.log.warn("%s (0x%X): IDA did not keep its %d %s; %s" % (what, new, len(items), hexplan.NOUNS[kind],
                 "the earlier ones were restored" if restored else "the earlier ones could not be restored, check them by hand"))
    for it in items:
        review(ctx, what, old, new, kind, it, "IDA did not keep it", "hexrays-failed")


def same_lvars(a, b):
    return a is not None and b is not None and (a["delta"], a["flags"], a["items"]) == (b["delta"], b["flags"], b["items"])


def new_saved_info(ea, key, fields, decls):
    s = ida_hexrays.lvar_saved_info_t()
    loc = ida_hexrays.lvar_locator_t()
    vd = ida_hexrays.vdloc_t()
    if key[0][0] == "stk":
        vd.set_stkoff(key[0][1])
    else:
        vd.set_reg1(key[0][1])
    loc.location = vd
    loc.defea = BADADDR if key[1] is None else ea + key[1]
    s.ll = loc
    s.flags = fields["flags"]
    set_fields(s, fields, decls.get(key))
    return s


def set_fields(s, fields, decl):
    s.name = fields["name"] or ""
    s.cmt = fields["cmt"] or ""
    s.size = fields["size"]
    if fields["type"] and (s.type.empty() or text_of(s.type) != fields["type"]):
        tif = parse(decl)
        if tif is not None:
            s.type = tif


def save_lvars(ea, result, decls):
    lv = stored_lvars(ea) or ida_hexrays.lvar_uservec_t()
    seen, other = set(), 0
    for k in range(lv.lvvec.size()):
        s = lv.lvvec[k]
        key = lvar_key(s, ea, other)
        if key[0][0] == "other":
            other += 1
        seen.add(key)
        if key in result["items"] and result["items"][key] != lvar_fields(s):
            set_fields(s, result["items"][key], decls.get(key))
    for key, fields in result["items"].items():
        if key not in seen:
            lv.lvvec.push_back(new_saved_info(ea, key, fields, decls))
    lv.stkoff_delta = result["delta"]
    lv.ulv_flags = result["flags"]
    ida_hexrays.save_user_lvar_settings(ea, lv)


def write_lvars(ctx, what, old, new, hx, items):
    header = {"delta": hx["lvars"]["stkoff_delta"], "flags": hx["lvars"]["ulv_flags"]}
    wanted, decls = [], {}
    for it in items:
        fields = hexplan.value_of("lvars", it)
        key = hexplan.key_of("lvars", it)
        if fields["type"]:
            why = lvar_type_problem(it)
            if why:
                ctx.log.review("hexrays-skipped", "%s: the type %s of %s is not ported: %s" % (what, fields["type"], hexplan.describe("lvars", it), why),
                               old + (it["defoff"] or 0), new + (it["defoff"] or 0))
                fields = hexplan.without_type(fields)
            else:
                decls[key] = it["decl"]
        wanted.append((key, fields, it))
    have = read_lvars(new)
    original = stored_lvars(new)
    result, changed, notes = hexplan.merge_lvars(have, header, wanted)
    for it, category, why in notes:
        review(ctx, what, old, new, "lvars", it, why, category)
    if not changed:
        return
    save_lvars(new, result, decls)
    if same_lvars(read_lvars(new), result):
        ctx.log.ported(hexplan.COUNTERS["lvars"], changed)
        return
    ida_hexrays.save_user_lvar_settings(new, original if original is not None else ida_hexrays.lvar_uservec_t())
    after = read_lvars(new)
    restored = same_lvars(after, have) if have is not None else after is None
    failed = [it for key, fields, it in wanted if key in result["items"] and (have is None or result["items"][key] != have["items"].get(key))]
    warn_failed(ctx, what, old, new, "lvars", failed, restored)


def apply_function(ctx, old, entry, unions):
    hx = entry["hexrays"]
    what = label(ctx, old, entry.get("name"))
    labels = hx.get("labels")
    if labels:
        ctx.log.review("hexrays-not-ported", "%s: %s" % (what, hexplan.labels_text(labels)), old, ctx.new_start(old))
    if ctx.pairing.classes.get(old) != "certain":
        skip_all(ctx, what, old, ctx.new_start(old), hx, "the function has no certain match")
        return
    new = ctx.new_function(old, what)
    if new is None:
        skip_all(ctx, what, old, ctx.new_start(old), hx, "there is no function at its address in the new database")
        return
    if not ctx.gate_ok(old):
        skip_all(ctx, what, old, new, hx, GATE_FAILED if old in ctx.gate else "its instructions were not compared")
        return
    f = func_at(new)
    old_insns, new_insns = hexplan.insn_map(entry.get("shape") or {}), hexplan.insn_map(feat_insn.shape_of(f))
    exact = hexplan.exact_problem(hx, frame_of(f), ops_of(f))
    placed = {}
    for kind, it in hexplan.items_of(hx):
        why = exact if kind in hexplan.EXACT and exact else hexplan.place_problem(kind, it, old_insns, new_insns) or item_type_problem(kind, it, unions)
        if why:
            review(ctx, what, old, new, kind, it, why)
        else:
            placed.setdefault(kind, []).append(it)
    for kind in hexplan.KINDS:
        if placed.get(kind):
            write_kind(ctx, what, old, new, kind, placed[kind])
    if placed.get("lvars"):
        write_lvars(ctx, what, old, new, hx, placed["lvars"])


def apply(ctx, dump):
    funcs = dump.get("functions", {})
    keys = [k for k in sorted(funcs, key=int) if funcs[k].get("hexrays")]
    if not keys:
        return
    if not available():
        ctx.log.warn(NO_HEXRAYS % "ported to the new database")
        for key in keys:
            old = int(key)
            skip_all(ctx, label(ctx, old, funcs[key].get("name")), old, ctx.new_start(old), funcs[key]["hexrays"], "the Hex-Rays decompiler is not available")
        return
    union_problem = []

    def unions():
        if not union_problem:
            union_problem.append(dataplan.types_problem(dump.get("union_types"), type_decl_of))
        return union_problem[0]

    for key in keys:
        apply_function(ctx, int(key), funcs[key], unions)
