import hashlib

import ida_bytes
import ida_funcs
import ida_idaapi
import ida_lines
import ida_segment
import ida_typeinf
import ida_ua
import idautils

import align
import baseline as baselines
import dataplan
import feat_types
import insnplan
from feat_names import func_at, label, user_name, why_not
from feat_protos import type_closure

BADADDR = ida_idaapi.BADADDR
OP_MASKS = [ida_bytes.MS_N_TYPE << ida_bytes.get_operand_type_shift(n) for n in range(8)]
ANY_OP = 0
for _mask in OP_MASKS:
    ANY_OP |= _mask
RADIX = {16: "hex", 10: "dec", 8: "oct", 2: "bin"}
SETTERS = {"hex": ida_bytes.op_hex, "dec": ida_bytes.op_dec, "oct": ida_bytes.op_oct, "bin": ida_bytes.op_bin, "char": ida_bytes.op_chr}
LINES = {"ant": ida_lines.E_PREV, "post": ida_lines.E_NEXT}
NO_BASELINE = "no baseline: instruction comments and operand formats are not ported, because IDA-made ones cannot be told from yours"


def extra_lines(ea, base):
    out = []
    while True:
        line = ida_lines.get_extra_cmt(ea, base + len(out))
        if line is None:
            return out
        out.append(line)


def op_desc(ea, n, fl=None):
    fl = ida_bytes.get_flags(ea) if fl is None else fl
    if not ida_bytes.is_defarg(fl, n):
        return None
    if ida_bytes.is_enum(fl, n):
        tid, serial = ida_bytes.get_enum_id(ea, n)
        name = ida_typeinf.get_tid_name(tid) if tid != BADADDR else None
        return insnplan.desc("enum", name, serial=serial) if name else insnplan.desc("other")
    if ida_bytes.is_stroff(fl, n):
        path, delta = ida_bytes.get_stroff_path(ea, n)
        names = [ida_typeinf.get_tid_name(t) for t in path or []]
        return insnplan.desc("stroff", path=names, delta=delta or 0) if names and all(names) else insnplan.desc("other")
    if ida_bytes.is_char(fl, n):
        return insnplan.desc("char")
    if ida_bytes.is_numop(fl, n) and ida_bytes.get_radix(fl, n) in RADIX:
        return insnplan.desc(RADIX[ida_bytes.get_radix(fl, n)])
    return insnplan.desc("other")


def has_data(fl):
    return ida_bytes.has_cmt(fl) or ida_bytes.has_extra_cmts(fl) or bool(fl & ANY_OP)


def record_at(ea, fl=None):
    fl = ida_bytes.get_flags(ea) if fl is None else fl
    rec = {}
    if ida_bytes.has_cmt(fl):
        for kind, rpt in (("cmt", False), ("rpt", True)):
            text = ida_bytes.get_cmt(ea, rpt)
            if text:
                rec[kind] = text
    if ida_bytes.has_extra_cmts(fl):
        for kind, base in LINES.items():
            lines = extra_lines(ea, base)
            if lines:
                rec[kind] = lines
    ops = {}
    for n, mask in enumerate(OP_MASKS):
        if fl & mask:
            d = op_desc(ea, n, fl)
            if d is not None and d["fmt"] in insnplan.FORMATS:
                ops[str(n)] = d
    if ops:
        rec["ops"] = ops
    return rec


def items_of(f):
    return sorted(set(idautils.FuncItems(f.start_ea)))


def records():
    out = {}
    for i in range(ida_funcs.get_func_qty()):
        for ea in items_of(ida_funcs.getn_func(i)):
            fl = ida_bytes.get_flags(ea)
            if has_data(fl):
                rec = record_at(ea, fl)
                if rec:
                    out[str(ea)] = rec
    return out


def optypes(insn):
    out = []
    for k in range(8):
        if insn.ops[k].type == ida_ua.o_void:
            break
        out.append(insn.ops[k].type)
    return out


def target_of(insn):
    for k in range(8):
        op = insn.ops[k]
        if op.type == ida_ua.o_void:
            return None
        if op.type in (ida_ua.o_near, ida_ua.o_far):
            g = ida_funcs.get_func(op.addr)
            return g.start_ea if g is not None else None
        if op.type == ida_ua.o_mem and func_at(op.addr) is not None:
            return op.addr
    return None


def _ch(x):
    return ord(x) if isinstance(x, str) else int(x)


def _value(v):
    return None if ida_segment.getseg(v) is not None else int(v)


def op_key(insn):
    rows = []
    for k in range(8):
        op = insn.ops[k]
        if op.type == ida_ua.o_void:
            break
        row = [_ch(op.type), _ch(op.dtype)]
        if op.type in (ida_ua.o_reg, ida_ua.o_phrase, ida_ua.o_displ):
            row.append(int(op.reg))
        if op.type in (ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_mem):
            row += [_ch(op.specflag1), _ch(op.specflag2)]
        if op.type in (ida_ua.o_phrase, ida_ua.o_displ):
            row.append(_value(op.addr))
        if op.type == ida_ua.o_imm:
            row.append(_value(op.value))
        rows.append(row)
    return hashlib.sha1(repr(rows).encode("ascii")).hexdigest()[:8]


def shape_of(f, keys=False):
    insn = ida_ua.insn_t()
    out = []
    for ea in items_of(f):
        if ida_ua.decode_insn(insn, ea) > 0:
            row = [ea - f.start_ea, insn.size, insn.get_canon_mnem(), optypes(insn), target_of(insn)]
            if keys:
                row.append(op_key(insn))
        else:
            row = [ea - f.start_ea, ida_bytes.get_item_size(ea), "", [], None]
            if keys:
                row.append(None)
        out.append(row)
    return {"frsize": f.frsize, "argsize": f.argsize, "insns": out}


def decl_of(name):
    have = feat_types.existing(ida_typeinf.get_idati(), name) if name else None
    return (have[0] or None) if have is not None else None


def owner_items(ctx, f):
    out = []
    for ea in items_of(f):
        fl = ida_bytes.get_flags(ea)
        if has_data(fl):
            rec = record_at(ea, fl)
            if rec:
                out += insnplan.owner_items(ea - f.start_ea, rec, baselines.insn_record(ctx.baseline, ea))
    for it in out:
        names = insnplan.type_names(it)
        if names:
            decls = {}
            for name in names:
                decls.update(type_closure(name))
            decls.update({name: decl_of(name) for name in names})
            it["decls"] = decls
    return out


def export(ctx, dump):
    if not baselines.has_insn(ctx.baseline):
        ctx.log.warn(NO_BASELINE)
        return
    funcs = dump["functions"]
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        old = f.start_ea
        items = owner_items(ctx, f)
        if not items:
            continue
        cls = ctx.pairing.classes.get(old)
        if ctx.ported(old) and cls != "likely":
            funcs.setdefault(str(old), {})["insn"] = items
            ctx.shape_wanted.add(old)
            continue
        why = "one of several identical functions, instruction data is never ported to those" if cls == "likely" else why_not(ctx, old)[1]
        ctx.log.review("insn-not-ported", "%s: %d instruction comment(s) or operand format(s) not ported: %s" % (
            label(ctx, old, ctx.owner_name(old, user_name(old))), len(items), why), old, ctx.pairing.new_of(old))


def export_shapes(ctx, dump):
    for old in sorted(ctx.shape_wanted):
        f = func_at(old)
        if f is not None:
            dump["functions"].setdefault(str(old), {})["shape"] = shape_of(f, keys=ctx.pairing.classes.get(old) != "certain")


def skip(ctx, what, old, new, it, why, new_off=None):
    ctx.log.review("insn-skipped", "%s: the %s at +0x%X is not ported: %s" % (what, insnplan.describe(it), it["off"], why),
                   old + it["off"], new + new_off if new is not None and new_off is not None else None)


def set_lines(ea, base, want, had):
    for k, line in enumerate(want):
        ida_lines.update_extra_cmt(ea, base + k, line)
    for k in range(len(want), had):
        ida_lines.del_extra_cmt(ea, base + k)
    return extra_lines(ea, base) == want


def set_format(ea, n, want, insn):
    fmt = want.get("fmt")
    if fmt in SETTERS:
        return None if SETTERS[fmt](ea, n) else "IDA refused it"
    if fmt == "enum":
        tid = ida_typeinf.get_named_type_tid(want.get("arg") or "")
        if tid == BADADDR:
            return "the enum %s is not in the new database" % want.get("arg")
        return None if ida_bytes.op_enum(ea, n, tid, want.get("serial", 0)) else "IDA refused it"
    if fmt == "stroff":
        path = want.get("path") or []
        tids = [ida_typeinf.get_named_type_tid(name) for name in path]
        missing = [name for name, tid in zip(path, tids) if tid == BADADDR]
        if missing or not tids:
            return "the struct %s is not in the new database" % ", ".join(missing or path)
        return None if ida_bytes.op_stroff(insn, n, tids, want.get("delta", 0)) else "IDA refused it"
    return "the format %s is unknown" % fmt


def apply_cmt(ctx, ea, it):
    kind, want = it["kind"], insnplan.want_of(it)
    if kind in ("cmt", "rpt"):
        action = insnplan.decide(ida_bytes.get_cmt(ea, kind == "rpt"), want, it.get("ida"))
        if action == "set" and not ida_bytes.set_cmt(ea, want, kind == "rpt"):
            return "warn"
        return action
    have = extra_lines(ea, LINES[kind])
    action = insnplan.decide(have, want, it.get("ida"))
    if action == "set" and not set_lines(ea, LINES[kind], want, len(have)):
        return "warn"
    return action


def apply_format(ctx, ea, it, old_types):
    n, want = it["opn"], insnplan.want_of(it)
    insn = ida_ua.insn_t()
    types = optypes(insn) if ida_ua.decode_insn(insn, ea) > 0 else []
    if n >= len(types) or n >= len(old_types) or types[n] != old_types[n]:
        return "skip", "the operand type differs in the new instruction"
    have = op_desc(ea, n)
    action = insnplan.decide(have, want, it.get("ida"))
    if action != "set":
        return action, None
    problem = insnplan.type_problem(it, decl_of)
    if problem:
        return "skip", problem
    why = set_format(ea, n, want, insn)
    if why is None and op_desc(ea, n) == want:
        return "set", None
    if have:
        set_format(ea, n, have, insn)
    else:
        ida_bytes.clr_op_type(ea, n)
    return "skip", why or "IDA did not keep it"


def apply_item(ctx, what, old, new, it, new_off, old_types):
    ea = new + new_off
    if it["kind"] == "opfmt":
        action, why = apply_format(ctx, ea, it, old_types.get(it["off"], []))
        counter = "operand formats"
    else:
        action, why = apply_cmt(ctx, ea, it), None
        counter = "instruction comments"
    if action == "skip":
        skip(ctx, what, old, new, it, why, new_off)
    elif action == "warn":
        ctx.log.warn("cannot set the %s at 0x%X" % (insnplan.describe(it), ea))
    elif action == "keep":
        ctx.log.review("insn-differs", "%s: the instruction at +0x%X already has another %s, kept" % (what, new_off, insnplan.describe(it)),
                       old + it["off"], ea)
    else:
        ctx.log.ported(counter)


def apply(ctx, dump):
    funcs = dump.get("functions", {})
    paired_new = {row.new_va for row in ctx.pairing.rows.values()}
    for key in sorted(funcs, key=int):
        entry = funcs[key]
        shape = entry.get("shape")
        old = int(key)
        cls = ctx.pairing.classes.get(old)
        if shape is None or not ctx.ported(old) or cls == "likely":
            continue
        what = label(ctx, old, entry.get("name"))
        noted = dataplan.has_annotation(entry)
        new = ctx.new_function(old, what, quiet=not noted)
        if new is None:
            continue
        items = entry.get("insn", [])
        new_shape = shape_of(func_at(new), keys=cls != "certain")
        if cls == "certain":
            ok, why = align.shapes_match(shape, new_shape, ctx.new_start, paired_new.__contains__)
            ctx.gate[old] = ok
            if not ok and not noted:
                continue
            if not ok:
                tail = "; its %d instruction item(s) are not ported" % len(items) if items else ""
                ctx.log.review("gate-failed", "%s: %s%s" % (what, why, tail), old, new)
                for it in items:
                    skip(ctx, what, old, None, it, "the function's instructions differ in the new database (gate-failed)")
                continue
        placed, skipped = insnplan.plan(items, shape, new_shape, cls == "certain")
        for it, why, new_off in skipped:
            skip(ctx, what, old, new, it, why, new_off)
        old_types = {x[0]: x[3] for x in shape["insns"]}
        for it, new_off in placed:
            apply_item(ctx, what, old, new, it, new_off, old_types)
