import ida_bytes
import ida_funcs
import ida_idaapi
import ida_name
import ida_nalt
import ida_segment
import idautils

import baseline as baselines
import dataplan
import insnplan
from feat_names import SN
from feat_protos import decl_text, set_type, stored, text_of, type_closure, type_decl_of

BADADDR = ida_idaapi.BADADDR
NO_BASELINE = "no baseline: data names, comments and types are not ported, because IDA-made ones cannot be told from yours"
RPT = {"cmt": False, "rptcmt": True}
WORDS = {"name": "name", "cmt": "comment", "rptcmt": "repeatable comment", "type": "type"}
COUNTERS = {"cmt": "data comments", "rptcmt": "repeatable data comments"}
UNKNOWN = "it is on undefined bytes; only defined data items are ported"
TAIL = "it is inside another item; only the start of a data item is ported"
IN_FUNCTION = "it is data inside a function; only data outside functions is ported"


def data_items():
    for i in range(ida_segment.get_segm_qty()):
        seg = ida_segment.getnseg(i)
        for ea in idautils.Heads(seg.start_ea, seg.end_ea):
            fl = ida_bytes.get_flags(ea)
            if not ida_bytes.is_code(fl) and ida_funcs.get_fchunk(ea) is None:
                yield ea, fl


def extra_items():
    for ea, _name in idautils.Names():
        fl = ida_bytes.get_flags(ea)
        if not ida_bytes.has_user_name(fl) or ida_bytes.is_code(fl):
            continue
        if not ida_bytes.is_head(fl):
            yield ea, fl, UNKNOWN if ida_bytes.is_unknown(fl) else TAIL
        elif ida_funcs.get_fchunk(ea) is not None:
            yield ea, fl, IN_FUNCTION


def record_at(ea, fl):
    rec = {}
    if ida_bytes.has_user_name(fl):
        rec["name"] = ida_name.get_name(ea)
    if ida_bytes.has_cmt(fl):
        for kind, rpt in RPT.items():
            text = ida_bytes.get_cmt(ea, rpt)
            if text:
                rec[kind] = text
    if ida_nalt.get_aflags(ea) & ida_nalt.AFL_TI:
        text = text_of(stored(ea))
        if text:
            rec["type"] = text
    return rec


def records():
    out = {}
    for ea, fl in list(data_items()) + [(ea, fl) for ea, fl, _why in extra_items()]:
        rec = record_at(ea, fl)
        if rec:
            out[str(ea)] = rec
    return out


def data_refs_from(ea):
    return sorted({t for t in idautils.DataRefsFrom(ea) if ida_segment.getseg(t) is not None})


def ref_kind(ctx, x, ea):
    if x.iscode:
        return "jump", None
    f = ida_funcs.get_func(x.frm)
    if f is None:
        return ("code" if ida_bytes.is_code(ida_bytes.get_flags(x.frm)) else "data"), None
    if data_refs_from(x.frm) != [ea]:
        return "ambiguous", None
    cls = ctx.pairing.classes.get(f.start_ea)
    if cls == "certain":
        return None, (f.start_ea, x.frm - f.start_ea)
    return ("likely" if cls == "likely" else "unmatched" if cls is None else "changed"), None


def refs_of(ctx, ea):
    refs, counts = set(), {}
    for x in idautils.XrefsTo(ea, 0):
        kind, ref = ref_kind(ctx, x, ea)
        if ref is not None:
            refs.add(ref)
        else:
            counts[kind] = counts.get(kind, 0) + 1
    return [list(r) for r in dataplan.cap_refs(refs)], counts


def export(ctx, dump):
    if not baselines.has_data(ctx.baseline):
        ctx.log.warn(NO_BASELINE)
        return
    out = dump["data"]
    for ea, fl in data_items():
        rec = record_at(ea, fl)
        if not rec:
            continue
        base = baselines.data_record(ctx.baseline, ea)
        owner = dataplan.owner_data(rec, base, ida_nalt.is_userti(ea))
        if owner is None:
            continue
        what = dataplan.label(owner["name"] or ida_name.get_name(ea), ea)
        refs, counts = refs_of(ctx, ea)
        if not refs:
            parts = ", ".join(WORDS[k] for k in dataplan.KINDS if owner[k])
            ctx.log.review("data-not-ported", "%s: not ported (%s): %s" % (what, parts, dataplan.unported_reason(counts)), ea)
            continue
        item = dict(owner, ea=ea, refs=refs, size=ida_bytes.get_item_size(ea))
        ida = dataplan.ida_values(owner, base)
        if ida:
            item["ida"] = ida
        if owner["type"]:
            item["type_decl"] = decl_text(stored(ea))
            item["types"] = type_closure(owner["type"])
        out.append(item)
        ctx.shape_wanted.update(r[0] for r in refs)
    for ea, fl, why in extra_items():
        owner = dataplan.owner_data(record_at(ea, fl), baselines.data_record(ctx.baseline, ea), ida_nalt.is_userti(ea))
        if owner is not None:
            parts = ", ".join(WORDS[k] for k in dataplan.KINDS if owner[k])
            ctx.log.review("data-not-ported", "%s: not ported (%s): %s" % (dataplan.label(owner["name"] or ida_name.get_name(ea), ea), parts, why), ea)


def targets_of(ctx):
    def get(func, off):
        new = ctx.new_start(func)
        return data_refs_from(new + off) if new is not None else []
    return get


def where_problem(new, size):
    fl = ida_bytes.get_flags(new)
    if not ida_bytes.is_head(fl) or ida_bytes.is_code(fl) or ida_funcs.get_fchunk(new) is not None:
        return "0x%X in the new database is not the start of a data item" % new
    return dataplan.size_problem(size, ida_bytes.get_item_size(new))


def apply_name(ctx, d, old, new):
    want = d.get("name")
    if not want:
        return
    have = ida_name.get_name(new)
    at = ida_name.get_name_ea(BADADDR, want)
    action = dataplan.name_action(have, ida_bytes.has_user_name(ida_bytes.get_flags(new)), want, None if at == BADADDR else at, new)
    if action == "set" and not ida_name.set_name(new, want, SN):
        at = ida_name.get_name_ea(BADADDR, want)
        action = "in-use" if at != BADADDR and at != new else "refused"
    if action == "in-use":
        ctx.log.review("name-in-use", "%s is already the name of 0x%X in the new database, not applied" % (want, at), old, new)
    elif action == "refused":
        ctx.log.review("name-refused", "IDA refused the name %s" % want, old, new)
    elif action == "keep":
        ctx.log.review("data-differs", "%s: the data item at 0x%X is already named %s, kept" % (want, new, have), old, new)
    else:
        ctx.log.ported("data names")


def apply_cmts(ctx, d, old, new, what):
    for kind, rpt in RPT.items():
        want = d.get(kind)
        if not want:
            continue
        action = insnplan.decide(ida_bytes.get_cmt(new, rpt), want, (d.get("ida") or {}).get(kind))
        if action == "set" and not ida_bytes.set_cmt(new, want, rpt):
            ctx.log.warn("cannot set the %s at 0x%X" % (WORDS[kind], new))
        elif action == "keep":
            ctx.log.review("data-differs", "%s: the data item at 0x%X already has another %s, kept" % (what, new, WORDS[kind]), old, new)
        else:
            ctx.log.ported(COUNTERS[kind])


def apply_type(ctx, d, old, new, what):
    want = d.get("type")
    if not want:
        return
    have = text_of(stored(new))
    action = dataplan.type_action(have, ida_nalt.is_userti(new), want, (d.get("ida") or {}).get("type"))
    if action == "keep":
        ctx.log.review("data-differs", "%s: the data item at 0x%X already has the type %s, kept" % (what, new, have), old, new)
        return
    why = set_type(ctx, new, want, d.get("type_decl"), d.get("types"), d.get("size")) if action == "set" else None
    if why:
        ctx.log.review("data-skipped", "%s: its type %s is not ported: %s" % (what, want, why), old, new)
    else:
        ctx.log.ported("data types")


def apply(ctx, dump):
    get = targets_of(ctx)
    items = dump.get("data", [])
    mapped = [dataplan.map_target(d.get("refs") or [], ctx.gate_ok, get) for d in items]
    shared = dataplan.shared_targets([(i, new) for i, (new, _) in enumerate(mapped)])
    claims = {i: new for new, keys in shared.items() for i in keys}
    for i, d in enumerate(items):
        old = d["ea"]
        what = dataplan.label(d.get("name"), old)
        new, why = mapped[i]
        if i in claims:
            others = [dataplan.label(items[k].get("name") and "%s at 0x%X" % (items[k]["name"], items[k]["ea"]), items[k]["ea"]) for k in shared[new] if k != i]
            why = dataplan.shared_reason(new, others)
        elif new is not None:
            why = where_problem(new, d.get("size"))
        if why:
            ctx.log.review("data-skipped", "%s: not ported: %s" % (what, why), old, new)
            continue
        apply_name(ctx, d, old, new)
        apply_cmts(ctx, d, old, new, what)
        apply_type(ctx, d, old, new, what)
