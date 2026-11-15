import ida_bytes
import ida_funcs
import ida_idaapi
import ida_nalt
import ida_typeinf

import baseline as baselines
import dataplan
import feat_types
from feat_names import label, user_name, why_not

PR = ida_typeinf.PRTYPE_1LINE
DECL_NAME = "__exed"
NO_BASELINE = "no baseline: function prototypes are not ported, because IDA-made ones cannot be told from yours"


def stored(ea):
    t = ida_typeinf.tinfo_t()
    return t if ida_nalt.get_tinfo(t, ea) else None


def text_of(tif):
    if tif is None:
        return None
    return ida_typeinf.print_tinfo("", 0, 0, PR, tif, "", "") or None


def decl_text(tif):
    return ida_typeinf.print_tinfo("", 0, 0, PR | ida_typeinf.PRTYPE_SEMI, tif, DECL_NAME, "") or None


def type_decl_of(name):
    have = feat_types.existing(ida_typeinf.get_idati(), name) if name else None
    return None if have is None else (have[0] or "")


_odd = []


def type_closure(text):
    if not _odd:
        _odd.append(feat_types.odd_names())
    return dataplan.closure(text, type_decl_of, _odd[0])


def parse(decl):
    t = ida_typeinf.tinfo_t()
    if not decl or ida_typeinf.parse_decl(t, None, decl, ida_typeinf.PT_SIL) is None or t.empty():
        return None
    return t


def snapshot(ea):
    return {"tif": stored(ea), "user": ida_nalt.is_userti(ea), "dt": ida_bytes.get_flags(ea) & ida_bytes.DT_TYPE, "size": ida_bytes.get_item_size(ea)}


def same_state(ea, snap):
    return (text_of(stored(ea)) == text_of(snap["tif"]) and ida_nalt.is_userti(ea) == snap["user"]
            and ida_bytes.get_flags(ea) & ida_bytes.DT_TYPE == snap["dt"] and ida_bytes.get_item_size(ea) == snap["size"])


def restore(ea, snap):
    ida_nalt.del_tinfo(ea)
    if snap["tif"] is not None:
        ida_typeinf.apply_tinfo(ea, snap["tif"], ida_typeinf.TINFO_DEFINITE if snap["user"] else ida_typeinf.TINFO_GUESSED)
    if ida_funcs.get_func(ea) is None and (ida_bytes.get_flags(ea) & ida_bytes.DT_TYPE != snap["dt"] or ida_bytes.get_item_size(ea) != snap["size"]):
        ida_bytes.del_items(ea, ida_bytes.DELIT_SIMPLE, ida_bytes.get_item_size(ea))
        ida_bytes.create_data(ea, snap["dt"], snap["size"], ida_idaapi.BADADDR)
    return same_state(ea, snap)


def kept(ea, want, size):
    return text_of(stored(ea)) == want and ida_nalt.is_userti(ea) and (size is None or ida_bytes.get_item_size(ea) == size)


def set_type(ctx, ea, want, decl, types, size=None):
    problem = dataplan.types_problem(types, type_decl_of)
    if problem:
        return problem
    tif = parse(decl)
    if tif is None:
        return "IDA cannot parse %s in the new database" % (decl or "it")
    got = text_of(tif)
    if got != want:
        return "it reads as %s in the new database" % got
    if size is None and not tif.is_func():
        return "it is not a function type in the new database"
    if size is not None and tif.get_size() != size:
        return "the type is %d byte(s) in the new database, the data item is %d" % (tif.get_size(), size)
    snap = snapshot(ea)
    if ida_typeinf.apply_tinfo(ea, tif, ida_typeinf.TINFO_DEFINITE) and kept(ea, want, size):
        return None
    if restore(ea, snap):
        return "IDA did not keep it"
    ctx.log.warn("0x%X: IDA did not keep the type %s and the earlier type could not be restored, check it by hand" % (ea, want))
    return "IDA did not keep it; the earlier type could not be restored"


def records():
    out = {}
    for i in range(ida_funcs.get_func_qty()):
        ea = ida_funcs.getn_func(i).start_ea
        text = text_of(stored(ea))
        if text:
            out[str(ea)] = text
    return out


def why_not_certain(ctx, old, cls):
    if cls == "likely":
        return "one of several identical functions, prototypes are never ported to those"
    if cls == "changed":
        return "changed, %d%% similar; prototypes are only ported to functions with a certain match" % (ctx.pairing.rows[old].similarity or 0)
    return why_not(ctx, old)[1]


def export(ctx, dump):
    if not baselines.has_protos(ctx.baseline):
        ctx.log.warn(NO_BASELINE)
        return
    funcs = dump["functions"]
    for i in range(ida_funcs.get_func_qty()):
        old = ida_funcs.getn_func(i).start_ea
        if not ida_nalt.is_userti(old):
            continue
        tif = stored(old)
        if tif is None:
            continue
        text = text_of(tif)
        ida = baselines.proto_record(ctx.baseline, old)
        if text is not None and text == ida:
            continue
        what = label(ctx, old, ctx.owner_name(old, user_name(old)))
        cls = ctx.pairing.classes.get(old)
        decl = decl_text(tif)
        if cls == "certain" and text and decl:
            entry = funcs.setdefault(str(old), {})
            entry.update(proto=text, proto_decl=decl, proto_types=type_closure(text))
            if ida:
                entry["proto_ida"] = ida
            ctx.shape_wanted.add(old)
            continue
        why = why_not_certain(ctx, old, cls) if cls != "certain" else "IDA cannot print it in the old database"
        ctx.log.review("proto-not-ported", "%s: its prototype %s is not ported: %s" % (what, text, why), old, ctx.pairing.new_of(old))


def skip(ctx, category, what, text, why, old, new):
    ctx.log.review(category, "%s: its prototype %s is not ported: %s" % (what, text, why), old, new)


def apply(ctx, dump):
    funcs = dump.get("functions", {})
    for key in sorted(funcs, key=int):
        entry = funcs[key]
        text = entry.get("proto")
        if not text:
            continue
        old = int(key)
        what = label(ctx, old, entry.get("name"))
        if ctx.pairing.classes.get(old) != "certain":
            skip(ctx, "proto-skipped", what, text, "the function has no certain match", old, ctx.new_start(old))
            continue
        new = ctx.new_function(old, what)
        if new is None:
            skip(ctx, "proto-skipped", what, text, "there is no function at its address in the new database", old, ctx.new_start(old))
            continue
        if not ctx.gate_ok(old):
            why = "the function's instructions differ in the new database (gate-failed)" if old in ctx.gate else "its instructions were not compared"
            skip(ctx, "proto-skipped", what, text, why, old, new)
            continue
        have = text_of(stored(new))
        action = dataplan.type_action(have, ida_nalt.is_userti(new), text, entry.get("proto_ida"))
        if action == "keep":
            ctx.log.review("proto-differs", "%s: the new function already has the prototype %s, kept" % (what, have), old, new)
            continue
        why = set_type(ctx, new, text, entry.get("proto_decl"), entry.get("proto_types")) if action == "set" else None
        if why:
            skip(ctx, "proto-failed", what, text, why, old, new)
        else:
            ctx.log.ported("function prototypes")
