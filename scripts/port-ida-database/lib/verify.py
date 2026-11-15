import ida_funcs
import ida_hexrays
import ida_nalt

import baseline as baselines
import portlog
import pseudo
from feat_names import func_at, label
from feat_protos import stored

NO_HEXRAYS = "the Hex-Rays decompiler is not available: -Verify cannot compare the pseudocode (%s)"
NO_BASELINE = "-Verify: without a baseline the prototypes Hex-Rays guessed in the old database are kept, so more pseudocode may differ"


def available():
    try:
        return bool(ida_hexrays.init_hexrays_plugin())
    except Exception:
        return False


def decompile(ea):
    hf = ida_hexrays.hexrays_failure_t()
    try:
        cf = ida_hexrays.decompile(ea, hf)
    except Exception as e:
        return None, str(e) or type(e).__name__
    if cf is None:
        return None, hf.desc() or "decompilation failed"
    return str(cf), None


def wanted(dump):
    funcs = dump.get("functions", {})
    return sorted((int(k) for k, e in funcs.items() if e.get("hexrays") or e.get("proto")))


def forget_guessed(ctx):
    n = 0
    for i in range(ida_funcs.get_func_qty()):
        ea = ida_funcs.getn_func(i).start_ea
        if ida_nalt.is_userti(ea) or stored(ea) is None or baselines.proto_record(ctx.baseline, ea) is not None:
            continue
        ida_nalt.del_tinfo(ea)
        n += 1
    return n


def export(ctx, dump):
    if not ctx.verify:
        return 0
    todo = wanted(dump)
    if not todo:
        return 0
    if not available():
        ctx.log.warn(NO_HEXRAYS % "old database")
        return 0
    if baselines.has_protos(ctx.baseline):
        forget_guessed(ctx)
    else:
        ctx.log.warn(NO_BASELINE)
    funcs = dump["functions"]
    done = 0
    for old in todo:
        entry = funcs[str(old)]
        text, why = decompile(old) if func_at(old) else (None, "not a function")
        entry["pseudo"] = text
        if text is None:
            ctx.log.review("pseudo-not-checked", "%s: cannot decompile it in the old database: %s" % (label(ctx, old, entry.get("name")), why),
                           old, ctx.pairing.new_of(old))
        else:
            done += 1
    return done


def verify(ctx, dump, skip):
    todo = [old for old in wanted(dump) if dump["functions"][str(old)].get("pseudo") and old not in skip]
    if not todo:
        return 0
    if not available():
        ctx.log.warn(NO_HEXRAYS % "new database")
        return 0
    compared = 0
    for old in todo:
        entry = dump["functions"][str(old)]
        what = label(ctx, old, entry.get("name"))
        new = ctx.pairing.new_of(old)
        if new is None or func_at(new) is None:
            ctx.log.review("pseudo-not-checked", "%s: no function at the new address" % what, old, new)
            continue
        text, why = decompile(new)
        if text is None:
            ctx.log.review("pseudo-not-checked", "%s: cannot decompile it in the new database: %s" % (what, why), old, new)
            continue
        compared += 1
        diff = pseudo.first_difference(pseudo.normalise(entry["pseudo"]), pseudo.normalise(text))
        if diff:
            ctx.log.review(portlog.MISMATCH, "%s: the pseudocode differs, %s" % (what, diff), old, new)
    return compared
