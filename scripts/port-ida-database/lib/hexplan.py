KINDS = ("cmts", "numforms", "unions", "iflags")
LISTED = ("cmts", "numforms", "unions", "labels", "iflags", "lvars")
EXACT = ("unions", "iflags", "lvars")
NO_SIZE = -1
NOUNS = {"cmts": "comment(s)", "numforms": "number format(s)", "unions": "union selection(s)", "labels": "label(s)", "iflags": "item flag(s)",
         "lvars": "variable setting(s)"}
COUNTERS = {"cmts": "Hex-Rays comments", "numforms": "Hex-Rays number formats", "unions": "Hex-Rays union selections",
            "iflags": "Hex-Rays item flags", "lvars": "Hex-Rays variable settings"}
LABELS_WHY = "labels are keyed by the decompiler's label number: not ported"
LVAR_FIELDS = ("name", "type", "cmt")
FIELD_NOUNS = {"name": "name", "type": "type", "cmt": "comment"}


def items_of(hx):
    out = [(kind, it) for kind in KINDS for it in hx.get(kind) or []]
    return out + [("lvars", it) for it in (hx.get("lvars") or {}).get("list", [])]


def count_text(hx):
    counts = {}
    for kind, _it in items_of(hx) + [("labels", it) for it in hx.get("labels") or []]:
        counts[kind] = counts.get(kind, 0) + 1
    return ", ".join("%d %s" % (counts[k], NOUNS[k]) for k in LISTED if k in counts)


def labels_text(labels):
    return "its %d Hex-Rays label(s) (%s) are not ported: %s" % (len(labels), ", ".join(it["name"] for it in labels), LABELS_WHY)


def key_of(kind, it):
    if kind == "cmts":
        return it["off"], it["itp"]
    if kind == "numforms":
        return it["off"], it["opnum"]
    if kind == "unions":
        return it["off"]
    if kind == "iflags":
        return it["off"], it["op"]
    return tuple(it["loc"]), it["defoff"]


def value_of(kind, it):
    if kind == "cmts":
        return it["text"]
    if kind == "numforms":
        return it["flags"], it["nf_opnum"], it["props"], it["serial"], it["nbytes"], it["type_name"]
    if kind == "unions":
        return tuple(it["path"])
    if kind == "iflags":
        return it["flags"]
    return {"name": it.get("name"), "type": it.get("type"), "cmt": it.get("cmt"), "size": it.get("size", -1), "flags": it.get("flags", 0)}


def off_of(kind, it):
    return it["defoff"] if kind == "lvars" else it["off"]


def loc_text(loc):
    return "stack 0x%X" % loc[1] if loc[0] == "stk" else "register %d" % loc[1]


def describe(kind, it):
    if kind == "cmts":
        return "the Hex-Rays comment at +0x%X" % it["off"]
    if kind == "numforms":
        return "the Hex-Rays number format of operand %d at +0x%X" % (it["opnum"], it["off"])
    if kind == "unions":
        return "the Hex-Rays union selection at +0x%X" % it["off"]
    if kind == "iflags":
        return "the Hex-Rays item flags at +0x%X" % it["off"]
    if it.get("name"):
        return "the Hex-Rays variable %s (%s)" % (it["name"], loc_text(it["loc"]))
    return "the Hex-Rays variable setting for %s" % loc_text(it["loc"])


def insn_map(shape):
    return {x[0]: (x[2], list(x[3])) for x in shape.get("insns", [])}


def place_problem(kind, it, old_insns, new_insns):
    off = off_of(kind, it)
    if off is None:
        return None
    if off not in new_insns:
        return "+0x%X is not an instruction in the new function" % off
    if off not in old_insns:
        return "+0x%X was not an instruction in the old function" % off
    (old_mnem, old_ops), (new_mnem, new_ops) = old_insns[off], new_insns[off]
    if old_mnem != new_mnem:
        return "the instruction at +0x%X differs in the new function (old %s, new %s)" % (off, old_mnem, new_mnem)
    if kind == "numforms":
        n = it["opnum"]
        if n >= len(old_ops) or n >= len(new_ops) or old_ops[n] != new_ops[n]:
            return "operand %d of the instruction at +0x%X differs in the new function" % (n, off)
    return None


def exact_problem(hx, new_frame, new_ops):
    if hx.get("frame") != new_frame:
        return "the stack frame differs in the new function"
    if hx.get("ops") != new_ops:
        return "the registers or stack offsets its instructions use differ in the new function"
    return None


def merge(kind, have, want):
    result = dict(have)
    added, notes = 0, []
    for key, value, it in want:
        if key in result:
            if result[key] != value:
                notes.append((it, "hexrays-differs", "the new function already has another one, kept"))
            continue
        result[key] = value
        added += 1
    return result, added, notes


def clash(name):
    return "the name %s is already used by another variable in the new function" % name


def without_type(fields):
    return dict(fields, type=None, size=NO_SIZE)


def merge_lvars(have, want, items):
    if have is not None and (have["delta"], have["flags"]) != (want["delta"], want["flags"]):
        why = "the new function's variable settings use another stack base or flags (delta 0x%X, flags 0x%X; old delta 0x%X, flags 0x%X)" % (
            have["delta"], have["flags"], want["delta"], want["flags"])
        return have, 0, [(it, "hexrays-skipped", why) for _key, _f, it in items]
    result = {"delta": want["delta"], "flags": want["flags"], "items": dict(have["items"]) if have and have["items"] else {}}
    if have and have["items"]:
        result["delta"], result["flags"] = have["delta"], have["flags"]
    names = {f["name"] for f in result["items"].values() if f["name"]}
    changed, notes = 0, []
    for key, fields, it in items:
        cur = result["items"].get(key)
        if cur is None:
            new = dict(fields, size=NO_SIZE)
            if new["name"] and new["name"] in names:
                notes.append((it, "hexrays-skipped", clash(new["name"])))
                new["name"] = None
                if not new["type"] and not new["cmt"]:
                    continue
            if not any(new[f] for f in LVAR_FIELDS) and not new["flags"]:
                continue
            result["items"][key] = new
            if new["name"]:
                names.add(new["name"])
            changed += 1
            continue
        upd = dict(cur)
        for f in LVAR_FIELDS:
            w, h = fields[f], cur[f]
            if not w or w == h:
                continue
            if h:
                shown = h if f == "name" else repr(h)
                notes.append((it, "hexrays-differs", "the new function already has the %s %s for it, kept" % (FIELD_NOUNS[f], shown)))
                continue
            if f == "name" and w in names:
                notes.append((it, "hexrays-skipped", clash(w)))
                continue
            upd[f] = w
            if f == "type":
                upd["size"] = NO_SIZE
            if f == "name":
                names.add(w)
        if upd != cur:
            result["items"][key] = upd
            changed += 1
    return result, changed, notes
