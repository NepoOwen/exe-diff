import align
import dataplan

CMT_KINDS = ("cmt", "rpt", "ant", "post")
FORMATS = ("dec", "hex", "oct", "bin", "char", "enum", "stroff")
MAX_ALIGN = 4000
MIN_RUN = 3
CHANGED_FORMAT = "operand formats are only ported to unchanged functions"
TYPE_WORD = {"enum": "enum", "stroff": "struct"}


def desc(fmt, arg=None, path=None, delta=0, serial=0):
    out = {"fmt": fmt}
    if arg is not None:
        out["arg"] = arg
    if path is not None:
        out["path"] = list(path)
    if delta:
        out["delta"] = delta
    if serial:
        out["serial"] = serial
    return out


def describe(item):
    if item["kind"] != "opfmt":
        return {"cmt": "comment", "rpt": "repeatable comment", "ant": "anterior lines", "post": "posterior lines"}[item["kind"]]
    fmt = item["fmt"]
    if fmt == "enum":
        return "enum %s format of operand %d" % (item.get("arg"), item["opn"])
    if fmt == "stroff":
        return "struct offset %s format of operand %d" % (".".join(item.get("path", [])), item["opn"])
    return "%s format of operand %d" % (fmt, item["opn"])


def want_of(item):
    if item["kind"] in ("cmt", "rpt"):
        return item["text"]
    if item["kind"] in ("ant", "post"):
        return list(item["lines"])
    return {k: v for k, v in item.items() if k not in ("off", "kind", "opn", "ida", "decls")}


def type_names(item):
    if item.get("kind") != "opfmt":
        return []
    if item.get("fmt") == "enum":
        return [item.get("arg")]
    if item.get("fmt") == "stroff":
        return list(item.get("path") or [])
    return []


def type_problem(item, new_decl_of):
    decls = item.get("decls") or {}
    for name in type_names(item):
        word = TYPE_WORD[item["fmt"]]
        have = new_decl_of(name) if name else None
        if have is None:
            return "the %s %s is not in the new database" % (word, name)
        if decls.get(name) is None or decls[name] != have:
            return "the %s %s in the new database is not the same type as in the old one" % (word, name)
    names = set(type_names(item))
    return dataplan.types_problem({k: v for k, v in decls.items() if k not in names}, new_decl_of)


def _cmt_item(off, kind, value, base):
    key = "text" if kind in ("cmt", "rpt") else "lines"
    item = {"off": off, "kind": kind, key: value}
    if base:
        item["ida"] = base
    return item


def owner_items(off, record, base):
    base = base or {}
    out = []
    for kind in CMT_KINDS:
        value = record.get(kind)
        if value and value != base.get(kind):
            out.append(_cmt_item(off, kind, value, base.get(kind)))
    ops, base_ops = record.get("ops") or {}, base.get("ops") or {}
    for n in sorted(ops, key=int):
        d = ops[n]
        if d.get("fmt") not in FORMATS or d == base_ops.get(n):
            continue
        item = dict(d, off=off, kind="opfmt", opn=int(n))
        if base_ops.get(n):
            item["ida"] = base_ops[n]
        out.append(item)
    return out


def decide(have, want, ida):
    if have == want:
        return "same"
    if not have:
        return "set"
    if ida is not None and have == ida:
        return "set"
    return "keep"


def seq(insns):
    return [(x[2], tuple(x[3]), x[5] if len(x) > 5 else None) for x in insns]


def plan(items, old_shape, new_shape, exact, cap=MAX_ALIGN):
    if exact:
        return [(it, it["off"]) for it in items], []
    old, new = old_shape["insns"], new_shape["insns"]
    if max(len(old), len(new)) > cap:
        why = "the function has more than %d instructions, too many to align" % cap
        return [], [(it, why, None) for it in items]
    mapping = dict(align.align_runs(seq(old), seq(new), MIN_RUN))
    index = {x[0]: k for k, x in enumerate(old)}
    placed, skipped = [], []
    for it in items:
        k = index.get(it["off"])
        j = mapping.get(k) if k is not None else None
        new_off = new[j][0] if j is not None else None
        if it["kind"] == "opfmt":
            skipped.append((it, CHANGED_FORMAT, new_off))
        elif j is None:
            skipped.append((it, "it is in a changed part of the function", None))
        else:
            placed.append((it, new_off))
    return placed, skipped
