from typedecl import TOKEN

KINDS = ("name", "cmt", "rptcmt", "type")
CMT_KINDS = ("cmt", "rptcmt")
FROM = (("changed", "changed functions"), ("likely", "functions without a certain match"), ("unmatched", "functions with no match"),
        ("ambiguous", "instructions that also reference other data"), ("data", "data"), ("code", "code outside functions"), ("jump", "jumps or calls"))
ONLY_CERTAIN = "data is only ported through references from functions with a certain match"
REF_CAP = 16


def type_names(text):
    return [t for t in TOKEN.findall(text or "") if t[0].isalpha() or t[0] in "_$"]


def plain_name(name):
    return bool(name) and TOKEN.fullmatch(name) is not None and (name[0].isalpha() or name[0] in "_$")


def odd_index(names):
    index = {}
    for name in names:
        first = TOKEN.match(name)
        index.setdefault(first.group(0) if first else name, []).append(name)
    return index


def closure(text, decl_of, odd=()):
    out, seen, todo, texts = {}, set(), type_names(text), [text or ""]
    while todo:
        name = todo.pop(0)
        if name in seen:
            continue
        seen.add(name)
        decl = decl_of(name)
        if decl is not None:
            out[name] = decl
            texts.append(decl)
            todo += type_names(decl)
    if odd:
        index = odd if isinstance(odd, dict) else odd_index(odd)
        tokens = set(t for text in texts for t in TOKEN.findall(text))
        for token in tokens & index.keys():
            for name in index[token]:
                if name not in out and any(name in t for t in texts):
                    out[name] = None
    return out


def types_problem(types, new_decl_of):
    if types is None:
        return "the types it uses were not recorded"
    for name in sorted(types):
        if types[name] is None:
            return "the type %s cannot be checked against the new database: its name is not a plain C name" % name
        have = new_decl_of(name)
        if have is None:
            return "the type %s is not in the new database" % name
        if not types[name] or types[name] != have:
            return "the type %s in the new database is not the same type as in the old one" % name
    return None


def owner_value(current, base):
    if not current or current == base:
        return None
    return current


def owner_data(rec, base, user_type):
    base = base or {}
    out = {k: owner_value(rec.get(k), base.get(k)) for k in KINDS}
    if not user_type:
        out["type"] = None
    return out if any(v is not None for v in out.values()) else None


def ida_values(owner, base):
    base = base or {}
    return {k: base[k] for k in CMT_KINDS + ("type",) if owner.get(k) and base.get(k)}


def map_target(refs, gate_ok, targets_of):
    gated = [r for r in refs if gate_ok(r[0])]
    if not gated:
        return None, "none of its %d reference(s) is in a function that passed the gate" % len(refs)
    found = set()
    for func, off in ((r[0], r[1]) for r in gated):
        targets = list(targets_of(func, off))
        if len(targets) != 1:
            return None, "the instruction at old 0x%X has %d data references in the new database" % (func + off, len(targets))
        found.add(targets[0])
    if len(found) > 1:
        return None, "its references lead to different addresses in the new database (%s)" % ", ".join("0x%X" % t for t in sorted(found))
    return found.pop(), None


def cap_refs(refs, cap=REF_CAP):
    return sorted(refs)[:cap]


def shared_targets(mapped):
    claims = {}
    for key, new in mapped:
        if new is not None:
            claims.setdefault(new, []).append(key)
    return {new: keys for new, keys in claims.items() if len(keys) > 1}


def shared_reason(new, others):
    return "its new address 0x%X is also claimed by %s" % (new, ", ".join(others))


def has_annotation(entry):
    return any(entry.get(k) for k in ("name", "cmt", "rptcmt", "folder", "insn", "proto", "hexrays"))


def type_action(have, have_user, want, ida=None):
    if have == want and have_user:
        return "same"
    if not have or not have_user or have == want or have == ida:
        return "set"
    return "keep"


def name_action(have, have_user, want, want_at, ea):
    if have == want:
        return "same"
    if want_at is not None and want_at != ea:
        return "in-use"
    return "keep" if have_user else "set"


def size_problem(old_size, new_size):
    if old_size == new_size:
        return None
    return "the data item in the new database is %d byte(s), the old one is %d" % (new_size, old_size)


def unported_reason(counts):
    parts = ["%s (%d)" % (text, counts[key]) for key, text in FROM if counts.get(key)]
    if not parts:
        return "no instruction references it; " + ONLY_CERTAIN
    return "only referenced from %s; %s" % (", ".join(parts), ONLY_CERTAIN)


def label(name, ea):
    return name or "data at 0x%X" % ea
