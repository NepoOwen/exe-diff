import ida_typeinf

import dataplan
import typedecl

HTI = ida_typeinf.HTI_DCL | ida_typeinf.HTI_NWR


class _Sink(ida_typeinf.text_sink_t):
    def __init__(self):
        ida_typeinf.text_sink_t.__init__(self)
        self.text = ""

    def _print(self, s):
        self.text += s
        return 0


def decl_of(til, ordinal):
    sink = _Sink()
    if ida_typeinf.print_decls(sink, til, [ordinal], 0) == 0:
        return None
    return typedecl.clean(sink.text) or None


def local_types(til=None):
    til = til or ida_typeinf.get_idati()
    out = []
    for o in range(1, ida_typeinf.get_ordinal_limit(til)):
        name = ida_typeinf.get_numbered_type_name(til, o)
        if name and not typedecl.anonymous(name):
            out.append((name, decl_of(til, o)))
    return out


def odd_names(til=None):
    til = til or ida_typeinf.get_idati()
    out = []
    for o in range(1, ida_typeinf.get_ordinal_limit(til)):
        name = ida_typeinf.get_numbered_type_name(til, o)
        if name and not dataplan.plain_name(name):
            out.append(name)
    return dataplan.odd_index(out)


def existing(til, name):
    o = ida_typeinf.get_type_ordinal(til, name)
    if not o:
        return None
    t = ida_typeinf.tinfo_t()
    fwd = t.get_numbered_type(til, o) and t.is_forward_decl()
    return decl_of(til, o) or "", bool(fwd)


def export(ctx, dump):
    types = []
    for name, decl in local_types():
        if decl is None:
            if ctx.owner_type(name, ""):
                ctx.log.review("type-failed", "%s: IDA cannot print its declaration in the old database, not ported" % name)
            continue
        if ctx.owner_type(name, decl):
            types.append({"name": name, "decl": decl})
    dump["types"] = typedecl.order(types)


class Final(str):
    pass


def _complete(til, name):
    have = existing(til, name)
    return have is not None and not have[1]


def _differently(ctx, til, name, got, before):
    why = "IDA reads its declaration differently in the new database (%s)" % " ".join(got.split())
    if name in before:
        ctx.log.warn("%s: IDA read the local type differently from the old database and it replaced the declaration that was there, check it by hand" % name)
        return Final(why + "; left as IDA read it")
    if ida_typeinf.del_named_type(til, name, ida_typeinf.NTF_TYPE):
        return Final(why + "; removed again")
    ctx.log.warn("%s: IDA read the local type differently from the old database and it could not be removed again, check it by hand" % name)
    return Final(why + "; it could not be removed again")


def _port(ctx, til, t, fwds, needs, before):
    name, want = t["name"], t["decl"]
    have = existing(til, name)
    if have is not None and (have[0] == want or not have[1]):
        if have[0] == want:
            return True
        ctx.log.review("type-differs", "%s: the new database already has another declaration of it, kept" % name)
        return False
    missing = [d for d in sorted(needs) if not _complete(til, d)]
    if missing:
        return "it holds %s by value, which the new database does not define" % ", ".join(missing)
    lines = [f for f in fwds if existing(til, f.split(" ", 1)[1].rstrip(";")) is None]
    errors = ida_typeinf.parse_decls(til, "\n".join(lines + [want]) + "\n", None, HTI)
    after = existing(til, name)
    if errors or after is None or (after[1] and not typedecl.is_forward(want)):
        return "IDA could not parse its declaration (%d error(s)), a type it uses may be missing in the new database" % errors
    if after[0] != want:
        return _differently(ctx, til, name, after[0], before)
    return True


def _leftover(til, name, names):
    have = existing(til, name)
    if have is None or not have[1]:
        return ""
    users = sorted(n for n in names if n != name and name in typedecl.refs((existing(til, n) or ("",))[0], {name}))
    if users:
        return "; left an empty forward declaration of %s, still used by %s" % (name, ", ".join(users))
    if ida_typeinf.del_named_type(til, name, ida_typeinf.NTF_TYPE):
        return ""
    return "; left an empty forward declaration of %s" % name


def apply(ctx, dump):
    til = ida_typeinf.get_idati()
    types = [t for t in dump.get("types", []) if t.get("name") and t.get("decl")]
    fwds = typedecl.forwards(types)
    needs = typedecl.needs_complete(types)
    names = [t["name"] for t in types]
    before = {n for n in names if existing(til, n) is not None}
    done, failed, final = 0, [(t, "") for t in types], []
    for _ in range(2):
        retry, failed = failed, []
        for t, _why in retry:
            r = _port(ctx, til, t, fwds[t["name"]], needs[t["name"]], before)
            if r is True:
                done += 1
            elif isinstance(r, Final):
                final.append((t, r))
            elif r:
                failed.append((t, r))
    for t, why in sorted(failed + final, key=lambda x: names.index(x[0]["name"])):
        name = t["name"]
        left = "" if name in before else _leftover(til, name, names)
        ctx.log.review("type-failed", "%s: %s%s" % (name, why, left))
    if done:
        ctx.log.ported("local types", done)
