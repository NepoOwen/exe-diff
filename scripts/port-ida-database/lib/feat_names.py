import ida_bytes
import ida_dirtree
import ida_funcs
import ida_idaapi
import ida_name

import cmts
import dataplan

SN = ida_name.SN_NOWARN | ida_name.SN_NOCHECK
BADADDR = ida_idaapi.BADADDR


def func_at(ea):
    f = ida_funcs.get_func(ea)
    return f if f is not None and f.start_ea == ea else None


def user_name(ea):
    return ida_name.get_name(ea) if ida_bytes.has_user_name(ida_bytes.get_flags(ea)) else None


def func_tree():
    return ida_dirtree.get_std_dirtree(ida_dirtree.DIRTREE_FUNCS)


def listdir(dt, path):
    ff = ida_dirtree.dirtree_iterator_t()
    out = []
    ok = dt.findfirst(ff, path.rstrip("/") + "/*")
    while ok:
        de = dt.resolve_cursor(ff.cursor)
        out.append((de.isdir, de.idx, dt.get_abspath(ff.cursor)))
        ok = dt.findnext(ff)
    return out


def walk(dt):
    folders, members = [], {}
    stack = ["/"]
    while stack:
        path = stack.pop()
        for isdir, idx, sub in listdir(dt, path):
            if isdir:
                folders.append(sub)
                members.setdefault(sub, [])
                stack.append(sub)
            elif path != "/":
                members[path].append(idx)
    return sorted(folders), members


def parent_of(path):
    return path.rsplit("/", 1)[0] or "/"


def under(path, folder):
    return path == folder or path.startswith(folder + "/")


def label(ctx, old, name=None):
    if name:
        return name
    row = ctx.pairing.rows.get(old)
    return row.name if row is not None and row.name else "0x%X" % old


def why_not(ctx, old):
    row = ctx.pairing.rows.get(old)
    cls = ctx.pairing.classes.get(old)
    if row is None:
        return "not-ported-unpaired", "no function in the new exe is paired with it"
    if cls == "below":
        return "not-ported-below", "changed, %d%% similar, below -MinSimilarity %d" % (row.similarity or 0, ctx.min_similarity)
    if cls == "likely":
        return "not-ported-likely", "one of several identical functions, pass -IncludeLikely to port it"
    return "not-ported-unpaired", "map.csv status %s" % row.status


def owner_annotations(ctx, f):
    ea = f.start_ea
    return (ctx.owner_name(ea, user_name(ea)), ctx.owner_cmt(ea, "cmt", ida_funcs.get_func_cmt(f, False)),
            ctx.owner_cmt(ea, "rptcmt", ida_funcs.get_func_cmt(f, True)))


def export(ctx, dump):
    dt = func_tree()
    folders, members = walk(dt)
    folder_of = {}
    for path in sorted(members):
        for ea in members[path]:
            folder_of.setdefault(ea, path)
    ported = set()
    funcs = dump["functions"]
    for old in sorted(ctx.pairing.rows):
        if not ctx.ported(old):
            continue
        f = func_at(old)
        if f is None:
            ctx.log.review("no-old-function", "%s is not the start of a function in the old database" % label(ctx, old), old, ctx.pairing.new_of(old))
            continue
        ported.add(old)
        name, cmt, rpt = owner_annotations(ctx, f)
        folder = folder_of.get(old)
        if name or cmt or rpt or folder:
            funcs.setdefault(str(old), {}).update(name=name, cmt=cmt, rptcmt=rpt, folder=folder)
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        ea = f.start_ea
        if ea in ported:
            continue
        name, cmt, rpt = owner_annotations(ctx, f)
        if not (name or cmt or rpt or ea in folder_of):
            continue
        category, why = why_not(ctx, ea)
        ctx.log.review(category, "%s: %s" % (label(ctx, ea, name), why), ea, ctx.pairing.new_of(ea))
    kept = []
    for folder in folders:
        inside = [ea for path, eas in members.items() if under(path, folder) for ea in eas]
        if not inside or any(ea in ported for ea in inside):
            kept.append(folder)
        else:
            ctx.log.review("folder-not-ported", "%s: none of its %d function(s) is ported" % (folder, len(set(inside))))
    dump["folders"] = kept


def apply_name(ctx, old, new, name):
    if not name:
        return
    have = ida_name.get_name(new)
    if have == name:
        ctx.log.ported("function names")
        return
    other = ida_name.get_name_ea(BADADDR, name)
    if other != BADADDR and other != new:
        ctx.log.review("name-in-use", "%s is already the name of 0x%X in the new database, not applied" % (name, other), old, new)
        return
    if ida_bytes.has_user_name(ida_bytes.get_flags(new)):
        ctx.log.review("new-has-name", "%s: the new function is already named %s, kept" % (name, have), old, new)
        return
    if ida_name.set_name(new, name, SN):
        ctx.log.ported("function names")
        return
    other = ida_name.get_name_ea(BADADDR, name)
    if other != BADADDR and other != new:
        ctx.log.review("name-in-use", "%s is already the name of 0x%X in the new database, not applied" % (name, other), old, new)
    else:
        ctx.log.review("name-refused", "IDA refused the name %s" % name, old, new)


def note_for(ctx, old):
    cls = ctx.pairing.classes.get(old)
    if cls == "changed":
        return cmts.changed_note(ctx.old_exe_name, ctx.pairing.rows[old].similarity)
    if cls == "likely":
        return cmts.LIKELY_NOTE
    return None


def apply_cmt(ctx, old, new, f, rpt, owner, note, what):
    if not owner and not note:
        return
    kind = "repeatable function comment" if rpt else "function comment"
    want = cmts.with_note(owner, note)
    have = ida_funcs.get_func_cmt(f, rpt) or ""
    action = cmts.decide(have, want, owner)
    if action == "keep":
        ctx.log.review("comment-differs", "%s: the new function already has another %s, kept" % (what, kind), old, new)
        return
    if action == "set" and not ida_funcs.set_func_cmt(f, want, rpt):
        ctx.log.warn("cannot set the %s of 0x%X" % (kind, new))
        return
    if cmts.strip_notes(want):
        ctx.log.ported(kind + "s")
    if note:
        ctx.log.ported("likely notes" if note == cmts.LIKELY_NOTE else "changed notes")


def apply_cmts(ctx, old, new, f, entry, what):
    apply_cmt(ctx, old, new, f, False, entry.get("cmt"), note_for(ctx, old), what)
    apply_cmt(ctx, old, new, f, True, entry.get("rptcmt"), None, what)


def make_folders(ctx, dt, folders):
    made = set()
    for folder in folders:
        if not dt.isdir(folder):
            err = dt.mkdir(folder)
            if err not in (ida_dirtree.DTE_OK, ida_dirtree.DTE_ALREADY_EXISTS) or not dt.isdir(folder):
                ctx.log.warn("cannot create the folder %s: %s" % (folder, dt.errstr(err)))
                continue
        made.add(folder)
    if made:
        ctx.log.ported("folders", len(made))
    return made


def apply_folder(ctx, dt, made, old, new, folder, what):
    if not folder:
        return
    if folder not in made:
        ctx.log.review("folder-missing", "%s: its folder %s could not be created" % (what, folder), old, new)
        return
    c = dt.find_entry(ida_dirtree.direntry_t(new, False))
    if not c.valid():
        ctx.log.warn("0x%X is not in the function folders" % new)
        return
    path = dt.get_abspath(c)
    parent = parent_of(path)
    if parent == folder:
        ctx.log.ported("functions in folders")
        return
    if parent != "/":
        ctx.log.review("folder-differs", "%s: the new function is already in %s, not moved to %s" % (what, parent, folder), old, new)
        return
    err = dt.rename(path, folder + "/" + path.rsplit("/", 1)[1])
    if err != ida_dirtree.DTE_OK:
        ctx.log.review("folder-refused", "%s: cannot move it to %s: %s" % (what, folder, dt.errstr(err)), old, new)
        return
    ctx.log.ported("functions in folders")


def apply(ctx, dump):
    dt = func_tree()
    made = make_folders(ctx, dt, dump.get("folders", []))
    funcs = dump.get("functions", {})
    for key in sorted(funcs, key=int):
        old = int(key)
        entry = funcs[key]
        if not ctx.ported(old) or not dataplan.has_annotation(entry):
            continue
        what = label(ctx, old, entry.get("name"))
        new = ctx.new_function(old, what)
        if new is None:
            continue
        f = func_at(new)
        apply_name(ctx, old, new, entry.get("name"))
        apply_cmts(ctx, old, new, f, entry, what)
        apply_folder(ctx, dt, made, old, new, entry.get("folder"), what)
