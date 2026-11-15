import os
import sys
import traceback

import ida_auto
import ida_pro
import idc

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)


def save_state(ctx, found, texts, info, baseline):
    import json
    import portlog
    import context
    state = context.env("PORTDB_STATE")
    if state:
        skip = sorted(set(old for old, ok in ctx.gate.items() if not ok) | ctx.no_function)
        with open(state, "w", encoding="utf-8") as f:
            json.dump({"log": ctx.log.to_json(), "found": found, "context": texts, "info": info, "baseline": baseline, "skip": skip}, f)
    path = context.env("PORTDB_SUMMARY")
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(portlog.summary_file(ctx.log, found, texts, info, baseline))


def main():
    import context
    import dbcontext
    import dump as dumpfile
    import idautil2
    import portlog
    from features import FEATURES

    dump = dumpfile.load(context.env("PORTDB_DUMP"))
    ctx = context.build_apply_ctx(dump)
    new_name = os.path.basename(ctx.pair.get("new_exe", "").replace("\\", "/")) or "the new exe"
    want = ctx.pair.get("new_md5", "").lower()
    have = idautil2.input_md5_hex()
    if not want or have != want:
        context.write_result(ctx.result_path, "refused", "this database is not for %s: its input file md5 is %s, pair.txt has %s" % (
            new_name, have or "not recorded", want or "nothing"))
        return 1
    if str(dump.get("old_md5", "")).lower() != ctx.pair.get("old_md5", "").lower():
        context.write_result(ctx.result_path, "refused", "the dump %s was made for another old exe than pair.txt names (%s)" % (
            ctx.dump_path, ctx.old_exe_name))
        return 1
    db = idautil2.db_context()
    paths = dbcontext.exe_paths(ctx.pair, "new")
    own, source = dbcontext.own_imagebase(None, want, paths)
    text = dbcontext.rebased("new", db["imagebase"], own, source)
    if text:
        context.write_result(ctx.result_path, "refused", text)
        return 1
    notices = list(dump.get("notices", []))
    if own is None:
        text = dbcontext.unchecked("new", paths)
        if ctx.strict or context.env_flag("PORTDB_NEWDB_GIVEN"):
            context.write_result(ctx.result_path, "refused", text + " (%s was given)" % ("-Strict" if ctx.strict else "-NewDb"))
            return 1
        notices.append(text)
        ctx.log.warn(text)
    kind = dbcontext.kind_notice(new_name, dbcontext.checked_pe(want, paths)[1])
    if kind:
        notices.append(kind)
        ctx.log.warn(kind)
    diffs = dbcontext.differences(dump.get("context", {}), db)
    if diffs and ctx.strict:
        context.write_result(ctx.result_path, "refused", dbcontext.refusal(diffs))
        return 1
    for _key, text in reversed(diffs):
        ctx.log.warn(text, first=True)
    info = dbcontext.information(dump.get("context", {}), db)
    baseline = bool(dump.get("baseline", True))
    ida_auto.auto_wait()
    for feature in FEATURES:
        feature.apply(ctx, dump)
    ida_auto.auto_wait()
    found = portlog.found(dump, ctx.log)
    if ctx.log_path:
        with open(ctx.log_path, "a", encoding="utf-8", newline="\r\n") as f:
            f.write("".join("note: %s\n" % t for t in info) + ("\n" if info else ""))
            f.write(ctx.log.render(found, baseline))
    save_state(ctx, found, [text for _key, text in diffs] + notices, info, baseline)
    context.write_result(ctx.result_path, "ok", "%s, %d warning(s), %d to review" % (
        portlog.result_text(ctx.log), len(ctx.log.warnings), len(ctx.log.reviews)))
    return 0


def failed(text):
    path = os.environ.get("PORTDB_RESULT")
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write("failed\n" + text)


code = 2
try:
    code = main()
except Exception:
    failed(traceback.format_exc())
finally:
    try:
        import idautil2
        idautil2.finish(code, save=True)
    except Exception:
        idc.process_config_line("ABANDON_DATABASE=YES")
        ida_pro.qexit(2)
