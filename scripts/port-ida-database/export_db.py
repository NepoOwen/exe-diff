import os
import sys
import traceback

import ida_auto
import ida_pro
import idc

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)


def main():
    import context
    import dataplan
    import dbcontext
    import dump as dumpfile
    import feat_insn
    import idautil2
    import verify
    from features import FEATURES

    ctx = context.build_export_ctx()
    want = ctx.pair.get("old_md5", "").lower()
    have = idautil2.old_md5_hex()
    if not want or have != want:
        context.write_result(ctx.result_path, "refused", "this database is not for %s: its input file md5 is %s, pair.txt has %s" % (
            ctx.old_exe_name, have or "not recorded", want or "nothing"))
        return 1
    db = idautil2.db_context()
    paths = dbcontext.exe_paths(ctx.pair, "old")
    own, source = dbcontext.own_imagebase(ctx.baseline, want, paths)
    text = dbcontext.rebased("old", db["imagebase"], own, source)
    if text:
        context.write_result(ctx.result_path, "refused", text)
        return 1
    notices = []
    if own is None:
        text = dbcontext.unchecked("old", paths)
        if ctx.strict:
            context.write_result(ctx.result_path, "refused", text + " (-Strict)")
            return 1
        notices.append(text)
    notices.append(dbcontext.kind_notice(ctx.old_exe_name, dbcontext.checked_pe(want, paths)[1]))
    notices = [n for n in notices if n]
    for text in notices:
        ctx.log.warn(text)
    ida_auto.auto_wait()
    dump = context.new_dump(want)
    dump["notices"] = notices
    dump["context"] = db
    dump["baseline"] = ctx.baseline is not None
    for feature in FEATURES:
        feature.export(ctx, dump)
    feat_insn.export_shapes(ctx, dump)
    decompiled = verify.export(ctx, dump)
    dump["log"] = ctx.log.to_json()
    dumpfile.save(ctx.dump_path, dump)
    extra = ", %d decompiled for -Verify" % decompiled if ctx.verify else ""
    annotated = sum(1 for entry in dump["functions"].values() if dataplan.has_annotation(entry))
    context.write_result(ctx.result_path, "ok", "%d annotated functions, %d local types exported%s" % (annotated, len(dump["types"]), extra))
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
        idautil2.finish(code)
    except Exception:
        idc.process_config_line("ABANDON_DATABASE=YES")
        ida_pro.qexit(2)
