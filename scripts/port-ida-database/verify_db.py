import json
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
    import dump as dumpfile
    import idautil2
    import portlog
    import verify

    dump = dumpfile.load(context.env("PORTDB_DUMP"))
    with open(context.env("PORTDB_STATE"), "r", encoding="utf-8") as f:
        state = json.load(f)
    ctx = context.build_apply_ctx({"log": state["log"]})
    want = ctx.pair.get("new_md5", "").lower()
    have = idautil2.input_md5_hex()
    if not want or have != want:
        context.write_result(ctx.result_path, "refused", "the database to verify is not for the new exe: its input file md5 is %s, pair.txt has %s" % (
            have or "not recorded", want or "nothing"))
        return 1
    ida_auto.auto_wait()
    compared = verify.verify(ctx, dump, set(state.get("skip", [])))
    ctx.log.verified(compared)
    if ctx.log_path:
        with open(ctx.log_path, "r", encoding="utf-8", newline="") as f:
            text = f.read()
        with open(ctx.log_path, "w", encoding="utf-8", newline="") as f:
            f.write(portlog.with_report(text, ctx.log.render(state["found"], state.get("baseline", True))))
    path = context.env("PORTDB_SUMMARY")
    if path:
        with open(path, "w", encoding="utf-8") as f:
            f.write(portlog.summary_file(ctx.log, state["found"], state.get("context", []), state.get("info", []), state.get("baseline", True)))
    t = ctx.log.totals()
    context.write_result(ctx.result_path, "ok", "%d functions compared, %d mismatch(es)" % (compared, t["mismatches"]))
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
