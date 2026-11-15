import os
import sys
import traceback

import ida_auto
import ida_bytes
import ida_funcs
import ida_name
import ida_pro
import idc

LIB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib")
if LIB not in sys.path:
    sys.path.insert(0, LIB)


def main():
    import baseline
    import context
    import feat_data
    import feat_insn
    import feat_protos
    import feat_types
    import idautil2
    import pairs

    result = context.env("PORTDB_RESULT")
    pair = {k: v.strip() for k, v in pairs.parse_pair_txt(context.read_text(context.env("PORTDB_PAIR"))).items()}
    old_name = context.env("PORTDB_OLD_EXE_NAME") or os.path.basename(pair.get("old_exe", "").replace("\\", "/"))
    want = pair.get("old_md5", "").lower()
    have = idautil2.input_md5_hex()
    if not want or have != want:
        context.write_result(result, "refused", "the analysis cache is not for %s: its input file md5 is %s, pair.txt has %s" % (
            old_name, have or "not recorded", want or "nothing"))
        return 1
    ida_auto.auto_wait()
    b = baseline.new_baseline(want)
    b["imagebase"] = idautil2.db_context()["imagebase"]
    for i in range(ida_funcs.get_func_qty()):
        f = ida_funcs.getn_func(i)
        key = str(f.start_ea)
        if ida_bytes.has_user_name(ida_bytes.get_flags(f.start_ea)):
            b["names"][key] = ida_name.get_name(f.start_ea)
        cmt = ida_funcs.get_func_cmt(f, False)
        if cmt:
            b["cmts"][key] = cmt
        rpt = ida_funcs.get_func_cmt(f, True)
        if rpt:
            b["rptcmts"][key] = rpt
    b["types"] = {name: decl or "" for name, decl in feat_types.local_types()}
    b["insn"] = feat_insn.records()
    b["protos"] = feat_protos.records()
    b["data"] = feat_data.records()
    baseline.save(context.env("PORTDB_BASELINE"), b)
    context.write_result(result, "ok", "%d IDA-made names, %d comments, %d local types, %d instructions with comments or operand formats, %d prototypes, %d data items" % (
        len(b["names"]), len(b["cmts"]) + len(b["rptcmts"]), len(b["types"]), len(b["insn"]), len(b["protos"]), len(b["data"])))
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
