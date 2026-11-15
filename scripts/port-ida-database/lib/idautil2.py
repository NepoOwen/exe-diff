import idc
import ida_loader
import ida_nalt
import ida_pro


def input_md5_hex():
    md5 = ida_nalt.retrieve_input_file_md5()
    return md5.hex().lower() if md5 else ""


old_md5_hex = input_md5_hex


def db_context():
    import ida_ida
    import ida_typeinf
    til = ida_typeinf.get_idati()
    return {"tils": sorted(til.base(i).name for i in range(til.nbases)),
            "compiler": ida_typeinf.get_compiler_name(ida_ida.inf_get_cc_id()) or "",
            "abi": ida_typeinf.get_abi_name() or "",
            "imagebase": ida_nalt.get_imagebase(),
            "bitness": ida_ida.inf_get_app_bitness()}


def finish(code, save=False):
    try:
        if save and code == 0:
            if not ida_loader.save_database(None, 0):
                code = 2
        else:
            idc.process_config_line("ABANDON_DATABASE=YES")
    finally:
        ida_pro.qexit(code)
