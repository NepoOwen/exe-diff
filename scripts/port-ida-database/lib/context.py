import os

import baseline as baselines
import pairs
import portlog
from dump import DUMP_VERSION


def env(name, default=None):
    value = os.environ.get(name)
    return default if value is None or value == "" else value


def env_flag(name):
    return env(name, "0").strip().lower() in ("1", "true", "yes")


def read_text(path):
    with open(path, "r", encoding="utf-8-sig") as f:
        return f.read()


class ExportCtx:
    def __init__(self, pairing, log, pair, old_exe_name, min_similarity=80, include_likely=False, verify=False, strict=False,
                 dump_path=None, result_path=None, log_path=None):
        self.pairing = pairing
        self.log = log
        self.pair = pair
        self.old_exe_name = old_exe_name
        self.min_similarity = min_similarity
        self.include_likely = include_likely
        self.verify = verify
        self.strict = strict
        self.dump_path = dump_path
        self.result_path = result_path
        self.log_path = log_path
        self.baseline = None
        self.shape_wanted = set()

    def ported(self, old_start):
        cls = self.pairing.classes.get(old_start)
        return cls is not None and pairs.is_ported(cls, self.include_likely)

    def owner_name(self, ea, current):
        return baselines.owner_name(self.baseline, ea, current)

    def owner_cmt(self, ea, kind, current):
        return baselines.owner_cmt(self.baseline, ea, kind, current)

    def owner_type(self, name, decl):
        return baselines.owner_type(self.baseline, name, decl)


def ida_function_start(ea):
    import ida_funcs
    f = ida_funcs.get_func(ea)
    return f is not None and f.start_ea == ea


class ApplyCtx(ExportCtx):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.gate = {}
        self.is_function_start = ida_function_start
        self.no_function = set()

    def new_start(self, old_start):
        return self.pairing.new_of(old_start)

    def new_function(self, old_start, what=None, quiet=False):
        new = self.new_start(old_start)
        if new is None:
            return None
        if self.is_function_start(new):
            return new
        if not quiet and old_start not in self.no_function:
            self.no_function.add(old_start)
            self.log.review("no-new-function", "%s: 0x%X is not the start of a function in the new database, nothing was created" % (
                what or "0x%X" % old_start, new), old_start, new)
        return None

    def gate_ok(self, old_start):
        return self.gate.get(old_start, False)


def _build(cls, log):
    pair = {k: v.strip() for k, v in pairs.parse_pair_txt(read_text(env("PORTDB_PAIR"))).items()}
    min_similarity = int(env("PORTDB_MIN_SIMILARITY", "80"))
    pairing = pairs.build_pairing(pairs.parse_map_csv(read_text(env("PORTDB_MAP"))), min_similarity)
    old_exe_name = env("PORTDB_OLD_EXE_NAME") or os.path.basename(pair.get("old_exe", "").replace("\\", "/"))
    return cls(pairing, log, pair, old_exe_name, min_similarity, env_flag("PORTDB_INCLUDE_LIKELY"), env_flag("PORTDB_VERIFY"),
               env_flag("PORTDB_STRICT"), env("PORTDB_DUMP"), env("PORTDB_RESULT"), env("PORTDB_LOG"))


def build_export_ctx():
    ctx = _build(ExportCtx, portlog.PortLog())
    path = env("PORTDB_BASELINE")
    if not path:
        ctx.log.warn(env("PORTDB_BASELINE_WARNING") or baselines.NO_CACHE % ctx.old_exe_name)
        return ctx
    data = baselines.load(path)
    if str(data.get("old_md5", "")).lower() != ctx.pair.get("old_md5", "").lower():
        ctx.log.warn("the baseline %s is not for %s: IDA-made names, comments and types cannot be told from yours" % (path, ctx.old_exe_name))
        return ctx
    ctx.baseline = data
    return ctx


def build_apply_ctx(dump):
    return _build(ApplyCtx, portlog.PortLog.from_json(dump.get("log", [])))


def new_dump(old_md5):
    return {"version": DUMP_VERSION, "old_md5": old_md5, "context": {}, "log": [], "functions": {}, "folders": [], "types": [], "data": [],
            "union_types": {}, "notices": []}


def write_result(path, status, message):
    if not path:
        return
    with open(path, "w", encoding="utf-8") as f:
        f.write(status + "\n" + message.rstrip("\n") + "\n")
