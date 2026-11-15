import json
import os

BASELINE_VERSION = 1
KINDS = {"cmt": "cmts", "rptcmt": "rptcmts"}
NO_CACHE = "no analysis cache for %s: IDA-made names, comments and types cannot be told from yours; run exediff with IDA first"


def new_baseline(old_md5):
    return {"version": BASELINE_VERSION, "old_md5": old_md5, "imagebase": None, "names": {}, "cmts": {}, "rptcmts": {}, "types": {}, "insn": {}, "protos": {}, "data": {}}


def save(path, baseline):
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(baseline, f, ensure_ascii=False, separators=(",", ":"))
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def load(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise ValueError("cannot read baseline %s: %s" % (path, e))
    except json.JSONDecodeError as e:
        raise ValueError("baseline %s is not valid JSON: %s" % (path, e))
    if not isinstance(data, dict) or data.get("version") != BASELINE_VERSION:
        raise ValueError("baseline %s has version %r, expected %d" % (path, data.get("version") if isinstance(data, dict) else None, BASELINE_VERSION))
    for key in ("names", "cmts", "rptcmts"):
        if not isinstance(data.get(key), dict):
            raise ValueError("baseline %s has no %s" % (path, key))
    if not isinstance(data.setdefault("types", {}), dict):
        raise ValueError("baseline %s has types that are not a JSON object" % path)
    if not isinstance(data.get("insn", {}), dict):
        raise ValueError("baseline %s has instruction records that are not a JSON object" % path)
    for key, what in (("protos", "function prototypes"), ("data", "data records")):
        if not isinstance(data.get(key, {}), dict):
            raise ValueError("baseline %s has %s that are not a JSON object" % (path, what))
    return data


def owner_name(baseline, ea, current):
    if not current:
        return None
    if baseline is None:
        return current
    return None if baseline["names"].get(str(ea)) == current else current


def owner_cmt(baseline, ea, kind, current):
    if not current:
        return None
    if baseline is None:
        return current
    return None if baseline[KINDS[kind]].get(str(ea)) == current else current


def owner_type(baseline, name, decl):
    if baseline is None:
        return True
    return (baseline.get("types") or {}).get(name) != decl


def has_insn(baseline):
    return baseline is not None and isinstance(baseline.get("insn"), dict)


def insn_record(baseline, ea):
    if baseline is None:
        return None
    return (baseline.get("insn") or {}).get(str(ea))


def has_protos(baseline):
    return baseline is not None and isinstance(baseline.get("protos"), dict)


def proto_record(baseline, ea):
    if baseline is None:
        return None
    return (baseline.get("protos") or {}).get(str(ea))


def has_data(baseline):
    return baseline is not None and isinstance(baseline.get("data"), dict)


def data_record(baseline, ea):
    if baseline is None:
        return None
    return (baseline.get("data") or {}).get(str(ea))
