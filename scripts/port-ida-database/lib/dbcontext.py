import hashlib
import os
import struct

KEYS = ["tils", "compiler", "abi", "bitness"]


def _tils(old, new):
    only_old = sorted(set(old) - set(new))
    only_new = sorted(set(new) - set(old))
    if not only_old and not only_new:
        return None
    parts = []
    if only_old:
        parts.append("only in the old database: %s" % ", ".join(only_old))
    if only_new:
        parts.append("only in the new database: %s" % ", ".join(only_new))
    return "type libraries differ (%s): types and prototypes may parse differently; load the same type libraries in both" % "; ".join(parts)


def _plain(what, old, new):
    return "%s differs: old %s, new %s" % (what, old or "none", new or "none")


def _bits(n):
    return "%d-bit" % n if n else "unknown"


def differences(old, new):
    out = []
    for key in KEYS:
        if key not in old or key not in new:
            continue
        a, b = old[key], new[key]
        if key == "tils":
            text = _tils(a, b)
        elif a == b:
            text = None
        elif key == "compiler":
            text = _plain("the compiler", a, b)
        elif key == "abi":
            text = _plain("the ABI", a, b)
        else:
            text = "the bitness differs: old %s, new %s" % (_bits(a), _bits(b))
        if text:
            out.append((key, text))
    return out


def information(old, new):
    a, b = old.get("imagebase"), new.get("imagebase")
    if a is None or b is None or a == b:
        return []
    return ["the image base differs: old 0x%X, new 0x%X; the new exe loads at another address and map.csv pairs each exe at its own base, "
            "so this is information only" % (a, b)]


def refusal(diffs):
    return "the databases differ (-Strict): " + "; ".join(text for _key, text in diffs)


def pe_info(data):
    if len(data) < 0x40 or data[:2] != b"MZ":
        return None
    at = struct.unpack_from("<I", data, 0x3C)[0]
    opt = at + 24
    if len(data) < opt + 2 or data[at:at + 4] != b"PE\0\0":
        return None
    machine, chars = struct.unpack_from("<H", data, at + 4)[0], struct.unpack_from("<H", data, at + 22)[0]
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B and len(data) >= opt + 32:
        base = struct.unpack_from("<Q", data, opt + 24)[0]
    elif magic == 0x10B and len(data) >= opt + 32:
        base = struct.unpack_from("<I", data, opt + 28)[0]
    else:
        return None
    return {"base": base, "magic": magic, "machine": machine, "dll": bool(chars & 0x2000)}


def pe_imagebase(data):
    info = pe_info(data)
    return info["base"] if info else None


def exe_info(path):
    if not path:
        return None
    try:
        with open(path, "rb") as f:
            return pe_info(f.read(0x10000))
    except OSError:
        return None


def exe_imagebase(path):
    info = exe_info(path)
    return info["base"] if info else None


def file_md5(path):
    if not path:
        return None
    h = hashlib.md5()
    try:
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1 << 20), b""):
                h.update(block)
    except OSError:
        return None
    return h.hexdigest()


def exe_paths(pair, side):
    work = pair.get(side + "_work")
    return [p for p in (os.path.join(work, "input.exe") if work else None, pair.get(side + "_exe")) if p]


def checked_pe(md5, paths):
    md5 = (md5 or "").lower()
    for path in paths:
        if md5 and file_md5(path) == md5:
            info = exe_info(path)
            if info:
                return path, info
    return None, None


def own_imagebase(baseline, md5, paths):
    if baseline and baseline.get("imagebase") is not None:
        return baseline["imagebase"], "exediff's analysis of it"
    path, info = checked_pe(md5, paths)
    if info:
        return info["base"], "the PE header of %s" % path
    return None, None


def kind_notice(name, info):
    if info is None:
        return None
    what = []
    if info["magic"] != 0x20B:
        what.append("a 32-bit file")
    elif info["machine"] != 0x8664:
        what.append("not an x64 file")
    if info["dll"]:
        what.append("a DLL")
    if not what:
        return None
    return "untested for this kind of file: %s is %s; port-ida-database was only tested on 64-bit x64 exe files, check the result by hand" % (
        name, " and ".join(what))


def rebased(which, have, want, source):
    if have is None or want is None or have == want:
        return None
    return ("the %s database was rebased from 0x%X to 0x%X (its own image base is 0x%X, from %s); map.csv uses the exe's own addresses, "
            "so every pair would point at the wrong place: rebase it back to 0x%X first (Edit > Segments > Rebase program) and run again"
            % (which, want, have, want, source, want))


def unchecked(which, paths):
    return ("the image base of the %s database could not be checked: %s is not a readable PE file with the md5 in pair.txt; "
            "if you rebased the database, rebase it back to the exe's own image base first" % (which, " or ".join(paths) or "no exe"))
