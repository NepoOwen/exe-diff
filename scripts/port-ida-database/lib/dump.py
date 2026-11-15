import json
import os

DUMP_VERSION = 1
LAYOUT = {"separators": (",", ":")}


def save(path: str, dump: dict) -> None:
    tmp = path + ".tmp"
    data = dict(dump)
    data.setdefault("version", DUMP_VERSION)
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, ensure_ascii=False, **LAYOUT)
        os.replace(tmp, path)
    except BaseException:
        try:
            os.remove(tmp)
        except OSError:
            pass
        raise


def load(path: str) -> dict:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except OSError as e:
        raise ValueError("cannot read dump %s: %s" % (path, e))
    except json.JSONDecodeError as e:
        raise ValueError("dump %s is not valid JSON: %s" % (path, e))
    if not isinstance(data, dict) or data.get("version") != DUMP_VERSION:
        raise ValueError("dump %s has version %r, expected %d" % (path, data.get("version") if isinstance(data, dict) else None, DUMP_VERSION))
    return data
