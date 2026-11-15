import json
import sys

SEAM_TYPE = {"name": "ExedFixSeam", "decl": "struct  ExedFixSeam { int a; };"}
ODD_TYPES = {"ExedFix<Odd>": None}


def main(src, dst):
    with open(src, "r", encoding="utf-8") as f:
        dump = json.load(f)
    dump["types"] = [SEAM_TYPE] + dump["types"]
    plain = next(d for d in dump["data"] if d.get("name") == "ExedFix_Data_Plain")
    plain["types"] = dict(ODD_TYPES)
    with open(dst, "w", encoding="utf-8") as f:
        json.dump(dump, f, ensure_ascii=False, separators=(",", ":"))


main(sys.argv[1], sys.argv[2])
