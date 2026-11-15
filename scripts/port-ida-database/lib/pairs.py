from dataclasses import dataclass, field
from typing import Optional

OLD_HEADER_MESSAGE = "map.csv is from an older exediff: it has no method column; run exediff again"
COLUMNS = ["status", "name", "old_va", "new_va", "old_size", "new_size", "method", "similarity"]


@dataclass(frozen=True)
class Row:
    status: str
    name: str
    old_va: Optional[int]
    new_va: Optional[int]
    old_size: Optional[int]
    new_size: Optional[int]
    method: Optional[str]
    similarity: Optional[int]


def _int(text):
    text = text.strip()
    if not text:
        return None
    return int(text, 0)


def _text(text):
    text = text.strip()
    return text or None


def parse_map_csv(text: str) -> list:
    if text.startswith("﻿"):
        text = text[1:]
    lines = text.splitlines()
    if not lines:
        raise ValueError("map.csv is empty")
    header = [c.strip() for c in lines[0].split(",")]
    if "method" not in header:
        raise ValueError(OLD_HEADER_MESSAGE)
    if header != COLUMNS:
        raise ValueError("map.csv has unexpected columns: " + ",".join(header))
    rows = []
    for number, line in enumerate(lines[1:], 2):
        if not line.strip():
            continue
        parts = line.split(",")
        if len(parts) < len(COLUMNS):
            raise ValueError("map.csv line %d has too few columns" % number)
        tail = parts[-6:]
        name = ",".join(parts[1:-6])
        rows.append(Row(parts[0].strip(), name, _int(tail[0]), _int(tail[1]), _int(tail[2]), _int(tail[3]),
                        _text(tail[4]), _int(tail[5])))
    return rows


def parse_pair_txt(text: str) -> dict:
    out = {}
    for line in text.splitlines():
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value
    return out


def classify(row: Row, min_similarity: int = 80) -> str:
    if row.status in ("same", "calls_changed"):
        return "certain" if row.method == "exact-unique" else "likely"
    if row.status == "changed":
        return "changed" if (row.similarity or 0) >= min_similarity else "below"
    return "unpaired"


def is_ported(cls: str, include_likely: bool) -> bool:
    if cls in ("certain", "changed"):
        return True
    return cls == "likely" and include_likely


@dataclass
class Pairing:
    rows: dict = field(default_factory=dict)
    classes: dict = field(default_factory=dict)
    unpaired_old: set = field(default_factory=set)
    unpaired_new: set = field(default_factory=set)

    def new_of(self, old_va: int) -> Optional[int]:
        row = self.rows.get(old_va)
        return row.new_va if row else None


def build_pairing(rows: list, min_similarity: int = 80) -> Pairing:
    p = Pairing()
    for row in rows:
        if row.status == "removed":
            if row.old_va is not None:
                p.unpaired_old.add(row.old_va)
        elif row.status == "added":
            if row.new_va is not None:
                p.unpaired_new.add(row.new_va)
        elif row.old_va is not None and row.new_va is not None:
            p.rows[row.old_va] = row
            p.classes[row.old_va] = classify(row, min_similarity)
    return p
