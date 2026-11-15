import re
from typing import Optional

_BLOCK_COMMENT = re.compile(r"/\*.*?\*/", re.S)
_LINE_COMMENT = re.compile(r"//[^\n]*")
_NAMES = re.compile(
    r"\b(?:sub|loc|off|qword|dword|word|byte|unk|asc|stru|flt|dbl|xmmword|ymmword|nullsub|j_sub|LABEL)_[0-9A-Fa-f]{6,}\b")
_HEX = re.compile(r"\b0x[0-9A-Fa-f]{9,}\b")
_SPACE = re.compile(r"[ \t\r\f\v]+")


def _lines(text):
    text = _BLOCK_COMMENT.sub(" ", text)
    text = _LINE_COMMENT.sub("", text)
    text = _NAMES.sub("ADDR", text)
    text = _HEX.sub("ADDR", text)
    out = []
    for line in text.split("\n"):
        line = _SPACE.sub(" ", line).strip()
        if line:
            out.append(line)
    return out


def normalise(text: str) -> str:
    return "\n".join(_lines(text))


def first_difference(a: str, b: str) -> Optional[str]:
    x, y = _lines(a), _lines(b)
    for i in range(max(len(x), len(y))):
        p = x[i] if i < len(x) else ""
        q = y[i] if i < len(y) else ""
        if p != q:
            return "line %d: %r != %r" % (i + 1, p, q)
    return None
