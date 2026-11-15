import difflib
from typing import Callable, Optional

Shape = dict


def _target_problem(old_target, new_target, new_start_of, is_paired_new) -> Optional[str]:
    expected = new_start_of(old_target) if old_target is not None else None
    if expected is not None:
        if new_target != expected:
            return "target differs (old 0x%X pairs to 0x%X, new is %s)" % (
                old_target, expected, "none" if new_target is None else "0x%X" % new_target)
        return None
    if new_target is not None and is_paired_new(new_target):
        return "target 0x%X is a paired function but old target is unpaired" % new_target
    return None


def shapes_match(old: Shape, new: Shape, new_start_of: Callable, is_paired_new: Callable) -> tuple:
    if old["frsize"] != new["frsize"] or old["argsize"] != new["argsize"]:
        return False, "frame sizes differ (old %d/%d, new %d/%d)" % (
            old["frsize"], old["argsize"], new["frsize"], new["argsize"])
    a, b = old["insns"], new["insns"]
    if len(a) != len(b):
        return False, "instruction count differs (old %d, new %d)" % (len(a), len(b))
    for x, y in zip(a, b):
        at = "0x%X" % x[0]
        if x[0] != y[0]:
            return False, "offset differs at %s (new 0x%X)" % (at, y[0])
        if x[1] != y[1]:
            return False, "size differs at %s (old %d, new %d)" % (at, x[1], y[1])
        if x[2] != y[2]:
            return False, "mnemonic differs at %s (old %s, new %s)" % (at, x[2], y[2])
        if list(x[3]) != list(y[3]):
            return False, "operand types differ at %s" % at
        problem = _target_problem(x[4], y[4], new_start_of, is_paired_new)
        if problem:
            return False, "%s at %s" % (problem, at)
    return True, ""


def align_runs(old: list, new: list, min_run: int = 3) -> list:
    matcher = difflib.SequenceMatcher(None, old, new, autojunk=False)
    out = []
    for block in matcher.get_matching_blocks():
        if block.size >= min_run:
            out.extend((block.a + i, block.b + i) for i in range(block.size))
    return out
