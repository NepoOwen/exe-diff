NOTE_PREFIX = "exediff: "
LIKELY_NOTE = "exediff: one of several identical functions"


def changed_note(old_exe_name, similarity):
    return "exediff: changed vs %s (%d%% similar)" % (old_exe_name, similarity or 0)


def strip_notes(text):
    if not text:
        return ""
    lines = text.split("\n")
    kept = [line for line in lines if not line.startswith(NOTE_PREFIX)]
    if len(kept) == len(lines):
        return text
    return "\n".join(kept).rstrip("\n")


def with_note(owner_text, note):
    owner = strip_notes(owner_text)
    if not note:
        return owner
    return owner + "\n" + note if owner else note


def decide(existing, want, owner_text):
    existing = existing or ""
    if existing == want:
        return "same"
    have = strip_notes(existing)
    if not have or have == strip_notes(owner_text):
        return "set"
    return "keep"
