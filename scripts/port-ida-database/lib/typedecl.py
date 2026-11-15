import re

TOKEN = re.compile(r"[A-Za-z_$][\w$]*(?:::[A-Za-z_$][\w$]*)*|\d\w*|[^\s\w$]")
ORDINAL = re.compile(r"/\* \d+ \*/")
UDT = re.compile(r"(struct|union)\b")
KIND = re.compile(r"(struct|union|enum|typedef)\b")
QUALIFIERS = {"const", "volatile", "__unaligned", "__ptr32", "__ptr64", "__restrict"}


def clean(text):
    lines = [l.rstrip() for l in (text or "").replace("\r\n", "\n").split("\n")]
    lines = [l for l in lines if not ORDINAL.fullmatch(l.strip())]
    return "\n".join(lines).strip("\n")


def anonymous(name):
    return name.rsplit("::", 1)[-1].startswith("$")


def _body(decl):
    return [l.strip() for l in decl.split("\n") if l.strip() and not l.strip().startswith("#")]


def uses(decl, names, own=None):
    tokens = TOKEN.findall(decl)
    out, depth = {}, 0
    for i, tok in enumerate(tokens):
        if tok == "(":
            depth += 1
        elif tok == ")":
            depth = max(depth - 1, 0)
        elif tok in names and tok != own:
            j = i + 1
            while j < len(tokens) and tokens[j] in QUALIFIERS:
                j += 1
            soft = depth > 0 or (j < len(tokens) and tokens[j] in ("*", "&"))
            out[tok] = out.get(tok, False) or not soft
    return out


def refs(decl, names, own=None):
    return set(uses(decl, names, own))


def udt_kind(decl):
    body = _body(decl)
    m = UDT.match(body[0]) if body else None
    return m.group(1) if m else None


def decl_kind(decl):
    body = _body(decl)
    m = KIND.match(body[0]) if body else None
    return m.group(1) if m else None


def is_forward(decl):
    body = _body(decl)
    return len(body) == 1 and udt_kind(decl) is not None and "{" not in body[0] and body[0].endswith(";")


def _graph(types):
    names = {t["name"] for t in types}
    use = {t["name"]: uses(t["decl"], names, t["name"]) for t in types}
    kind = {t["name"]: udt_kind(t["decl"]) for t in types}
    typedef = {t["name"] for t in types if decl_kind(t["decl"]) == "typedef"}

    def closure(name, seen):
        if name in seen:
            return set()
        seen.add(name)
        out = {name}
        if name in typedef:
            for d, hard in use[name].items():
                if hard:
                    out |= closure(d, seen)
        return out

    need = {}
    for t in types:
        n = t["name"]
        need[n] = set()
        if n not in typedef:
            for d, hard in use[n].items():
                if hard:
                    need[n] |= closure(d, set())
        need[n].discard(n)
    return {n: set(u) for n, u in use.items()}, need, kind


def needs_complete(types):
    return _graph(types)[1]


def order(types):
    deps, need, kind = _graph(types)
    rest, done, out = list(types), set(), []
    while rest:
        ready = [t for t in rest if deps[t["name"]] <= done and need[t["name"]] <= done]
        if not ready:
            ready = [next((t for t in rest if need[t["name"]] <= done and all(kind[d] for d in deps[t["name"]] - done)), rest[0])]
        for t in ready:
            out.append(t)
            done.add(t["name"])
        placed = {t["name"] for t in ready}
        rest = [t for t in rest if t["name"] not in placed]
    return out


def forwards(types):
    deps, need, kind = _graph(types)
    return {n: ["%s %s;" % (kind[d], d) for d in sorted(deps[n] - need[n]) if kind[d]] for n in deps}
