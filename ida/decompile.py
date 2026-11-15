import os, re, sys, time, traceback
import idc, ida_auto, ida_bytes, ida_funcs, ida_hexrays, ida_nalt, ida_name, ida_pro, ida_segment, ida_ua

# hex-rays stores guessed callee prototypes: never save, so every run starts from the same db
idc.process_config_line("ABANDON_DATABASE=YES")
mode = idc.ARGV[3] if len(idc.ARGV) > 3 else "full"
alias = {}

# signature maker v1.0.10 (A200K) x86 defaults: every operand type but o_reg, see docs/signatures.md
SIG_TYPES = {ida_ua.o_mem, ida_ua.o_phrase, ida_ua.o_displ, ida_ua.o_far, ida_ua.o_near, ida_ua.o_imm} | set(range(ida_ua.o_idpspec0, ida_ua.o_idpspec5 + 4))
SIG_MAX = 1000
UA_MAXOP = 8  # ua.hpp


def layout(start, end, chunks):
    # pdata splits one body into touching chunks: merge those into the main range, the rest are tails
    tails = []
    for b, e in sorted(chunks):
        if start <= b <= end:
            end = max(end, e)
        else:
            tails.append((b, e))
    return end, tails


def analyse(ranges):
    if mode == "fast":
        for b, e in ranges:
            ida_auto.plan_and_wait(b, e)


def define(start, end, tails):
    f = ida_funcs.get_func(start)
    if not f or f.start_ea != start:
        ida_funcs.add_func(start, end)
        f = ida_funcs.get_func(start)
    if f:
        for b, e in tails:
            if not ida_funcs.get_func(b):
                ida_funcs.append_func_tail(f, b, e)
    analyse([(start, end)] + tails)


def redefine(start, end, tails):
    for b, e in [(start, end)] + tails:
        ea = b
        while ea < e:
            f = ida_funcs.get_func(ea)
            if f:
                ida_funcs.del_func(f.start_ea)
            ea += 1 if not f else max(1, min(f.end_ea, e) - ea)
        ida_bytes.del_items(b, ida_bytes.DELIT_SIMPLE, e - b)
        ea = b
        while ea < e:
            n = ida_ua.create_insn(ea)
            ea += n if n > 0 else 1
    ida_funcs.add_func(start, end)
    f = ida_funcs.get_func(start)
    if f:
        for b, e in tails:
            ida_funcs.append_func_tail(f, b, e)
        ida_funcs.reanalyze_function(f)
    for b, e in [(start, end)] + tails:
        ida_auto.plan_and_wait(b, e)


def decompile(start):
    hf = ida_hexrays.hexrays_failure_t()
    cf = ida_hexrays.decompile(start, hf)
    return cf, hf


def attempt(start, end, chunks):
    end, tails = layout(start, end, chunks)
    define(start, end, tails)
    cf, hf = decompile(start)
    if cf:
        return cf, hf, False
    redefine(start, end, tails)
    return decompile(start) + (True,)


def unalias(text):
    return re.sub(r"\bexediff_\w+", lambda m: alias.get(m.group(0), m.group(0)), text)


def write(path, text):
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


class Progress:
    # progress.txt: "<pass> <done> <total>", read by exediff.exe while idat runs
    def __init__(self, out, total):
        self.path, self.total, self.last = os.path.join(out, "progress.txt"), total, 0.0

    def __call__(self, step, done, force=False):
        if force or time.time() - self.last >= 0.5:
            self.last = time.time()
            write(self.path, "%d %d %d\n" % (step, done, self.total))


def wildcards(insn):
    bits = set()
    ops = insn.ops
    for i in range(UA_MAXOP):
        op = ops[i]
        if op.type == ida_ua.o_void:
            break
        if op.type not in SIG_TYPES or (op.type == ida_ua.o_imm and op.value == 0):
            continue
        n = insn.size - op.offb
        if i < UA_MAXOP - 1 and ops[i + 1].type != ida_ua.o_void and ops[i + 1].offb > 0:
            n = ops[i + 1].offb - op.offb
        bits.update(range(op.offb, op.offb + n))
    return bits


class Haystack:
    def __init__(self):
        self.bufs = []
        for n in range(ida_segment.get_segm_qty()):
            s = ida_segment.getnseg(n)
            b = ida_bytes.get_bytes(s.start_ea, s.end_ea - s.start_ea)
            if b:
                self.bufs.append(b)

    @staticmethod
    def regex(pat):
        return re.compile(b"".join(b"." if wild else re.escape(bytes([b])) for b, wild in pat), re.S)

    def narrow(self, pat, lo, found):
        # every occurrence of pat, kept as (buffer, offset); None while pat has no literal byte and matches anywhere
        if found is not None:
            rx = self.regex(pat[lo:])
            return [(k, at) for k, at in found if rx.match(self.bufs[k], at + lo)]
        best, run = (0, 0), 0
        for i, (_, wild) in enumerate(pat):
            run = 0 if wild else run + 1
            if run > best[1]:
                best = (i + 1 - run, run)
        if not best[1]:
            return None
        off = best[0]
        anchor = bytes(b for b, _ in pat[off:off + best[1]])
        rx = self.regex(pat)
        found = []
        for k, buf in enumerate(self.bufs):
            at = buf.find(anchor)
            while at >= 0:
                if at >= off and rx.match(buf, at - off):
                    found.append((k, at - off))
                at = buf.find(anchor, at + 1)
        return found


def signature(hay, start):
    # signature maker "create unique signature" with wildcards for operands, continue when leaving function scope,
    # wildcard optimized instructions and do not wildcard 0-operands all on
    if not ida_bytes.is_code(ida_bytes.get_flags(start)):
        return None, "Can not create code signature for data"
    # matches only drop as the pattern grows, so a batch of instructions is checked at once and
    # walked one instruction at a time only once it is unique
    pat, found, ea, batch = [], None, start, 1
    while True:
        lo, ends, stop = len(pat), [], None
        for _ in range(batch if found is not None else 1):
            insn = ida_ua.insn_t()
            n = ida_ua.decode_insn(insn, ea)
            if n <= 0:
                stop = "Signature not unique, reached end of executable code at %X" % ea if pat else "Failed to decode first instruction"
                break
            if len(pat) > SIG_MAX:
                stop = "Signature not unique after %d bytes" % SIG_MAX
                break
            wild = wildcards(insn)
            pat += [(b, i in wild) for i, b in enumerate(ida_bytes.get_bytes(ea, n))]
            ends.append(len(pat))
            ea += n
        if ends:
            narrowed = hay.narrow(pat, lo, found)
            if narrowed is not None and len(narrowed) == 1:
                for end in ends:
                    if end == len(pat) or len(hay.narrow(pat[:end], lo, found)) == 1:
                        pat = pat[:end]
                        while pat[-1][1]:
                            pat.pop()
                        return " ".join("?" if wild else "%02X" % b for b, wild in pat), None
            found = narrowed
            if found is not None:
                batch = min(batch * 2, 64)
        if stop:
            return None, stop + (", %d places match" % len(found) if found else "")


def run(req, out, log):
    base = ida_nalt.get_imagebase()
    t0 = time.time()
    if mode == "full":
        ida_auto.auto_wait()
    log.write("analysis %.2f s\n" % (time.time() - t0))
    if not ida_hexrays.init_hexrays_plugin():
        log.write("hex-rays not available\n")

    names, funcs = [], []
    for line in open(req):
        p = line.split()
        if not p:
            continue
        if p[0] == "N":
            names.append((base + int(p[1], 16), p[2]))
        elif p[0] == "F":
            funcs.append([base + int(p[1], 16), base + int(p[2], 16), []])
        elif p[0] == "C" and funcs:
            funcs[-1][2].append((base + int(p[1], 16), base + int(p[2], 16)))

    for ea, name in names:
        if mode == "fast" and not ida_funcs.get_func(ea):
            ida_funcs.add_func(ea)
        ida_name.set_name(ea, name, ida_name.SN_FORCE | ida_name.SN_NOWARN)
        if ida_name.get_name(ea) != name:
            # ida keeps its own dummy name when given one of its prefixes (sub_), even when set_name says yes
            if ida_name.set_name(ea, "exediff_" + name, ida_name.SN_FORCE | ida_name.SN_NOWARN):
                alias["exediff_" + name] = name

    # the first pass gives every requested callee its prototype before the pass that is written out
    progress = Progress(out, len(funcs))
    retried = set()
    for done, (start, end, chunks) in enumerate(funcs):
        progress(1, done)
        try:
            if attempt(start, end, chunks)[2]:
                retried.add(start)
        except Exception:
            pass
    log.write("first pass %.2f s\n" % (time.time() - t0))

    failed, unsigned, hay = 0, 0, None
    for done, (start, end, chunks) in enumerate(funcs):
        progress(2, done)
        rva = start - base
        t = time.time()
        try:
            cf, hf, again = attempt(start, end, chunks)
            if again:
                retried.add(start)
            note = " retried" if start in retried else ""
            if cf:
                write(os.path.join(out, "%08X.c" % rva), unalias(str(cf)))
            else:
                failed += 1
                note += " failed"
                write(os.path.join(out, "%08X.err" % rva), "%s at %X" % (hf.str or hf.desc(), hf.errea))
        except Exception:
            failed += 1
            note = " exception"
            write(os.path.join(out, "%08X.err" % rva), traceback.format_exc())
        ts = time.time()
        try:
            if hay is None:
                hay = Haystack()
            sig, error = signature(hay, start)
        except Exception:
            sig, error = None, traceback.format_exc()
        if not sig:
            unsigned += 1
            note += " no signature"
        write(os.path.join(out, "%08X.sig" % rva), sig if sig else "error: " + error)
        log.write("%08X %.2f s, signature %.2f s%s\n" % (rva, ts - t, time.time() - ts, note))
    progress(2, len(funcs), True)
    log.write("%d functions, %d retried, %d failed, %d without signature, %.2f s\n" % (len(funcs), len(retried), failed, unsigned, time.time() - t0))


code = 1
try:
    req, out = idc.ARGV[1], idc.ARGV[2]
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "decompile.log"), "w") as log:
        try:
            run(req, out, log)
            code = 0
        except Exception:
            log.write(traceback.format_exc())
except Exception:
    traceback.print_exc(file=sys.stderr)
finally:
    ida_pro.qexit(code)
